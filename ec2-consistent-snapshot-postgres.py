#!/usr/bin/python
#
# ec2-consistent-snapshot-postgres - An script to do consistent snapshots.
#
# It's based on the methodology used by
# https://github.com/alestic/ec2-consistent-snapshot
#
# Copyright (c) 2013 Carlos Perello Marin <carlos@pemas.net>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

import boto
import boto.ec2
import logging
import os
import os.path
import sys

from boto.sdb.db.model import Model
from boto.sdb.db.property import *
from boto.sdb.db.query import Query
from datetime import datetime, timedelta
from optparse import OptionParser
from subprocess import Popen, PIPE
from urllib2 import urlopen, HTTPError
from urlparse import urljoin
from glock import GlobalLock, GlobalLockError, LockAlreadyAcquired
from time import sleep


class FsFreezeError(Exception):
    """Raised when there is a problem freezing or unfreezing the filesystem."""
    pass


class VolumeNotWriteable(Exception):
    """Raised when the filesystem is not writeable."""
    pass


class Backup(Model):
    """SDB backed object that represents a volume backup."""

    snapshotid = StringProperty()
    volumeid = StringProperty()
    expires = DateTimeProperty()


def parse_arguments():
    """Parse command line arguments."""
    parser = OptionParser()
    parser.add_option(
        "-l", "--lock", dest="lockFile",
        default="/var/lock/ec2-consistent-snapshot-postgres.lock",
        help="The lock file to use to prevent multiple executions.")
    parser.add_option(
        "-s", "--status-file", dest="statusFile",
        default="/var/tmp/ec2-consistent-snapshot-postgres.status",
        help="The status file to write for nagios monitorization.")
    parser.add_option(
        "", "--disable-backup-file", dest="disableBackupFile",
        default="/var/tmp/ec2-consistent-snapshot-postgres.disabled",
        help="If this file exists the backups will be disabled.")
    parser.add_option(
        "-e", "--expire", dest="expire", default=0, type=int,
        help="The number of hours this snapshot will be valid.")
    parser.add_option("-d", "--ebs-devices", dest="devices",
        help="The device names to take a snapshot for.")
    parser.add_option(
        "-r", "--region", dest="region", default='eu-west-1',
        help="The AWS region to work.")
    parser.add_option("", "--description", dest="description",
        default="ec2-consistent-snapshot-postgres",
        help="Specify a description string for the EBS snapshot.")
    parser.add_option("-f", "--freeze-filesystem", dest="freezeFS",
        help="Freeze the given filesystem mount point so it's consistent.")
    parser.add_option("", "--snapshot-timeout", dest="snapshotTimeout",
        default="10.0", type=float,
        help="How many seconds to wait for the snapshot-create to return.")
    parser.add_option("", "--lock-timeout", dest="lockTimeout",
        default="0.5", type=float,
        help="How many seconds to wait for a database lock.")
    parser.add_option("", "--lock-tries", dest="lockTries",
        default="60", type=int,
        help="How many times to try to get a database lock before failing.")
    parser.add_option("", "--lock-sleep", dest="lockSleep",
        default="5.0", type=float,
        help="How many seconds to sleep between database lock tries.")
    parser.add_option("", "--max-load", dest="maxLoad",
        default="2.0", type=float,
        help="The maximum load the system should have to start the backup.")
    parser.add_option("", "--max-load-tries", dest="maxLoadTries",
        default="6", type=int,
        help="Times to try to start a backup when the load is high.")
    parser.add_option(
        "-v", "--verbose", action="store_true", dest="verbose", default=False,
        help="Increase log output verbosity.")
    parser.add_option(
        "", "--log-file", dest="logfilename",
        default="/var/log/ec2-consistent-snapshot-postgres.log",
        help="The log file.")
    parser.add_option(
        "", "--snapshot-domain", dest="domain",
        default="ec2-consistent-snapshot-postgres",
        help="The domain where all snapshots will be grouped in SDB.")
    parser.add_option(
        "-p", "--purge", action="store_true", dest="purge", default=False,
        help="Whether all available snapshots must be purged.")
    return parser.parse_args()


def check_load_ok():
    """Return whether the load is ok to start a snapshot."""

    load = os.getloadavg()

    return load[0] < options.maxLoad


def create_logger(logfilename, domain, verbose=False):
    """Return a logger object that writes to the given filename."""

    if not logfilename:
        print >> sys.stderr, 'You should specify a valid log file name!'
        sys.exit(1)

    # Set up a specific logger with our desired output level
    logger = logging.getLogger(domain)
    if verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.WARNING)

    # Add the log message handler to the logger
    handler = logging.handlers.RotatingFileHandler(
        logfilename, maxBytes=10000000, backupCount=5)
    # create formatter
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    # add formatter to ch
    handler.setFormatter(formatter)

    logger.addHandler(handler)

    return logger


def get_instance_id():
    """Return the instance ID for this machine from the metadata url."""

    instance_file = urlopen(
        'http://169.254.169.254/latest/meta-data/instance-id')

    instance_id = instance_file.read()
    instance_file.close()

    return instance_id


def get_all_volumes(instance_id, region, devices):
    """Return a list of all volumes attached to the given instance id."""

    ec2 = boto.ec2.connect_to_region(region)
    volumes = ec2.get_all_volumes()
    instance_volumes = []
    for vol in volumes:
        if (vol.attach_data is None or
            vol.attach_data.instance_id != instance_id or
            vol.attach_data.device not in devices):
            continue

        instance_volumes.append(vol)

    return instance_volumes


def create_snapshots(volume_list):
    """Create snapshots backup of the given volumes."""

    comm_args = [
        "/usr/bin/ec2-consistent-snapshot", "--mysql",
        "--region", options.region, "--freeze-filesystem", options.freezeFS
        ]
    comm_args.extend(volume_list)

    p1 = Popen(comm_args, stdout=PIPE, stderr=PIPE)
    stdout, stderr = p1.communicate()

    snapshots = []
    if len(stderr.strip()) > 0:
        logger.error(stderr)

    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith('snap-'):
            snapshots.append(line)
        else:
            logger.error(
                'Found an unexpected output from ec2-consistent-snapshot\'s'
                ' stdout: "%s"' % line)

    return snapshots


def purge_all_snapshots(instance_volumes):
    """Remove all EBS snapshots and SDB metadata."""

    for vol in instance_volumes:
        logger.info("Querying for all snapshots for volume: %s" % vol.id)
        # only delete snapshots for the volumes that we were working on
        query = Query(Backup)
        query.filter("volumeid =", vol.id)
        for backup in query:
            logger.info("Removing EBS snapshot %s" % backup.snapshotid)
            try:
                vol.connection.delete_snapshot(backup.snapshotid)
                backup.delete()
            except:
                logger.error(
                    "Unable to delete snapshot %s, please delete manually." % (
                        backup.snapshotid))


def purge_expired_snapshots(instance_volumes):
    """Remove EBS snapshots and SDB metadata."""

    for vol in instance_volumes:
        logger.info("Querying for old snapshots for volume: %s" % vol.id)
        # only delete snapshots for the volumes that we were working on
        query = Query(Backup)
        query.filter("volumeid =", vol.id)
        query.filter("expires <=", datetime.now())
        for backup in query:
            logger.info(
                "Removing expired EBS snapshot %s" % backup.snapshotid)
            try:
                vol.connection.delete_snapshot(backup.snapshotid)
                backup.delete()
            except:
                logger.error(
                    "Unable to delete snapshot %s, please delete manually." % (
                        backup.snapshotid))


def check_volume_writeable(fs_path):
    """Check whether the filesystem is frozen or not."""

    touch_file = os.path.join(fs_path, ".snapshot-backup.touch")
    comm_args = ["/usr/bin/touch", touch_file]
    timeout = 10

    p1 = Popen(comm_args)
    sleep(timeout)
    if p1.poll() is None:
        # The touch didn't finish in 10 seconds, we assume the fs is frozen.
        raise VolumeNotWriteable(
            "We didn't complete a touch in %d seconds", timeout)
    else:
        if os.path.exists(touch_file):
            comm_args = ["/bin/rm", touch_file]

            p1 = Popen(comm_args)
            sleep(timeout)
            if p1.poll() is None:
                raise VolumeNotWriteable(
                    "We didn't complete an rm in %d seconds", timeout)


def set_fs_status(fs_path, unfreeze):
    """Freezes or unfreezes a filesystem."""

    if unfreeze:
        freeze_arg = "-u"
    else:
        freeze_arg = "-f"

    comm_args = ["/sbin/fsfreeze", freeze_arg, fs_path]

    p1 = Popen(comm_args, stdout=PIPE, stderr=PIPE)
    stdout, stderr = p1.communicate()

    if len(stderr.strip()) > 0:
        logger.error(stderr.strip())
        raise FsFreezeError(stderr.strip())
    elif p1.returncode != 0:
        if unfreeze:
            error_message = (
                "While unfreeze filesystem, fsfreeze returned code '%d'" % (
                    p1.returncode))
        else:
            error_message = (
                "While freeze filesystem, fsfreeze returned code '%d'" % (
                    p1.returncode))

        logger.error(error_message)
        raise FsFreezeError(error_message)
    else:
        pass


def cleanup_system_with_errors(fs_path):
    """Remove all locks that may be left behind with an error."""
    try:
        set_fs_status(fs_path, unfreeze=True)
    except FsFreezeError:
        # We were unable to unfreeze the filesystem. Try with a new freeze and
        # a new unfreeze.
        set_fs_status(fs_path, unfreeze=False)
        set_fs_status(fs_path, unfreeze=True)


def notify_success():
    """Notifies the system that the snapshot succeed."""
    # Update the status file, so nagios is able to know that it worked.
    status = open(options.statusFile, 'w')
    status.write("OK")
    status.close()


def notify_error():
    """Notifies the system that the snapshot failed."""

    logger.error("Cleaning up system with errors")
    try:
        cleanup_system_with_errors(options.freezeFS)
    except FsFreezeError:
        msg = "Unable to recover from a filesystem freeze!"
        print >> sys.stderr, msg
        logger.error(msg)

    # Update the status file, so nagios is able to notify this error.
    status = open(options.statusFile, 'w')
    status.write("ERROR")
    status.close()


def main():

    # First, we check the server load.
    load_tries = 0
    while load_tries < options.maxLoadTries:
        if check_load_ok():
            logger.info("The load is good enough to do the snapshot.")
            break
        else:
            # Sleep for a while waiting for a lower load
            sleep(load_tries*5*60)
        load_tries += 1

    if load_tries == options.maxLoadTries:
        # Notify the error due to a high load and exit.
        logger.error("Unable to do the snapshot due to a high load.")
        return 5

    try:
        check_volume_writeable(options.freezeFS)
    except VolumeNotWriteable:
        error_message = (
            "The volume at '%s' is not writeable!" % options.freezeFS)
        logger.error(error_message)
        print >> sys.stderr, error_message
        notify_error(options)
        return 1

    # Parse the devices we got from the command line as a list.
    if options.devices is None or len(options.devices) == 0:
        error_message = "You didn't provide any device to backup."
        logger.error(error_message)
        print >> sys.stderr, error_message
        return 2
    devices = options.devices.strip().split(',')

    instance_id = get_instance_id()
    instance_volumes = get_all_volumes(instance_id, options.region, devices)

    if options.purge:
        # Explore the available snapshots for this instance and purge it.
        answer = raw_input(
            'You are going to remove all snapshots from this instance on %s\n'
            'Do you want to continue? (y/N)' % options.domain)
        if answer is not None and answer.lower() in ('y', 'yes'):
            purge_all_snapshots(instance_volumes)
            return 0
        else:
            return 1

    if len(instance_volumes) == 0:
        logger.error(
            'Unable to find (%s) device(s) attached to this instance %s' % (
                options.devices, instance_id))
        return 1

    volume_list = []
    for vol in instance_volumes:
        logger.info('Volume %s attached as %s at %s' % (
            vol.id, vol.attach_data.device, options.freezeFS))
        volume_list.append(vol.id)

    logger.info("Creating the snapshot...")
    snapshots = create_snapshots(volume_list, options)

    if len(snapshots) != len(instance_volumes):
        volume_ids = [volume.id for volume in instance_volumes]
        logger.error(
            'We got less snapshots than volumes! %s vs. %s' % (
                ','.join(snapshots), ','.join(volume_ids)))
        return 1

    # Sanity check to be sure the filesystem is left in a correct state.
    try:
        check_volume_writeable(options.freezeFS)
    except VolumeNotWriteable:
        error_message = (
            "The volume at '%s' is not writeable!" % options.freezeFS)
        logger.error(error_message)
        print >> sys.stderr, error_message
        notify_error(options)
        return 1

    notify_success(options)

    # Connect to simple DB
    sdb = boto.connect_sdb()
    if not sdb.lookup(options.domain):
        sdb.create_domain(options.domain)

    # Add the metadata for the snapshots we just created.
    if options.expire > 0:
        expires = datetime.now() + timedelta(hours=int(options.expire))
        for i in range(len(snapshots)):
            backup = Backup()
            backup.snapshotid = snapshots[i]
            backup.volumeid = instance_volumes[i].id
            backup.expires = expires
            backup.save()
            logger.info("Created snapshot %s for %s expires %s" % (
                backup.snapshotid, backup.volumeid, backup.expires))
    else:
        logger.info("Created snapshot %s for %s (no expiration)" % (
            snapshots[i], instance_volumes[i].id))

    # Explore the available snapshots for this instance and purge the ones
    # expired.
    purge_expired_snapshots(instance_volumes)
    return 0


if __name__ == '__main__':

    (options, args) = parse_arguments()
    logger = create_logger(options.logfilename, options.domain, options.verbose)

    if os.path.exists(options.disableBackupFile):
        logger.error("The backups are disabled")
        return_value = 0
    else:
        # Lock other backups run.
        lock = GlobalLock(options.lockFile)
        try:
            lock.acquire()
        except LockAlreadyAcquired:
            logger.error("There is already a backup running!")
            return_value = 3
        except GlobalLockError:
            logger.error(
                "We couldn't create the lock: '%s'" % options.lockFile)
            return_value = 4
        else:
            return_value = main()
            lock.release()
    if return_value not in (0, 2, 3, 4, 5):
        # return value of 2 and 5 is an error, but unrelated with file system
        # errors.
        notify_error(options)
    sys.exit(return_value)
