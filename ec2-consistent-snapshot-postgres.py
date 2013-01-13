#!/usr/bin/python
#
# ec2-consistent-snapshot-postgres - An script to do consistent snapshots.
#
# It's based on the methodology used by
# https://github.com/alestic/ec2-consistent-snapshot
#
# Copyright (c) 2013 Carlos Perello Marin
#
# Author: Carlos Perello Marin <carlos@pemas.net>
#
# This program is free software; you can redistribute it and/or 
# modify it under the terms of the GNU General Public License as 
# published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
# USA

import logging
import sys

from optparse import OptionParser
from glock import GlobalLock, GlobalLockError, LockAlreadyAcquired


lock_file = '/var/lock/ec2-consistent-snapshot-postgres.lock'
_logger = None


def parse_arguments():
    """Parse command line arguments."""
    parser = OptionParser()
    parser.add_option(
        "", "--disable-backup-file", dest="disableBackupFile",
        default="/var/tmp/ec2-consistent-snapshot-postgres.disabled",
        help="If this file exists the backups will be disabled.")
    parser.add_option(
        "-e", "--expire", dest="expire", default="0",
        help="The number of hours this snapshot will be valid.")
    parser.add_option("-d", "--ebs-devices", dest="devices")
    parser.add_option("-m", "--mount-point", dest="mountpoint")
    parser.add_option(
        "-r", "--region", dest="region", default='eu-west-1')
    parser.add_option(
        "-v", "--verbose", action="store_true", dest="verbose", default=False)
    parser.add_option(
        "", "--log-file", dest="logfilename",
        default="/var/log/snapshot-backup.log")
    parser.add_option(
        "-b", "--backup-domain", dest="domain", default="snapshot-backup")
    parser.add_option(
        "-p", "--purge", action="store_true", dest="purge", default=False)
    return parser.parse_args()


def get_logger():
    return _logger


def create_logger(logfilename, domain, verbose=False):
    """Return a logger object that writes to the given filename."""
    if not logfilename:
        print >> sys.stderr, 'You should specify a valid log file name!'
        sys.exit(1)

    global _logger

    # Set up a specific logger with our desired output level
    _logger = logging.getLogger(domain)
    if verbose:
        _logger.setLevel(logging.DEBUG)
    else:
        _logger.setLevel(logging.WARNING)

    # Add the log message handler to the logger
    handler = logging.handlers.RotatingFileHandler(
        logfilename, maxBytes=10000000, backupCount=5)
    # create formatter
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    # add formatter to ch
    handler.setFormatter(formatter)

    _logger.addHandler(handler)


def main(options):



if __name__ == '__main__':

    (options, args) = parse_arguments()
    create_logger(options.logfilename, options.domain, options.verbose)

    # Lock other backups run.
    lock = GlobalLock(lock_file)
    try:
        lock.acquire()
    except LockAlreadyAcquired:
        get_logger().error("There is already a backup running!")
    except GlobalLockError:
        get_logger().error("We couldn't create the lock: '%s'" % lock_file)
    else:
         main(options)
        lock.release()
