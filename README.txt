NAME
    ec2-consistent-snapshot-postgres - Create EBS snapshots on EC2 w/consistent
    filesystem/db

SYNOPSIS
     ec2-consistent-snapshot-postgres [opts]...

OPTIONS
    -h, --help
        Print help and exit.

    -l, --lock=LOCKFILE
        The lock file to use to prevent multiple executions.
        Default: "/var/lock/ec2-consistent-snapshot-postgres.lock"

    --disable-backup-file=DISABLEBACKUPFILE
        If this file exists the backups will be disabled. It's useful while
        doing migrations or maintainment tasks so you don't need to disable
        cron jobs, just touch that file and backups will be disabled.
        Default: "/var/tmp/ec2-consistent-snapshot-postgres.disabled"

    -e, --expire=HOURS
        The number of hours this snapshot will be valid. After the given
        number of hours, the snapshot will be purged.
        Default: 0

    -d, --ebs-devices=DEVICESLIST
        A list of device names to take a snapshot for.

    -r, --region=REGION
        The AWS region to work.
        Default: "es-west-1".

    --description=DESCRIPTION
        Specify a description string for the EBS snapshot.
        Default: ec2-consistent-snapshot-postgres

    --freeze-filesystem=MOUNTPOINT
        Indicates that the filesystem at the specified mount point should be
        flushed and frozen during the snapshot. Requires the fsfreeze program.
        fsfreeze comes with newer versions of util-linux.

    --snapshot-timeout=SECONDS
        How many seconds to wait for the snapshot-create to return.
        Default: 10.0

    --lock-timeout=SECONDS
        How many seconds to wait for a database lock.
        Making this too large can force other processes to wait while this
        process waits for a lock. Better to make it small and try lots of
        times.
        Default: 0.5.

    --lock-tries=COUNT
        How many times to try to get a database lock before failing.
        Default: 60.

    --lock-sleep=SECONDS
        How many seconds to sleep between database lock tries.
        Default: 5.0.

    --max-load=LOAD
        The maximum load the system should have to start the backup.
        Default: 2.0.

    --max-load-tries=COUNT
        How many times to try to start a backup when the load is higher than
        the given limit. Each try increases 5 minutes of delay. For instance,
        first retry will wait 5 minutes, second retry will wait for 10 minutes,
        third retry will wait for 15 minutes and so on.
        Default: 6.

    -v, --verbose
        Increase log output verbosity.

    --log-file=LOGFILE
        The log file.

    --snapshot-domain=NAME
        The domain where all snapshots will be grouped in SDB.
        Default: ec2-consistent-snapshot-postgres

    -p --purge
        Whether all available snapshots must be purged.
        WARNING: This is a destructive option only useful to clean all
        snapshots not valid anymore.
        Default: False


DESCRIPTION
    This program creates an EBS snapshot for an Amazon EC2 EBS volume. To
    help ensure consistent data in the snapshot, it tries to flush and
    freeze the filesystem(s) first as well as flushing and locking the
    database.

    Filesystems can be frozen during the snapshot. While frozen, a
    filesystem will be consistent on disk and all writes will block.

    There are a number of timeouts to reduce the risk of interfering with
    the normal database operation while improving the chances of getting a
    consistent snapshot.

    If you have multiple EBS volumes in a RAID configuration, you can
    specify all of the devices on the command line and it will create
    snapshots for each while the filesystem and database are locked. Note
    that it is your responsibility to keep track of the resulting snapshot
    ids and to figure out how to put these back together when you need to
    restore the RAID setup.

    If you have multiple EBS volumes which are hosting different file
    systems, it might be better to simply run the command once for each
    device.


INSTALLATION
    To install this program you need to configure the boto library with your
    AWS credentials at /etc/boto.cfg as described at
    http://code.google.com/p/boto/wiki/BotoConfig

CREDITS
    Eric Hammond <ehammond@thinksome.com> for the original perl implementation
    for MySQL.

AUTHOR
    Carlos Perello Marin <carlos@pemas.net>

LICENSE
    Copyright (c) 2013 Carlos Perello Marin <carlos@pemas.net>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>

