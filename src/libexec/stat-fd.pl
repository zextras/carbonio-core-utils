#!/usr/bin/perl -w

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

# Periodically print FD open stats obtained from /proc/sys/fs/file-nr
# The first column of /proc/sys/fs/file-nr gives an instantaneous reading
# of all file descriptors open throughout all processes.  The third column
# gives a maximum file descriptor count for the entire system.

use strict;
use Getopt::Long;
use Cwd qw/realpath/;
use lib "/opt/zextras/common/lib/perl5";
use Zextras::Mon::Stat;
use Zextras::Mon::Logger;
use vars qw($LOGFH $CONSOLE $LOGFILE $ROTATE_NOW $ROTATE_DEFER);

Zextras::Mon::Stat::getLocalConfig('zimbra_user', 'zimbra_server_hostname',
               'zmstat_interval', 'zmstat_disk_interval');
my $zuser = $Zextras::Mon::Stat::LC{zimbra_user};
my ($zuid,$zgid) = (getpwnam($zuser))[2,3];

if (@ARGV > 0 && $ARGV[0] eq 'stop') {
	my $dir = getPidFileDir();
	my $pidFile = "$dir/fd-real.pid";
	my $pid = readPidFile($pidFile);
    if (!kill(0, $pid)) {
        unlink($pidFile);
    } elsif (kill(15, $pid) == 1) {  # SIGTERM
        unlink($pidFile);
    } elsif (kill(9, $pid) == 1) {
    	unlink($pidFile);
    }
	exit;
}
if (@ARGV > 0 && $ARGV[0] eq 'rotate') {
	my $dir = getPidFileDir();
	my $pidFile = "$dir/fd-real.pid";
	my $pid = readPidFile($pidFile);
	kill(1, $pid);
}

if ($< != 0) {
    Zextras::Mon::Stat::userCheck();
    createPidFile('fd.pid');
    $SIG{TERM} = sub {
    	system("sudo /opt/zextras/libexec/zmstat-fd stop");
    };
    $SIG{INT} = sub {
    	system("sudo /opt/zextras/libexec/zmstat-fd stop");
    };
    $SIG{HUP} = sub {
    	system("sudo /opt/zextras/libexec/zmstat-fd rotate");
    };
    my $args = "";
    if (@ARGV > 0) {
    	$args = " " . join(' ', @ARGV);
    }
    system("sudo /opt/zextras/libexec/zmstat-fd$args");
    exit;
}

my $STAT = '/proc/sys/fs/file-nr';
my $HEADING = 'timestamp, fd_count, mailboxd_fd_count';

sub get_fd_stat() {
    open(STAT, "<$STAT") || die "Can't open $STAT: $!";
    my $line = <STAT>;
    $line =~ /^(\d+)\s+/;
    my $stat = $1;
    close(STAT);
    $stat;
}
sub get_mbox_stat() {
    my $mbox_pid = get_mboxd_pid();
    return 0 if ($mbox_pid == 0);
    
    opendir(PROC, "/proc/$mbox_pid/fd") || warn $!;
    my @ents = grep { /^[0-9]+/ } readdir(PROC);
    closedir(PROC);
    return scalar @ents;
}

sub get_mboxd_pid() {
    my $pid = 0;
    if ( !$pid ) {
        eval {
            $pid = qx(pgrep -f '/opt/zextras/.*/java.*mailboxd');
            chomp($pid);
        };
        if ( !$pid ) {
            print STDERR "Unable to determine mailboxd pid\n";
        }
    }
    return $pid;
}

sub sighup {
    if (!$CONSOLE) {
        $LOGFH = rotateLogFile($LOGFH, $LOGFILE, $HEADING);
        my ($name, $path) = File::Basename::fileparse($LOGFILE);
        my $date = getDate();
        my $rotatefile = "$path/$date/$name.gz";
        chown $zuid, $zgid, $rotatefile;
        chown $zuid, $zgid, $LOGFILE;
        my $fmode = 0640; chmod $fmode, $LOGFILE;
    } else {
        $ROTATE_NOW = 1;
    }
}
$SIG{HUP} = \&sighup;

sub usage {
    print STDERR << '_USAGE_';
Usage: zmstat-fd [options]
Monitor system filedescriptor usage
-i, --interval: output a line every N seconds
-l, --log:      log file (default is /opt/zextras/zmstat/fd.csv)
-c, --console:  output to stdout

If logging to a file, rotation occurs when a HUP signal is sent or when
the date changes.  The current log is renamed to <dir>/YYY-MM-DD/fd.csv
and a new file is created.
_USAGE_
    exit(1);
}

$| = 1;

$LOGFILE = getLogFilePath('fd.csv');
my $interval = getZmstatInterval();
my $opts_good = GetOptions(
    'interval=i' => \$interval,
    'log=s' => \$LOGFILE,
    'console' => \$CONSOLE,
);
if (!$opts_good) {
    print STDERR "\n";
    usage();
}

$LOGFILE=realpath($LOGFILE);

# if any of these are symlinks allow that too...
my @zpaths =  map( "/opt/zextras/" . $_ , qw(log data/tmp zmstat) );
unshift( @zpaths, qw(/tmp /var/log) );

my $match = 0;
foreach my $path (@zpaths) {
    my $rpath = realpath($path);
    if ( defined($rpath) and $LOGFILE =~ /^$rpath/ ) {
        $match = 1;
        last;
    }
}

unless ($match) {
  print "Error: Specified log file must be created in one of the following locations: @zpaths\n\n";
  exit(1);
}

createPidFile('fd-real.pid');

my $date = getDate();
if ($CONSOLE) {
    $LOGFH = \*STDOUT;
    $LOGFH->print($HEADING . "\n");
    
} else {
    $LOGFH = openLogFile($LOGFILE, $HEADING);
    chown $zuid, $zgid, $LOGFILE;
    my $fmode = 0640; chmod $fmode, $LOGFILE;
}
waitUntilNiceRoundSecond($interval);

while (1) {
    my $stat = get_fd_stat();
    my $mbox_stat = get_mbox_stat();
    my $tstamp = getTstamp();
    my $currDate = getDate();
    if ($currDate ne $date && !$CONSOLE) {
        $LOGFH = rotateLogFile($LOGFH, $LOGFILE, $HEADING, $date);
        my ($name, $path) = File::Basename::fileparse($LOGFILE);
        my $rotatefile = "$path/$date/$name.gz";
        chown $zuid, $zgid, $rotatefile;
        chown $zuid, $zgid, $LOGFILE;
        my $fmode = 0640; chmod $fmode, $LOGFILE;
        $date = $currDate;
    }
    $ROTATE_DEFER = 1;
    $LOGFH->print("$tstamp, $stat, $mbox_stat\n");
    Zextras::Mon::Logger::LogStats( "info", "zmstat fd.csv: ${HEADING}:: $tstamp, $stat, $mbox_stat"); 
    $LOGFH->flush();
    $ROTATE_DEFER = 0;
    if ($ROTATE_NOW) {
        $ROTATE_NOW = 0;
        $LOGFH = rotateLogFile($LOGFH, $LOGFILE, $HEADING);
        my ($name, $path) = File::Basename::fileparse($LOGFILE);
        my $date = getDate();
        my $rotatefile = "$path/$date/$name.gz";
        chown $zuid, $zgid, $rotatefile;
        chown $zuid, $zgid, $LOGFILE;
        my $fmode = 0640; chmod $fmode, $LOGFILE;
    }
    sleep($interval);
}
