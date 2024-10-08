#!/usr/bin/perl -w

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

# Not a typo, df (not file-descriptors)

use strict;
use Getopt::Long;
use lib "/opt/zextras/common/lib/perl5";
use Zextras::Mon::Stat;
use Zextras::Mon::Logger;
use vars qw($LOGFH $CONSOLE $LOGFILE $ROTATE_NOW $ROTATE_DEFER);

zmstatInit();

my $DISK_CRIT_THRESHOLD = getLocalConfig("zmdisklog_critical_threshold") || 95;
my $DISK_WARN_THRESHOLD = getLocalConfig("zmdisklog_warn_threshold") || 85;
my $hostname = qx(/opt/zextras/bin/zmhostname);
chomp $hostname;

my $DF = 'df -k -x squashfs -x udev -x devtmpfs -x overlay -x efivarfs';
my $HEADING = 'timestamp, path, disk, disk_use, disk_space, disk_pct_used';

my @DF_EXCLUDES = split(/:/, getLocalConfig("zmstat_df_excludes") || "");

sub get_df_stat() {
    open(DF, "$DF |") || die "Can't open $DF: $!";
    my $dev;
    my @stats;
    while (<DF>) {
        next if ($_ =~ /^Filesystem\s+/);
        my ($space, $used, $avail, $pct, $path);
        if ($_ =~ /^(\S+)\s*$/) {
            $dev = $1;
            next;
        } elsif ($_ =~ /^(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\%\s+(.+)/) {
            $dev   = $1;
            $space = $2;
            $used  = $3;
            $avail = $4;
            $pct   = $5;
            $path  = $6;
        } elsif ($_ =~ /^\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\%\s+(.+)/) {
            $space = $1;
            $used  = $2;
            $avail = $3;
            $pct   = $4;
            $path  = $5;
        }
        next if $dev !~ m#^/#;
        push(@stats, {
            path => $path,
            disk => $dev,
            disk_use => $used,
            disk_pct_used => $pct,
            disk_space => $space
        });
    }
    close DF;
    @stats;
}
sub sighup {
    if (!$CONSOLE) {
        $LOGFH = rotateLogFile($LOGFH, $LOGFILE, $HEADING);
    } else {
        $ROTATE_NOW = 1;
    }
}
$SIG{HUP} = \&sighup;

sub usage {
    print STDERR << '_USAGE_';
Usage: zmstat-df [options]
Monitor disk usage
-i, --interval: output a line every N seconds
-l, --log:      log file (default is /opt/zextras/zmstat/df.csv)
-c, --console:  output to stdout

If logging to a file, rotation occurs when a HUP signal is sent or when
the date changes.  The current log is renamed to <dir>/YYY-MM-DD/df.csv
and a new file is created.
_USAGE_
    exit(1);
}

$| = 1;

$LOGFILE = getLogFilePath('df.csv');
my $interval = $Zextras::Mon::Stat::LC{'zmstat_disk_interval'};
my $opts_good = GetOptions(
    'interval=i' => \$interval,
    'log=s' => \$LOGFILE,
    'console' => \$CONSOLE,
);
if (!$opts_good) {
    print STDERR "\n";
    usage();
}
createPidFile('df.pid');

my $date = getDate();
if ($CONSOLE) {
    $LOGFH = \*STDOUT;
    $LOGFH->print($HEADING . "\n");
    
} else {
    $LOGFH = openLogFile($LOGFILE, $HEADING);
}
waitUntilNiceRoundSecond($interval);

while (1) {
    my @stats = get_df_stat();
    foreach my $df (@stats) {
    	my $pct = $df->{'disk_pct_used'};
    	my $dev = $df->{'disk'};
        my $mnt = $df->{'path'};
        my $skip_vol = 0;
        for my $vol ( @DF_EXCLUDES ) {
            $skip_vol = 1 if (($vol eq $mnt) || ($vol eq $dev));
        }
        if (($skip_vol == 1) && (($pct >= $DISK_CRIT_THRESHOLD) || ($pct >= $DISK_WARN_THRESHOLD))) {
            Zextras::Mon::Logger::Log( "info", "Disk warning: ${hostname}: $mnt on device $dev at $pct%");
        } elsif ($pct >= $DISK_CRIT_THRESHOLD) {
            Zextras::Mon::Logger::Log( "crit", "Disk warning: ${hostname}: $mnt on device $dev at $pct%"); 
    	} elsif ($pct >= $DISK_WARN_THRESHOLD) {
            Zextras::Mon::Logger::Log( "err", "Disk warning: ${hostname}: $mnt on device $dev at $pct%");
    	}
    }
    my $tstamp = getTstamp();
    my $currDate = getDate();
    if ($currDate ne $date && !$CONSOLE) {
        $LOGFH = rotateLogFile($LOGFH, $LOGFILE, $HEADING, $date);
        $date = $currDate;
    }
    $ROTATE_DEFER = 1;
    foreach my $stat (@stats) {
    	my $line = sprintf("%s, %s, %s, %d, %d, %d", $tstamp,
                           $stat->{path}, $stat->{disk}, $stat->{disk_use},
                           $stat->{disk_space}, $stat->{disk_pct_used});
        $LOGFH->print("$line\n");
        Zextras::Mon::Logger::LogStats( "info", "zmstat df.csv: ${HEADING}:: $line"); 
    }
    $LOGFH->flush();
    $ROTATE_DEFER = 0;
    if ($ROTATE_NOW) {
        $ROTATE_NOW = 0;
        $LOGFH = rotateLogFile($LOGFH, $LOGFILE, $HEADING);
    }
    sleep($interval);
}
sub getLocalConfig {
  my $key = shift;
  if (defined ($ENV{zmsetvars})) {
    return $ENV{$key};
  }
  open CONF,
    "/opt/zextras/bin/zmlocalconfig -q -m shell |" or die "Can't open local config: $!";
  my @conf = <CONF>;
  close CONF;

  chomp @conf;

  foreach (@conf) {
    my ($key, $val) = split '=', $_, 2;
    $val =~ s/;$//;
    $val =~ s/'$//;
    $val =~ s/^'//;
    $ENV{$key} = $val;
  }
  $ENV{zmsetvars} = 'true';
  return $ENV{$key};
}
