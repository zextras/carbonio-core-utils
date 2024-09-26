#!/usr/bin/perl -w

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

use strict;
use Carp ();
use Getopt::Long;
use lib "/opt/zextras/common/lib/perl5";
use Zimbra::Mon::Zmstat;
use Zimbra::Mon::Logger;
use Zimbra::DB::DB;

zmstatInit();

my ($CONSOLE, $LOGFH, $LOGFILE, $HEADING, $ROTATE_DEFER, $ROTATE_NOW);
my @statNames;

sub getHeading() {
    @statNames = ();
    my @status = Zimbra::DB::DB::runSql("SHOW GLOBAL STATUS", 0);
    my $heading = 'timestamp';
    foreach my $row (@status) {
        my ($name, $value) = split("\t", $row);
        $heading .= ', ' . $name;
        push(@statNames, $name);
    }
    return $heading;
}

sub getValues($) {
    my $tstamp = shift;
    my %stat;
    my @status = Zimbra::DB::DB::runSql("SHOW GLOBAL STATUS", 0);
    foreach my $row (@status) {
        my ($name, $value) = split("\t", $row);
        $stat{$name} = $value;
    }
    my $values = $tstamp;
    foreach my $name (@statNames) {
        my $value = $stat{$name};
        $value = '' if (!defined($value));
        $values .= ',' . $value;
    }
    return $values;
}

sub usage() {
    print STDERR <<_USAGE_;
Usage: zmstat-mysql [options]
Monitor MySQL status variables
-i, --interval: output a line every N seconds
-l, --log:      log file (default is /opt/zextras/zmstat/mysql.csv)
-c, --console:  output to stdout

If logging to a file, rotation occurs when HUP signal is sent or when
date changes.  Current log is renamed to <dir>/YYYY-MM-DD/mysql.csv
and a new file is created.
_USAGE_
    exit(1);
}

sub sighup {
    if (!$CONSOLE) {
        if (!$ROTATE_DEFER) {
            $LOGFH = rotateLogFile($LOGFH, $LOGFILE, $HEADING);
        } else {
            $ROTATE_NOW = 1;
        }
    }
}

#
# main
#

$| = 1; # Flush immediately

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

if (!defined($LOGFILE) || $LOGFILE eq '') {
    $LOGFILE = getLogFilePath('mysql.csv');
} elsif ($LOGFILE eq '-') {
    $CONSOLE = 1;
}
if ($CONSOLE) {
    $LOGFILE = '-';
}

createPidFile('mysql.pid');

local $SIG{__WARN__} = \&Carp::cluck;

$SIG{HUP} = \&sighup;

my $date = getDate();
my $t_last = waitUntilNiceRoundSecond($interval);
my $t_next = $t_last + $interval;

$HEADING = getHeading();
$LOGFH = openLogFile($LOGFILE, $HEADING);

while (1) {
    my $tstamp = getTstamp();
    my $currDate = getDate();
    if ($currDate ne $date) {
        $LOGFH = rotateLogFile($LOGFH, $LOGFILE, $HEADING, $date);
        $date = $currDate;
    }

    # Don't allow rotation in signal handler while we're writing.
    $ROTATE_DEFER = 1;
    eval {
    	my $values = getValues($tstamp);
        $LOGFH->print("$values\n");
        Zimbra::Mon::Logger::LogStats( "info", "zmstat mysql.csv: ${HEADING}:: $values"); 
        $LOGFH->flush();
    };
    if ($@) {
        print STDERR "$tstamp: $@\n";
    }
    $ROTATE_DEFER = 0;
    if ($ROTATE_NOW) {
        # Signal handler delegated rotation to main.
        $ROTATE_NOW = 0;
        $LOGFH = rotateLogFile($LOGFH, $LOGFILE, $HEADING);
    }

    my $now = time();
    my $howlong = $t_next - $now;
    if ($howlong > 0) {
        sleep($howlong);
    } else {
        sleep(1);
    }
    $t_next += $interval;
}
close($LOGFH);
