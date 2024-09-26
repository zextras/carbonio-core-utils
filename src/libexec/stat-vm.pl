#!/usr/bin/perl -w

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

# Periodically print vmstat and /proc/meminfo output as comma-separated values.
# Most values are in KB.  See 'man vmstat' and 'cat /proc/meminfo' for more
# info.
#
# Notable columns are:
#
# r - number of processes waiting for run time
# swpd - amount of virtual memory used (KB)
# free - amount of idle/free memory (KB)
# cache - amount of memory used by page cache (KB)
# si - swap in KB/s
# so - swap out KB/s
# cs - number of context switches per second
# us - % user (non-kernel) time, including nice time
# sy - % kernel time
# id - % idle time
# wa - % iowait
# Active - active memory pages (KB)
# Inactive - inactive memory pages (KB)
# Dirty
# Writeback
# Mapped

use strict;
use Getopt::Long;
use lib "/opt/zextras/common/lib/perl5";
use Zimbra::Mon::Zmstat;
use Zimbra::Mon::Logger;

zmstatInit();

my $VMSTAT  = '/usr/bin/vmstat -n -S K';
my $MEMINFO = '/proc/meminfo';
my $LOADAVG = '/proc/loadavg';
my @VMSTAT_FIELDS;
my @MEMINFO_FIELDS;

my ( $CONSOLE, $LOGFH, $LOGFILE, $HEADING, $ROTATE_DEFER, $ROTATE_NOW );

sub getHeading() {
    my $line;
    open( VMSTAT_H, "$VMSTAT |" ) or die "Can't run $VMSTAT: $!";
    <VMSTAT_H>;
    $line = <VMSTAT_H>;
    chomp($line);
    $line =~ s/^\s+//;
    @VMSTAT_FIELDS = split( /\s+/, $line );
    close(VMSTAT_H);
    open( MEMINFO_H, "< $MEMINFO" ) or die "Can't open $MEMINFO: $!";

    while ( defined( $line = <MEMINFO_H> ) ) {
        my @fields = split( /[:\s]+/, $line );
        push( @MEMINFO_FIELDS, $fields[0] );
    }
    close(MEMINFO_H);
    return
      join( ', ', 'timestamp', @VMSTAT_FIELDS, @MEMINFO_FIELDS, "loadavg" );
}

sub getMeminfo() {
    my %meminfo;
    open( MEMINFO, "< $MEMINFO" ) or die "Can't open $MEMINFO: $!";
    my $line;
    while ( defined( $line = <MEMINFO> ) ) {
        my @fields = split( /[:\s]+/, $line );
        $meminfo{ $fields[0] } = $fields[1];
    }
    close(MEMINFO);
    my @vals;
    foreach my $key (@MEMINFO_FIELDS) {
        push( @vals, $meminfo{$key} || 0 );
    }
    return join( ', ', @vals );
}

sub getLoadInfo() {
    my %meminfo;
    open( LOADAVG, "< $LOADAVG" ) or die "Can't open $LOADAVG: $!";
    my $line = <LOADAVG>;
    $line =~ /^(\S+)\s+/;
    my $load = $1;
    close(LOADAVG);
    return $load;
}

my $stat_pid;

sub runVMSTAT($) {
    my $interval = shift;
    my $fh       = new FileHandle;
    my $cmd      = "$VMSTAT $interval";
    $stat_pid = open( $fh, "$cmd |" )
      || die "Unable to execute command \"$cmd\": $!";

    # Skip over the first three lines.
    $fh->getline();
    $fh->getline();
    $fh->getline();
    return $fh;
}

sub usage() {
    print STDERR <<_USAGE_;
Usage: zmstat-vm [options]
Monitor vmstat info
-i, --interval: output a line every N seconds
-l, --log:      log file (default is /opt/zextras/zmstat/vm.csv)
-c, --console:  output to stdout

If logging to a file, rotation occurs when HUP signal is sent or when
date changes.  Current log is renamed to <dir>/YYYY-MM-DD/vm.csv
and a new file is created.
_USAGE_
    exit(1);
}

sub sighup {
    if ( !$CONSOLE ) {
        if ( !$ROTATE_DEFER ) {
            $LOGFH = rotateLogFile( $LOGFH, $LOGFILE, $HEADING );
        }
        else {
            $ROTATE_NOW = 1;
        }
    }
}

#
# main
#

$| = 1;    # Flush immediately

my $interval  = getZmstatInterval();
my $opts_good = GetOptions(
    'interval=i' => \$interval,
    'log=s'      => \$LOGFILE,
    'console'    => \$CONSOLE,
);
if ( !$opts_good ) {
    print STDERR "\n";
    usage();
}

if ( !defined($LOGFILE) || $LOGFILE eq '' ) {
    $LOGFILE = getLogFilePath('vm.csv');
}
elsif ( $LOGFILE eq '-' ) {
    $CONSOLE = 1;
}
if ($CONSOLE) {
    $LOGFILE = '-';
}

createPidFile('vm.pid');

$SIG{HUP} = \&sighup;

$HEADING = getHeading();
$LOGFH   = openLogFile( $LOGFILE, $HEADING );

my $date = getDate();
waitUntilNiceRoundSecond($interval);
my $vmstatFH = runVMSTAT($interval);

sub sigterm {
    kill( 15, $stat_pid ) if $stat_pid;
    close($vmstatFH)      if $vmstatFH;
    exit(0);
}
$SIG{TERM} = \&sigterm;
while (1) {
    my $line;
    while ( !defined( $line = readLine( $vmstatFH, 1 ) ) ) {

        # Restart vmstat if it got killed for some reason.
        waitUntilNiceRoundSecond($interval);
        close($vmstatFH);
        $vmstatFH = runVMSTAT($interval);
    }
    $line =~ s/^\s+//;    # remove leading whitespaces
    $line =~ s/\s+$//;    # remove trailing whitespaces
     # Skip the two-line heading (plus the system-wide totals line) that Mac OSX vm_stat prints every 20 iterations.
    if ( $line !~ /^\d/ ) {

# If the line does not start with a numeric value, we've hit the first header line.  So, skip these
# three lines
        $line = readLine( $vmstatFH, 1 );
        $line = readLine( $vmstatFH, 1 );
        $line = readLine( $vmstatFH, 1 );
        $line =~ s/^\s+//;
        $line =~ s/\s+$//;
    }

    $line =~ s/\s+/, /g;    # space separated --> comma separated
    $line .= ', ' . getMeminfo();
    $line .= ', ' . getLoadInfo();

    my $tstamp   = getTstamp();
    my $currDate = getDate();
    if ( $currDate ne $date ) {
        $LOGFH = rotateLogFile( $LOGFH, $LOGFILE, $HEADING, $date );
        $date  = $currDate;
    }

    # Don't allow rotation in signal handler while we're writing.
    $ROTATE_DEFER = 1;
    $LOGFH->print("$tstamp, $line\n");
    Zimbra::Mon::Logger::LogStats( "info",
        "zmstat vm.csv: ${HEADING}:: $tstamp, $line" );
    $LOGFH->flush();
    $ROTATE_DEFER = 0;
    if ($ROTATE_NOW) {

        # Signal handler delegated rotation to main.
        $ROTATE_NOW = 0;
        $LOGFH      = rotateLogFile( $LOGFH, $LOGFILE, $HEADING );
    }
}
close($vmstatFH);
close($LOGFH);
