#!/usr/bin/perl -w

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

use strict;
use Getopt::Long;
use lib "/opt/zextras/common/lib/perl5";
use Zimbra::Mon::Zmstat;
use Zimbra::Mon::Logger;

zmstatInit();

my $IOSTAT = '/usr/bin/iostat';
if ( !-e $IOSTAT ) {
    $IOSTAT = '/usr/sbin/iostat';
    if ( !-e $IOSTAT ) {
        die "No iostat installed on this host";
    }
}

system($IOSTAT);
if ( $? != 0 ) {
    die "iostat is non-functional";
}

my ( $CONSOLE, $LOGFH, $LOGFILE, $HEADING, $ROTATE_DEFER, $ROTATE_NOW );

sub getHeadingMac() {
    my @cols = ('timestamp');
    my $line = '';
    my $cmd  = "export LANG=C; $IOSTAT -d -K";
    open( HEADING, "$cmd |" )
      || die "Unable to execute command \"$cmd\": $!";

    # First line has device list.
    $line = readLine( *HEADING, 1 );
    $line =~ s/^\s+//;
    $line =~ s/\s+$//;
    my @devs = split( /\s+/, $line );
    foreach my $dev (@devs) {
        push( @cols, "$dev:kB/t", "$dev:tps", "$dev:kB/s" );
    }
    close(HEADING);
    return join( ', ', @cols );
}

sub getHeading($) {
    my $opts = shift;
    my @cols = ('timestamp');
    my $line = '';
    my $cmd  = "export LANG=C; $IOSTAT $opts";
    open( HEADING, "$cmd |" )
      || die "Unable to execute command \"$cmd\": $!";

    # Look for the beginning of either CPU section or device section.
    while ( $line !~ /^avg-cpu/ && $line !~ /^Device/ ) {
        $line = readLine( *HEADING, 1 );
    }

    # Process optional CPU stat lines.
    if ( $line =~ /^avg-cpu/ ) {
        $line =~ s/^avg-cpu:\s+//;
        push( @cols, split( '\s+', $line ) );
    }

    # Process the device stat lines.
    while ( $line !~ /^Device/ ) {
        $line = readLine( *HEADING, 1 );
    }
    $line =~ s/^Device\s+//;
    my @devs;
    my @dev_cols = split( '\s+', $line );
    $line = readLine( *HEADING, 1 );
    while ( $line ne '' ) {
        my @vals = split( '\s+', $line );
        push( @devs, $vals[0] );
        $line = readLine( *HEADING, 0 );
    }
    close(HEADING);

    foreach my $dev (@devs) {
        foreach my $col (@dev_cols) {
            push( @cols, $dev . ":" . $col );
        }
    }

    return join( ', ', @cols );
}

my $stat_pid;

sub runIOSTAT($$) {
    my ( $opts, $interval ) = @_;
    my $fh  = new FileHandle;
    my $cmd = "$IOSTAT $opts $interval";
    $stat_pid = open( $fh, "$cmd |" )
      || die "Unable to execute command \"$cmd\": $!";
    return $fh;
}

sub usage() {
    print STDERR <<_USAGE_;
Usage: zmstat-io [options]
-i, --interval: output a line every N seconds
-l, --log:      log file (default is /opt/zextras/zmstat/io[-x].csv)
-x, --xtended:  extended output
-c, --console:  output to stdout

Default log file name is io.csv, or io-x.csv if -x option is used.
On Macs, the -x option must be specified.

If logging to a file, rotation occurs when HUP signal is sent or when
date changes.  Current log is renamed to <dir>/YYYY-MM-DD/io[-x].csv
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
my $xtended   = 0;
my $opts_good = GetOptions(
    'interval=i' => \$interval,
    'log=s'      => \$LOGFILE,
    'xtended'    => \$xtended,
    'console'    => \$CONSOLE
);
if ( !$opts_good ) {
    print STDERR "\n";
    usage();
}

if ( !defined($LOGFILE) || $LOGFILE eq '' ) {
    $LOGFILE = getLogFilePath( $xtended ? 'io-x.csv' : 'io.csv' );
}
elsif ( $LOGFILE eq '-' ) {
    $CONSOLE = 1;
}
if ($CONSOLE) {
    $LOGFILE = '-';
}
my $iostatOpts = '-d -k';
if ($xtended) {
    $iostatOpts .= ' -x';
}

createPidFile( $xtended ? 'io-x.pid' : 'io.pid' );

$SIG{HUP} = \&sighup;

$HEADING = getHeading($iostatOpts);
$LOGFH   = openLogFile( $LOGFILE, $HEADING );

my $date = getDate();
waitUntilNiceRoundSecond($interval);
my $iostatFH = runIOSTAT( $iostatOpts, $interval );

sub sigterm {
    kill( 15, $stat_pid ) if $stat_pid;
    close($iostatFH)      if $iostatFH;
    exit(0);
}
$SIG{TERM} = \&sigterm;

while (1) {
    my $line;
    while ( !defined( $line = readLine( $iostatFH, 1 ) ) ) {

        # Restart iostat if it got killed for some reason.
        waitUntilNiceRoundSecond($interval);
        close($iostatFH);
        $iostatFH = runIOSTAT( $iostatOpts, $interval );
    }

    if ( ( $line =~ /^avg-cpu/ || $line =~ /^Device/ ) ) {
        my @vals;
        my $tstamp   = getTstamp();
        my $currDate = getDate();
        if ( $currDate ne $date ) {
            $LOGFH = rotateLogFile( $LOGFH, $LOGFILE, $HEADING, $date );
            $date  = $currDate;
        }
        if ( $line =~ /^avg-cpu/ ) {
            $line = readLine( $iostatFH, 1 );    # CPU stats
            $line =~ s/^\s+//;                   # Remove leading whitespaces.
            push( @vals, split( '\s+', $line ) );
        }
        while ( defined($line) && $line !~ /^Device/ ) {
            $line = readLine( $iostatFH, 1 );
        }
        $line = readLine( $iostatFH, 1 );
        while ( $line ne '' ) {
            my @disk_vals = split( '\s+', $line );
            push( @vals, splice( @disk_vals, 1 ) );
            $line = readLine( $iostatFH, 0 );
        }

        # Don't allow log rotation in signal handler while we're writing.
        $ROTATE_DEFER = 1;
        my $values = join( ', ', @vals );
        $LOGFH->print("$tstamp, $values\n");
        my $fn = $xtended ? "io-x.csv" : "io.csv";
        Zimbra::Mon::Logger::LogStats( "info",
            "zmstat $fn: ${HEADING}:: $tstamp, $values" );
        $LOGFH->flush();
        $ROTATE_DEFER = 0;

        if ($ROTATE_NOW) {

            # Signal handler delegated rotation to main.
            $ROTATE_NOW = 0;
            $LOGFH      = rotateLogFile( $LOGFH, $LOGFILE, $HEADING );
        }
    }
}
close($iostatFH);
close($LOGFH);
