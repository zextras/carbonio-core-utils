#!/usr/bin/perl -w

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

use strict;
use Carp ();
use Getopt::Long;
use lib "/opt/zextras/common/lib/perl5";
use Zextras::Mon::Stat;
use Zextras::Mon::Logger;

zmstatInit();

my ( $CONSOLE, $LOGFH, $LOGFILE, $HEADING, $ROTATE_DEFER, $ROTATE_NOW );
my $ZIMBRA_USER  = getZextrasUser();
my $POSTFIX_USER = 'postfix';

sub logerr($) {
    my $msg = shift;
    print STDERR getTstamp() . ": ERROR: $msg\n";
}

sub getEnabledProcs() {
    my $hostname = getZimbraServerHostname();

    my @procs;
    my $svc;
    my @enabledServices =
      qx(zmprov -l gs $hostname | grep zimbraServiceEnabled);
    foreach $svc (@enabledServices) {
        if ( $svc =~ /mailbox/ ) {
            push( @procs, 'mailbox' );
            push( @procs, 'mysql' );
            last;
        }
    }

    foreach $svc (@enabledServices) {
        if ( $svc =~ /ldap/ ) {
            push( @procs, 'ldap' );
            last;
        }
    }

    foreach $svc (@enabledServices) {
        if ( $svc =~ /mta/ ) {
            push( @procs, 'postfix' );
            last;
        }
    }

    foreach $svc (@enabledServices) {
        if ( $svc =~ /antispam/ || $svc =~ /antivirus/ ) {
            push( @procs, 'amavis' );
            push( @procs, 'clam' );
            last;
        }
    }

    push( @procs, 'zmstat' );
    return @procs;
}

sub getHeading(@) {
    my @procs = @_;
    my @cols;
    @cols = ( 'timestamp', 'system', 'user', 'sys', 'idle', 'iowait' );

    foreach my $p (@procs) {
        my $proc = $p->{'name'};
        push( @cols,
            $proc,           "$proc-total-cpu", "$proc-utime", "$proc-stime",
            "$proc-totalMB", "$proc-rssMB",     "$proc-sharedMB",
            "$proc-process-count" );
    }
    return join( ', ', @cols );
}

my @PS_COLS = ( 'user', 'pid', 'ppid', 'pcpu', 'vsz', 'rss', 'command' );
my $PS_CMD  = "ps axww -o " . join( ',', @PS_COLS );
my $POSTFIX_MASTER_PATTERN = '/libexec/master ';

my @PROCS;    # list of all processes (a snapshot)

sub procFromPs($) {
    my $aref = shift;    # reference to 7-element array
    my $i    = 0;
    my $ps   = {};
    foreach my $field (@PS_COLS) {
        $ps->{$field} = $aref->[$i];
        $i++;
    }
    return $ps;
}

sub snapshotProcs() {
    @PROCS = ();
    my @users = ( $ZIMBRA_USER, 'postfix' );
    if ( open( PS, "$PS_CMD |" ) ) {
        <PS>;    # discard heading line
        my $line;
        my $numCols = scalar(@PS_COLS);
        while ( defined( $line = readLine( *PS, 1 ) ) ) {
            my @cols = split( /\s+/, $line, $numCols );
            if ( scalar(@cols) < $numCols ) {
                next;
            }
            my $proc      = procFromPs( \@cols );
            my $user      = $proc->{'user'};
            my $rightUser = 0;
            foreach my $u (@users) {
                if ( $u eq $user ) {
                    $rightUser = 1;
                    last;
                }
            }
            if ( !$rightUser ) {

                # special case: check if command is postfix master process
                if ( $proc->{'command'} =~ '$POSTFIX_MASTER_PATTERN' ) {

                    # pretend this was run by postfix user
                    $proc->{'user'} = $POSTFIX_USER;
                }
                else {
                    # wrong user and not postfix master; ignore this process
                    next;
                }
            }
            push( @PROCS, $proc );
        }
        close(PS);
    }
}

sub filterProcs(;$$$) {

    # $user = username; undef to not filter on username
    # $contains = ref to array of regex to match in command
    # $notContains = ref to array of regex to not match in command
    my ( $user, $contains, $notContains ) = @_;
    my @ret;
  PROCESS_LOOP: foreach my $proc (@PROCS) {
        if ( defined($user) ) {
            if ( $proc->{'user'} ne $user ) {
                next;
            }
        }
        my $cmd = $proc->{'command'};
        if ( defined($contains) ) {
            foreach my $regex (@$contains) {
                if ( $cmd !~ /$regex/ ) {
                    next PROCESS_LOOP;
                }
            }
        }
        if ( defined($notContains) ) {
            foreach my $regex (@$notContains) {
                if ( $cmd =~ /$regex/ ) {
                    next PROCESS_LOOP;
                }
            }
        }
        push( @ret, $proc );
    }
    return @ret;
}

sub getMailboxProcess() {
    my @regex = ('jetty_home/start[.]jar');
    my @ret   = filterProcs( $ZIMBRA_USER, \@regex );
    return @ret;
}

# Use this if mysqld is a single multi-threaded process. (dynamically linked build)
sub getMysqlProcess() {
    my $zimbraHome = "/opt/zextras";
    my $ps         = qx(cat /run/carbonio/mysql.pid);
    chomp($ps) if ( defined($ps) );
    my @ret = ( { 'pid' => $ps } );
    return @ret;
}

# Use this if mysqld runs as multiple processes. (statically linked build)
sub getMysqlProcessList() {
    my @regex    = ( '/(libexec|bin)/mysqld ', '/my\.cnf' );
    my @regexNot = ('logger');
    my @ret      = filterProcs( $ZIMBRA_USER, \@regex, \@regexNot );
    return @ret;
}

sub getLDAPProcess() {
    my @regex = ('slapd');
    my @ret   = filterProcs( $ZIMBRA_USER, \@regex );
    return @ret;
}

sub getPostfixProcessList() {
    my @ret = filterProcs($POSTFIX_USER);
    return @ret;
}

sub getAmavisProcessList() {
    my @regex = ('amavisd');
    my @ret   = filterProcs( $ZIMBRA_USER, \@regex );
    return @ret;
}

sub getClamAVProcessList() {
    my @regex = ('(freshclam|clamd)');
    my @ret   = filterProcs( $ZIMBRA_USER, \@regex );
    return @ret;
}

sub getStatsProcessList() {
    my @regex = ('(zmstat-|iostat|vmstat|vm_stat|postqueue)');
    my @ret   = filterProcs( $ZIMBRA_USER, \@regex );
    return @ret;
}

my @DEFAULT_PROCS = (
    'mailbox', 'mysql',  'ldap',
    'postfix', 'amavis', 'clam',     'zmstat'
);
my %ps_subs = (
    'mailbox' => \&getMailboxProcess,
    'mysql'   => \&getMysqlProcessList,
    'ldap',     \&getLDAPProcess,
    'postfix',  \&getPostfixProcessList,
    'amavis',   \&getAmavisProcessList,
    'clam',     \&getClamAVProcessList,
    'zmstat',   \&getStatsProcessList
);

# (current, new) in, (new current, delta) out
sub computeDelta($$) {
    my ( $prev, $new ) = @_;
    my $delta;
    if ( $new >= $prev ) {
        return ( $new, $new - $prev );
    }
    else {
        return ( $new, 0 );
    }
}

#
# Process Stat
#

sub _getProcessStat($) {
    my $proc = shift;
    my $pid  = $proc->{'pid'};
    if ( !defined($pid) ) {
        logerr('Undefined pid');
        return ( 0, 0, 0, 0, 0, 0 );
    }
    if ( !open( STAT, "< /proc/$pid/stat" ) ) {
        logerr("No such process: '$pid'");
        return ( 0, 0, 0, 0, 0, 0 );
    }
    my $line = <STAT>;
    close(STAT);
    chomp($line);
    my @stat_cols = split( ' ', $line );

    if ( !open( STATM, "< /proc/$pid/statm" ) ) {
        logerr("No such process: '$pid'");
        return ( 0, 0, 0, 0, 0, 0 );
    }
    $line = <STATM>;
    close(STATM);
    chomp($line);
    my @statm_cols = split( ' ', $line );

    return (
        $stat_cols[13],               # utime
        $stat_cols[14],               # stime
        $statm_cols[0] * 4 / 1024,    # total process size in MB
        $statm_cols[1] * 4 / 1024,    # resident size in memory in MB
        $statm_cols[2] * 4 / 1024,    # shared size in MB
        1
    );                                # process count

}

# Get stats for a group of related processes.  For memory size
# computation, we assume all processes share the entire memory
# footprint.  (MySQL pretty much works this way.  Each process
# adds small stack and connection buffer, and that additional
# size should be under 200KB, which is negligible.)
sub _getProcessListStat {
    my @procs = @_;
    my @sum   = ( 0, 0, 0, 0, 0, 0 );
    my $count = 0;
    foreach my $proc (@procs) {
        next if ( !$proc );
        $count++;
        my @p = _getProcessStat($proc);
        foreach my $i ( 0, 1 ) {
            $sum[$i] += $p[$i];
        }
        foreach my $i ( 2, 3, 4 ) {
            $sum[$i] = $p[$i];
        }
    }
    $sum[5] = scalar($count);
    return @sum;
}

sub newProcessStat($$) {
    my ( $name, $procfunc ) = @_;
    my @procs   = &$procfunc();
    my @current = _getProcessListStat(@procs);
    my @delta   = ( 0, 0, 0, 0, 0, 0 );
    my $entry   = {
        'name'     => $name,
        'current'  => \@current,
        'delta'    => \@delta,
        'procfunc' => $procfunc
    };
    return $entry;
}

sub updateProcessStat($$) {
    my ( $entry, $elapsed_jiffies ) = @_;
    my $procfunc = $entry->{'procfunc'};
    my @procs    = &$procfunc();
    my @newstat  = _getProcessListStat(@procs);
    my $current  = $entry->{'current'};
    my $delta    = $entry->{'delta'};

    # utime, stime as percentage
    foreach my $col ( 0, 1 ) {
        my $d;
        ( $current->[$col], $d ) =
          computeDelta( $current->[$col], $newstat[$col] );
        $d = $elapsed_jiffies > 0 ? $d * 100 / $elapsed_jiffies : 0;
        $delta->[$col] = $d;
    }

    # vsize, rss, shared
    foreach my $col ( 2, 3, 4, 5 ) {
        $current->[$col] = $delta->[$col] = $newstat[$col];
    }
}

sub getProcessStat($) {
    my $entry        = shift;
    my $name         = $entry->{'name'};
    my $delta        = $entry->{'delta'};
    my $pct_utime    = sprintf( "%.1f", $delta->[0] );
    my $pct_stime    = sprintf( "%.1f", $delta->[1] );
    my $pct_cpu      = sprintf( "%.1f", $pct_utime + $pct_stime );
    my $totalMB      = sprintf( "%.1f", $delta->[2] );
    my $residentMB   = sprintf( "%.1f", $delta->[3] );
    my $sharedMB     = sprintf( "%.1f", $delta->[4] );
    my $numProcesses = $delta->[5];
    return ( $name, $pct_cpu, $pct_utime, $pct_stime,
        $totalMB, $residentMB, $sharedMB, $numProcesses );
}

#
# System Stat
#

sub _getSystemStat() {
    if ( !open( STAT, "< /proc/stat" ) ) {
        logerr("Can't read /proc/stat");
        return (0);
    }
    my @cols;
    my $line = undef;
    while ( $line = <STAT> ) {
        if ( $line =~ /^cpu\s/ ) {
            @cols = split( ' ', $line );
            last;
        }
    }
    close(STAT);
    my $total = 0;
    my $i;
    for ( $i = 1 ; $i <= 5 ; $i++ ) {
        $total += $cols[$i];
    }
    return (
        $cols[1] + $cols[2],    # user + nice
        $cols[3],               # sys
        $cols[4],               # idle
        $cols[5],               # iowait
        $total
    );
}

sub newSystemStat() {
    my @current = _getSystemStat();
    my @delta   = ( 0, 0, 0, 0, 0 );
    my $entry   = {
        'current' => \@current,
        'delta'   => \@delta
    };
    return $entry;
}

sub updateSystemStat($) {
    my $entry   = shift;
    my $current = $entry->{'current'};
    my $delta   = $entry->{'delta'};
    my @stat    = _getSystemStat();
    my $i;
    for ( $i = 0 ; $i < 5 ; $i++ ) {
        ( $current->[$i], $delta->[$i] ) =
          computeDelta( $current->[$i], $stat[$i] );
    }
    return $delta->[4];    # elapsed jiffies
}

sub getSystemStat($) {
    my $entry = shift;
    my $delta = $entry->{'delta'};
    my ( $pct_user, $pct_sys, $pct_idle, $pct_iowait );
    my $total = $delta->[4];
    if ( $total > 0 ) {
        $pct_user   = sprintf( "%.1f", $delta->[0] * 100 / $total );
        $pct_sys    = sprintf( "%.1f", $delta->[1] * 100 / $total );
        $pct_idle   = sprintf( "%.1f", $delta->[2] * 100 / $total );
        $pct_iowait = sprintf( "%.1f", $delta->[3] * 100 / $total );
    }
    else {
        $pct_user = $pct_sys = $pct_idle = $pct_iowait = 0;
    }
    return ( 'system', $pct_user, $pct_sys, $pct_idle, $pct_iowait );
}

sub usage() {
    print STDERR <<_USAGE_;
Usage: zmstat-proc [options]
Monitor various Carbonio processes
-i, --interval: output a line every N seconds
-l, --log:      log file (default is /opt/zextras/zmstat/proc.csv)
-c, --console:  output to stdout

If logging to a file, rotation occurs when HUP signal is sent or when
date changes.  Current log is renamed to <dir>/YYYY-MM-DD/proc.csv
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
    $LOGFILE = getLogFilePath('proc.csv');
}
elsif ( $LOGFILE eq '-' ) {
    $CONSOLE = 1;
}
if ($CONSOLE) {
    $LOGFILE = '-';
}

createPidFile('proc.pid');

local $SIG{__WARN__} = \&Carp::cluck;

$SIG{HUP} = \&sighup;

my $date   = getDate();
my $t_last = waitUntilNiceRoundSecond($interval);
my $t_next = $t_last + $interval;

my $system = newSystemStat();

my @procs;
my @all;
if ( scalar(@ARGV) > 0 ) {
    @all = @ARGV;
}
else {
    @all = getEnabledProcs();
    if ( scalar(@all) == 0 ) {

        # something wrong?  let's monitor them all
        @all = @DEFAULT_PROCS;
    }
}
snapshotProcs();
foreach my $proc (@all) {
    my $ps_sub = $ps_subs{$proc};
    if ( !defined($ps_sub) ) {
        print STDERR "Warning: Not possible to monitor process $proc\n";
        next;
    }
    my $entry = newProcessStat( $proc, $ps_subs{$proc} );
    push( @procs, $entry );
}

$HEADING = getHeading(@procs);
$LOGFH   = openLogFile( $LOGFILE, $HEADING );

while (1) {
    snapshotProcs();
    my $tstamp   = getTstamp();
    my $currDate = getDate();
    if ( $currDate ne $date ) {
        $LOGFH = rotateLogFile( $LOGFH, $LOGFILE, $HEADING, $date );
        $date  = $currDate;
    }

    my $elapsed_jiffies = updateSystemStat($system);
    foreach my $proc (@procs) {
        updateProcessStat( $proc, $elapsed_jiffies );
    }

    my @vals = ($tstamp);
    push( @vals, getSystemStat($system) );
    foreach my $proc (@procs) {
        push( @vals, getProcessStat($proc) );
    }

    # Don't allow rotation in signal handler while we're writing.
    $ROTATE_DEFER = 1;
    my $values = join( ", ", @vals );
    $LOGFH->print("$values\n");
    Zextras::Mon::Logger::LogStats( "info",
        "zmstat proc.csv: ${HEADING}:: $values" );
    $LOGFH->flush();
    $ROTATE_DEFER = 0;
    if ($ROTATE_NOW) {

        # Signal handler delegated rotation to main.
        $ROTATE_NOW = 0;
        $LOGFH      = rotateLogFile( $LOGFH, $LOGFILE, $HEADING );
    }

    my $now     = time();
    my $howlong = $t_next - $now;
    if ( $howlong > 0 ) {
        sleep($howlong);
    }
    else {
        sleep(1);
    }
    $t_next += $interval;
}
close($LOGFH);
