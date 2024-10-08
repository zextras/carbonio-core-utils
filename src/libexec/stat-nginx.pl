#!/usr/bin/perl -w

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

use strict;
use vars qw($PROCFS @STATLIST $LOGFILE $CONSOLE $interval $LOGFH
            $ROTATE_NOW $ROTATE_DEFER $date $HAS_IO_ACCT);
use Getopt::Long;
use lib "/opt/zextras/common/lib/perl5";
use Zextras::Mon::Stat;
use Zextras::Mon::Logger;
use Data::Dumper;

# Initial version will support forked process monitoring.  I/O accounting
# will fail in a threaded environment /proc/PID/io does not account task/TID
# I/O stats

$PROCFS = '/proc';
# /proc/PID/io is only available on linux kernels 2.6.20+ with real-time
# process IO statistics enabled
$HAS_IO_ACCT = -f "/proc/self/io";

@STATLIST =  ('utime', 'stime', 'cputime', 'rchar', 'wchar',
              'read_bytes', 'write_bytes', 'rss', 'processes', 'threads');

my $HEADING = join(", ", "timestamp", @STATLIST);

sub get_pid_tree() {
    my %pid_tree;
    my %pid_ppid;

    opendir(PROC, $PROCFS);
    my @procs = grep { /^\d+$/o } readdir(PROC);
    closedir(PROC);

    foreach my $pid (@procs) {
        if (open(STATUS, "<$PROCFS/$pid/status")) { # else pid has gone away
            my $ppid;
            while (my $line = <STATUS>) {
                if ($line =~ /^PPid:\s+(\d+)/o) {
                    $ppid = $1;
                    last;
                }
            }
            close(STATUS);
            next if (!defined($ppid));
            $pid_ppid{$pid} = $ppid;
        }
    }

    foreach my $pid (keys %pid_ppid) {
        my $ppid = $pid_ppid{$pid};
        if (!exists($pid_tree{$ppid})) {
            $pid_tree{$ppid} = [];
        }
        push(@{$pid_tree{$ppid}}, $pid);
    }
    %pid_tree;
}


sub collect_stats($$$) {
    my $pid      = shift;
    my $pid_tree = shift;
    my $dataref  = shift;
    if (open(STAT, "<$PROCFS/$pid/stat")) {
        my $stats = <STAT>;
        my @stats = split(/\s+/, $stats);
        $dataref->{$pid}->{'ppid'}    = $stats[3];
        $dataref->{$pid}->{'utime'}   = $stats[13];
        $dataref->{$pid}->{'stime'}   = $stats[14];
        $dataref->{$pid}->{'threads'} = $stats[19];
        $dataref->{$pid}->{'rss'}     = $stats[23] * 4;
        close(STAT);
    }
    if (open(STAT, "<$PROCFS/$pid/io")) {
        my @stats = <STAT>;
        foreach my $stat (@stats) {
            chomp($stat);
            my @s = split(/:\s*/, $stat);
            $dataref->{$pid}->{$s[0]} = $s[1];
        }
        close(STAT);
    }
    for my $child (@{$pid_tree->{$pid}}) {
        &collect_stats($child, $pid_tree, $dataref);
    }
}

sub get_nginx_pid {
    my $pid = 0;
    if (open(PID, "</run/carbonio/nginx.pid")) {
        chomp($pid = <PID>);
        close(PID);
    } else {
        if ( -l "/opt/zextras/nginx" ) {
            print STDERR "zmstat-nginx: cannot open nginx.pid: $!\n";
        }
    }
    return $pid;
}

sub delta_stat($$$$) {
    my $prev_stats = shift;
    my $curr_stats = shift;
    my $pid  = shift;
    my $stat = shift;

    #  Handle the possibility that proc stats are not obtained due to a process dying before stat data is actually retrieved.
    if (!defined($curr_stats->{$pid}->{$stat})) {
        0;
    } elsif (!defined($prev_stats->{$pid}->{$stat})) {
        $curr_stats->{$pid}->{$stat};
    } else {
        $curr_stats->{$pid}->{$stat} - $prev_stats->{$pid}->{$stat};
    }
}

sub main() {
    my $prev_stats;
    waitUntilNiceRoundSecond($interval);
    while (1) {
        my %pid_stats;
        my %pid_tree;
        
        my $currDate = getDate();
        my $tstamp = getTstamp();
        if ($currDate ne $date && !$CONSOLE) {
        	$LOGFH = rotateLogFile($LOGFH, $LOGFILE, $HEADING, $date);
        	$date = $currDate;
        }
    
        my $nginx_pid;
        while (!($nginx_pid = get_nginx_pid())) {
            sleep(15);
        }
        %pid_tree = get_pid_tree();
        collect_stats($nginx_pid, \%pid_tree, \%pid_stats);

    
        if ($prev_stats) {
            my %stats;
    
            $stats{'utime'}       = 0;
            $stats{'stime'}       = 0;
            $stats{'rchar'}       = 0;
            $stats{'wchar'}       = 0;
            $stats{'write_bytes'} = 0;
            $stats{'read_bytes'}  = 0;
            $stats{'rss'}         = 0;
    
            foreach my $pid (keys %pid_stats) {
                my @statlist;
                if ($HAS_IO_ACCT) {
                    @statlist = ('utime', 'stime', 'rchar', 'wchar',
                                    'read_bytes', 'write_bytes');
                } else {
                    @statlist = ('utime', 'stime');
                }
                if (exists($prev_stats->{$pid})) { # delta
                    for (@statlist) {
                        $stats{$_} += delta_stat(
                                $prev_stats, \%pid_stats, $pid, $_);
                    }
                } else { # new process, take full count
                    for (@statlist) {
                        $stats{$_} += $pid_stats{$pid}->{$_};
                    }
                }
                # memory usage is always a total
                $stats{'rss'}     += $pid_stats{$pid}->{'rss'};
                $stats{'threads'} += $pid_stats{$pid}->{'threads'};
            }
    
            $stats{'cputime'}   = $stats{'utime'} + $stats{'stime'};
            $stats{'processes'} = scalar(keys %pid_stats);
    
            $ROTATE_DEFER = 1;
            my @printstats;
            push(@printstats, $tstamp);
            for (@STATLIST) {
            	push(@printstats, $stats{$_});
            }
            my $values = join(', ', @printstats);
            $LOGFH->print("$values\n");
            Zextras::Mon::Logger::LogStats( "info", "zmstat nginx.csv: ${HEADING}:: $values"); 
            $LOGFH->flush();
            $ROTATE_DEFER = 0;
            if ($ROTATE_NOW) {
            	$ROTATE_NOW = 0;
            	$LOGFH = rotateLogFile($LOGFH, $LOGFILE, $HEADING);
            }
        }
        $prev_stats = \%pid_stats;
        
        sleep($interval);
    }
}

sub usage {
    print STDERR << '_USAGE_';
Usage: zmstat-nginx [options]
Monitor nginx cpu and I/O statistics
-i, --interval: output a line every N seconds
-l, --log:      log file (default is /opt/zextras/zmstat/nginx.csv)
-c, --console:  output to stdout

If logging to a file, rotation occurs when a HUP signal is sent or when
the date changes.  The current log is renamed to <dir>/YYY-MM-DD/nginx.csv
and a new file is created.
_USAGE_
    exit(1);
}

sub sighup {
    if (!$CONSOLE) {
    	$LOGFH = rotateLogFile($LOGFH, $LOGFILE, $HEADING, $date);
    } else {
    	$ROTATE_NOW = 1;
    }
}

eval {
	get_nginx_pid();
};
if ($@) {
	print STDERR "nginx not running, not launching zmstat-nginx\n";
	exit;
}

$| = 1;

zmstatInit();

$LOGFILE = getLogFilePath('nginx.csv');
$interval = getZmstatInterval();
my $opts_good = GetOptions(
    'interval=i' => \$interval,
    'log=s'      => \$LOGFILE,
    'console'    => \$CONSOLE,
);
if (!$opts_good) {
	print STDERR "\n";
	usage();
}
createPidFile("nginx.pid");
$SIG{HUP} = \&sighup;

$date = getDate();
if ($CONSOLE) {
    $LOGFH = \*STDOUT;
    $LOGFH->print($HEADING . "\n");
    
} else {
    $LOGFH = openLogFile($LOGFILE, $HEADING);
}
main();

