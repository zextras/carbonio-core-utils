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
use Zimbra::Mon::Zmstat;
use Zimbra::Mon::Logger;
use Data::Dumper;
use Scalar::Util qw(looks_like_number);

# Initial version will support forked process monitoring.  I/O accounting
# will fail in a threaded environment /proc/PID/io does not account task/TID
# I/O stats

$PROCFS = '/proc';
# /proc/PID/io is only available on linux kernels 2.6.20+ with real-time
# process IO statistics enabled
$HAS_IO_ACCT = -f "/proc/self/io";

@STATLIST =  ('utime', 'stime', 'cputime', 'rchar', 'wchar',
              'read_bytes', 'write_bytes', 'rss', 'processes', 'threads');

my $HEADING = join(", ", "timestamp", "process", @STATLIST);

sub get_pid_tree() {
    my %pid_tree;
    my %pid_ppid;
    my %pid_names;

    opendir(PROC, $PROCFS);
    my @procs = grep { /^\d+$/o } readdir(PROC);
    closedir(PROC);

    foreach my $pid (@procs) {
        if (open(STATUS, "<$PROCFS/$pid/status")) { # else pid has gone away
            my $ppid;
            my $cmd;
            while (my $line = <STATUS>) {
                if ($line =~ /^PPid:\s+(\d+)/o) {
                    $ppid = $1;
                    last if $cmd;
                }

                if ($line =~ /^Name:\s+(\S+)/o) {
                    $cmd = $1;
                    last if $ppid;
                }
            }
            close(STATUS);

			if ($cmd =~ /java/) {
				if (open(CMDLINE, "<$PROCFS/$pid/cmdline")) { # else pid has gone away
					while (my $line = <CMDLINE>) {
						my @args = split('\0',$line);
						$cmd = 'zmconfigd' if ($args[$#args] =~ /\/opt\/zextras\/libexec\/zmconfigd/);
						$cmd = 'zmmailboxd' if ($args[$#args] =~ /\/opt\/zextras\/mailboxd\/etc\/jetty.xml/);
					}
				}
			}

            next if (!defined($ppid));
            next if (!defined($cmd));
            $pid_names{$pid} = $cmd;
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
    (\%pid_tree, \%pid_names);
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

sub delta_stat($$$$) {
    my $prev_stats = shift;
    my $curr_stats = shift;
    my $pid  = shift;
    my $stat = shift;

    #  Handle the possibility that proc stats are not obtained due to a process dying before stat data is actually retrieved.
    if (!looks_like_number($curr_stats->{$pid}->{$stat})) {
        0;
    } elsif (!looks_like_number($prev_stats->{$pid}->{$stat})) {
        $curr_stats->{$pid}->{$stat};
    } else {
        $curr_stats->{$pid}->{$stat} - $prev_stats->{$pid}->{$stat};
    }
}

sub get_pids_by_name($$) {
    my $pid_names = shift;
    my $name = shift;

    my @pids;

    foreach my $key (keys %$pid_names) {
        push(@pids, $key) if $name eq $pid_names->{$key};
    }
    @pids;
}
sub get_process_names($) {
    my $pid_names = shift;

    my %names;

    foreach my $name (values %$pid_names) {
        $names{$name} = 1;
    }

    keys %names;
}

sub main() {
    my $prev_stats;
    waitUntilNiceRoundSecond($interval);
    while (1) {
        my %pid_stats;
        my $pid_tree;
        my $pid_names;
        
        my $currDate = getDate();
        my $tstamp = getTstamp();
        if ($currDate ne $date && !$CONSOLE) {
        	$LOGFH = rotateLogFile($LOGFH, $LOGFILE, $HEADING, $date);
        	$date = $currDate;
        }
    
        ($pid_tree, $pid_names) = get_pid_tree();
        collect_stats(1, $pid_tree, \%pid_stats);
    
        if ($prev_stats) {
            my %stats;
    
    
            my @names = get_process_names($pid_names);
            foreach my $name (@names) {
                my @pids = get_pids_by_name($pid_names, $name);

                $stats{$name} = {};
                $stats{$name}->{'utime'}       = 0;
                $stats{$name}->{'stime'}       = 0;
                $stats{$name}->{'rchar'}       = 0;
                $stats{$name}->{'wchar'}       = 0;
                $stats{$name}->{'write_bytes'} = 0;
                $stats{$name}->{'read_bytes'}  = 0;
                $stats{$name}->{'rss'}         = 0;
                foreach my $pid (@pids) {
                    my @statlist;
                    if ($HAS_IO_ACCT) {
                        @statlist = ('utime', 'stime', 'rchar', 'wchar',
                                        'read_bytes', 'write_bytes');
                    } else {
                        @statlist = ('utime', 'stime');
                    }
                    if (exists($prev_stats->{$pid}) && exists($pid_stats{$pid})) { # delta
                        for (@statlist) {
                            $stats{$name}->{$_} += delta_stat(
                                    $prev_stats, \%pid_stats, $pid, $_);
                        }
                    } else { # new process, take full count
                        for (@statlist) {
                        	$pid_stats{$pid}->{$_} = 0 if !defined $pid_stats{$pid}->{$_};
                        	$stats{$name}->{$_}    = 0 if !defined $stats{$name}->{$_};
                            $stats{$name}->{$_} += $pid_stats{$pid}->{$_};
                        }
                    }
                    $stats{$name}->{'rss'}        = 0 if !defined $stats{$name}->{'rss'};
                    $pid_stats{$pid}->{'rss'}     = 0 if !defined $pid_stats{$pid}->{'rss'};
                    $stats{$name}->{'threads'}    = 0 if !defined $stats{$name}->{'threads'};
                    $pid_stats{$pid}->{'threads'} = 0 if !defined $pid_stats{$pid}->{'threads'};
                    
                    # memory usage is always a total
                    $stats{$name}->{'rss'}     += $pid_stats{$pid}->{'rss'};
                    $stats{$name}->{'threads'} += $pid_stats{$pid}->{'threads'};
                }
                $stats{$name}->{'cputime'}   =
                        $stats{$name}->{'utime'} + $stats{$name}->{'stime'};
                $stats{$name}->{'processes'} = scalar @pids;


                $ROTATE_DEFER = 1;
                my @printstats;
                push(@printstats, $tstamp, $name);
                for (@STATLIST) {
            	    push(@printstats, $stats{$name}->{$_});
                }
                my $values = join(', ', @printstats);
                $LOGFH->print("$values\n");
                # allprocs causes way too much traffic to send to logger at the moment
                # Zimbra::Mon::Logger::LogStats( "info", "zmstat allprocs.csv: ${HEADING}:: $values"); 
                $LOGFH->flush();
                $ROTATE_DEFER = 0;
                if ($ROTATE_NOW) {
            	    $ROTATE_NOW = 0;
                    $LOGFH = rotateLogFile($LOGFH, $LOGFILE, $HEADING);
                }
            }
    
        }
        $prev_stats = \%pid_stats;
        
        sleep($interval);
    }
}

sub usage {
    print STDERR << '_USAGE_';
Usage: zmstat-allprocs [options]
Monitor all process cpu and I/O statistics
-i, --interval: output a line every N seconds
-l, --log:      log file (default is /opt/zextras/zmstat/allprocs.csv)
-c, --console:  output to stdout

If logging to a file, rotation occurs when a HUP signal is sent or when
the date changes.  The current log is renamed to <dir>/YYY-MM-DD/allprocs.csv
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

$| = 1;

zmstatInit();

$LOGFILE = getLogFilePath('allprocs.csv');
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
createPidFile("allprocs.pid");
$SIG{HUP} = \&sighup;

$date = getDate();
if ($CONSOLE) {
    $LOGFH = \*STDOUT;
    $LOGFH->print($HEADING . "\n");
    
} else {
    $LOGFH = openLogFile($LOGFILE, $HEADING);
}
main();

