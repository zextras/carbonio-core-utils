#!/usr/bin/perl
# 
# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

#
# Generate CVS file of CPU usage.
#

use strict;
use Date::Manip;
use Getopt::Long;
use Sys::Hostname;
$| = 1;
my $hostname = hostname;
my ($opt_interval, $opt_help);

GetOptions("interval=i" => \$opt_interval,
           "help" => \$opt_help) || usage($!);

if (defined($opt_help)) {
    usage();
}

if (!defined($opt_interval)) {
    $opt_interval = 60;
}

sub usage {
    my $error = shift;
    print("Error: ", $error, "\n\n") if (defined($error));
    print <<EOF;
Usage: $0
  -i --interval=secs     Seconds between reports (default 60)
EOF
    exit(1) if (defined($error));
    exit(0);
}
my $oldSnapshot = snapshotProcesses(); 
my $oldsi = systemInfo();
procstat();

sub snapshotProcesses() {
    my $result = {};
    opendir(DIR, "/proc") || die "opendir /proc: $!";
    while (defined(my $piddir = readdir(DIR))) {
        next if ($piddir !~ /^[0-9]+$/);
        open(STAT, "/proc/$piddir/stat") || next;
        while (<STAT>) {
            my @stats = split(/\s+/);
            my $pid = $stats[0];
            $result->{$pid} = \@stats;
        }
        close(STAT);
    }
    closedir(DIR);
    return $result;
}

sub dumpProcessSnapshot($) {
    my $snapshot = shift();
    foreach my $pid (keys %{$snapshot}) {
        my $stats = $snapshot->{$pid};
        print join(' ', @{$stats}), "\n";
    }
}

sub processInfo($) {
    my $result = {};
    my $pid = shift;
    my $statmfile = "/proc/$pid/statm";
    my $cmdlinefile = "/proc/$pid/cmdline";

    local $/;

    open(STATM, $statmfile) || return;
    my @sd = split(/\s+/, <STATM>);
    $result->{vmsize} = $sd[0];
    $result->{resident} = $sd[1];
    $result->{shared} = $sd[2];
    close(STATM);

    open(CMDLINE, $cmdlinefile) || return;
    my $cmdline = <CMDLINE>;
    $cmdline =~ s/\00/ /g;
    $cmdline =~ s/,/_COMMA_/g;
    $result->{cmdline} = $cmdline;
    close(CMDLINE);

    return $result;
}


sub systemInfo() {
    my $result = {};
    
    open(SYSSTAT, "/proc/stat") || die "Can't open /proc/stat: $!";
    while (<SYSSTAT>) {
        if (/^cpu\s+/) {
            my @d = split(/\s+/);
            my $total = 0;
            foreach my $t (@d) {
                $total += $t;
            }
            $result->{elapsed} = $total;
            last;
        }
    }
    close(SYSSTAT);
    return $result;
}

sub procstat() {
    print "time,host,pid,utime,stime,upct,spct,vmsize,resident,shared,cmdline\n";
    while (1) {
        sleep($opt_interval);
        my $newSnapshot = snapshotProcesses();
        my $si = systemInfo();
        my $date = UnixDate(ParseDate("now"), "%m/%d/%Y %H:%M:%S"); 
        foreach my $pid (keys %{$newSnapshot}) {
            my $oldStats = $oldSnapshot->{$pid};
            my $newStats = $newSnapshot->{$pid};

            my $utime;
            my $stime;
            my $prog = $newStats->[1];

            if (defined($oldStats) && ($oldStats->[1] eq $newStats->[1])) {
                $utime = $newStats->[13] - $oldStats->[13];
                $stime = $newStats->[14] - $oldStats->[14];
            } else {
                $utime = $newStats->[13];
                $stime = $newStats->[14];
            }

            if ($utime == 0 && $stime == 0) {
                # process did not consume any ticks
                next;
            }

            my $elapsed = $si->{elapsed} - $oldsi->{elapsed};
            my $utimepct = sprintf("%.1f", $utime * 100.0 / $elapsed);
            my $stimepct = sprintf("%.1f", $stime * 100.0 / $elapsed);

            my $pi = processInfo($pid);
            print join(',', $date, $hostname, $pid, $utime, $stime,
                       $utimepct, $stimepct, $pi->{vmsize}, $pi->{resident},
                       $pi->{shared}, $pi->{cmdline}), "\n";
        }
        $oldSnapshot = $newSnapshot;
        $oldsi = $si;
    }
}
