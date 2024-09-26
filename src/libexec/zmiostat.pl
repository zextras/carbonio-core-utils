#!/usr/bin/perl
# 
# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

#
# Generate CSV files from iostat output
#

use strict;
use Date::Manip;
use Getopt::Long;
use Sys::Hostname;
$| = 1;
my $hostname = hostname;
my ($opt_interval, $opt_cpufile, $opt_help);

GetOptions("interval=i" => \$opt_interval,
           "cpu=s" => \$opt_cpufile,
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
    -c --cpu=file          Also record cpu statistics to specified file
EOF
    exit(1) if (defined($error));
    exit(0);
}

iostat();

sub iostat() {
    open(IOSTAT, "iostat -t -x $opt_interval |");
    if (defined($opt_cpufile)) {
        open(CPU, "> $opt_cpufile") || die "can't open: $opt_cpufile: $!";
    }
    CPU->autoflush(1);
    
    my $time;
    my $inDevices = 0;
    my $expectCPU = 0;
    my $printDeviceHeader = 1;
    my $printCPUHeader = 1;
    
    while (<IOSTAT>) {
        if (/^Time:/) {
            chomp;
            s/^Time:\s*//g;
            $time = UnixDate(ParseDate($_), "%m/%d/%Y %H:%M:%S");
            next;
        }
        
        if (defined($opt_cpufile) && /^avg-cpu:/) {
            $expectCPU = 1;
            if ($printCPUHeader) {
                $printCPUHeader = 0;
                s/^avg-cpu:\s*//g;
                print CPU join(",", "time", "host", split(/\s+/, $_)), "\n";
            }
            next;
        }

        if (defined($opt_cpufile) && $expectCPU) {
            $expectCPU = 0;
            s/^\s*//g;
            print CPU join(",", $time, $hostname, split(/\s+/, $_)), "\n";
            next;
        }

        if (/^Device:/) {
            $inDevices = 1;
            if ($printDeviceHeader) {
                $printDeviceHeader = 0; 
                s/^Device:/device/g;
                print join(",", "time", "host", split(/\s+/, $_)), "\n";
            }
            next;
        }

        if (/^\s*$/ && $inDevices) {
            $inDevices = 0;
            next;
        }
        
        if ($inDevices) {
            print join(",", $time, $hostname, split(/\s+/, $_)), "\n";
            next;
        }     
    }
    if (defined($opt_cpufile)) {
        close(CPU);
    }
    close(IOSTAT);
}
