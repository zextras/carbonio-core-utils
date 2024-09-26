#!/usr/bin/perl

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

use strict;

if ($#ARGV != 2) {
    print STDERR "Usage: zmqaction action queuename queuid1[,queueid2]+\n";
    exit(1);
}

my $action = $ARGV[0];
my $queue = $ARGV[1];
my $idarg = $ARGV[2];

my $paction;
if ($action eq "hold") {
    $paction = "-h";
} elsif ($action eq "release") {
    $paction = "-H";
} elsif ($action eq "requeue") {
    $paction = "-r";
} elsif ($action eq "delete") {
    $paction = "-d";
} else {
    print STDERR "ERROR: unknown action $action\n";
    exit(1);
}


if ($queue !~ /^(incoming|active|deferred|hold|maildrop|corrupt)$/) {
    print STDERR "ERROR: unknown queue $queue\n";
    exit(1);
}

if ($idarg eq "ALL") {
    system("sudo /opt/zextras/common/sbin/postsuper $paction ALL $queue");
} else {
    my @ids = split(',', $idarg);
    my $command = "sudo /opt/zextras/common/sbin/postsuper $paction - $queue";
    if (open(POSTSUPER, "| $command")) {
        foreach my $id (@ids) {
            print POSTSUPER $id, "\n";
        }
        close(POSTSUPER);
    } else {
        print STDERR "ERROR: command $command: $!\n";
        exit(1);
    }
}
