#!/usr/bin/perl

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

my $desthost=$ARGV[0];

shift;

my $keyfile="/opt/zextras/.ssh/zimbra_identity";

if ($desthost eq "") {
	print "Usage: $0 <hostname>\n";
	exit 1;
}

if ($#ARGV >= 0) {
	$cmd = "echo @ARGV | ssh -T -i ${keyfile} -o StrictHostKeyChecking=no zextras\@${desthost}";
} else {
	$cmd = "ssh -T -i ${keyfile} -o StrictHostKeyChecking=no zextras\@${desthost}";
}

open P, "$cmd |";
$SIG{ALRM} = \&quit;
while (<P>) {print $_; alarm(10);}
close P;

sub quit {
	exit 0;
}
