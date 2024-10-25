#!/usr/bin/perl

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

sub handleTerm {
	print "SIGTERM received, exiting\n";
	qx(/opt/zextras/bin/zmcontrol stop >> /opt/zextras/log/zcs.log 2>&1);
	exit 0;
}

$SIG{TERM} = \&handleTerm;

if ($ARGV[0] eq "start") {
	qx(/opt/zextras/bin/zmcontrol start >> /opt/zextras/log/zcs.log 2>&1);
	sleep;
}
