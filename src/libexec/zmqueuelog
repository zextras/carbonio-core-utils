#!/usr/bin/perl

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

use strict;

use lib "/opt/zextras/common/lib/perl5";
use Zextras::Util::Common;
use Zextras::Mon::Logger;

my $DFCMD;
$DFCMD = "df -ml ";


my $dt = qx(date "+%Y-%m-%d %H:%M:%S");
chomp $dt;

checkPid();
logQueue();
clearPid();

exit 0;

sub checkPid {
	if (-f "/run/carbonio/zmqueuelog.pid") {
		my $P = qx(cat /run/carbonio/zmqueuelog.pid);
		chomp $P;
		if ($P ne "") {
      system("kill -0 $P 2> /dev/null");
      if ($? == 0) {
        print "$0 already running with pid $P\n";
        exit 0;
      }
		}
	}
	qx(echo $$ > "/run/carbonio/zmqueuelog.pid");
}

sub clearPid {
	unlink ("/run/carbonio/zmqueuelog.pid");
}

sub logQueue {
	my @status = ();
	open STATUS, "/opt/zextras/common/sbin/postqueue -p |" or die "Can't get status: $!";
	@status = <STATUS>;
	close STATUS;
	my $kb = 0;
	my $msgs = 0;
	my $s = $status[$#status];
	if ($s =~ /^--/) {
		my @foo = split (' ', $s);
		$kb = $foo[1];
		$msgs = $foo[4];
	}
	Zextras::Mon::Logger::Log( "info", "$dt, QUEUE: $kb $msgs" );
}