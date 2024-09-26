#!/usr/bin/perl

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

use lib "/opt/zextras/common/lib/perl5";
use strict;
use JSON::PP;
use Data::Dumper;

use  Zextras::Util::Common;
use Zextras::Mon::Logger;

# Exit if software-only node.
exit(0) unless (-f "/opt/zextras/conf/localconfig.xml");

$SIG{ALRM} = \&catchAlarm;

my $pidFile="/run/carbonio/zmstatuslog.pid";

my $TIMEOUT=60;
my $DFCMD;

$DFCMD = "df -ml ";


my $dt = qx(date "+%Y-%m-%d %H:%M:%S");
chomp $dt;

my $hostname;

checkPid();
logStatus();
clearPid();

exit 0;

sub logStatus {
	my @status = ();
  alarm($TIMEOUT);
	open STATUS, "/opt/zextras/bin/zmcontrol status |" or die "Can't get status: $!";
	@status = <STATUS>;
	close STATUS;

	my $ismailboxrunning = '';
	my $isaloggerserver = '';

	foreach my $s (@status) {
		if ($s =~ /is not/) {
			next;
		}
		chomp $s;
		if ($s =~ /^Host (.*)/) {
			$hostname = $1;
			next;
		}
		$s =~ s/ webapp//;
		my ($service, $stat) = split ' ', $s, 2;

		if (( $service eq 'mailbox' ) && ( $stat eq 'Running' )) {
			$ismailboxrunning = 'found';
		}

		if (( $service eq 'logger' ) && ( $stat eq 'Running' )) {
			$isaloggerserver = 'found';
		}

		Zextras::Mon::Logger::LogStats( "info", "$dt, STATUS: ${hostname}: $service: $stat" );
	}

	if (($ismailboxrunning) && ($isaloggerserver)) {
		if ( -e '/opt/zextras/bin/zxsuite' ) {
			my $docs_status = `/opt/zextras/bin/zxsuite --json docs status`;
			my $docs_hash = JSON::PP->new->utf8->decode($docs_status);
			my $list_servers = $docs_hash->{'response'};
			foreach my $server (@{$list_servers->{servers}}) {
				my $status = 'Stopped';
				if ( $server->{'status'} eq "online" ) {
					$status = 'Running';
				}
				Zextras::Mon::Logger::LogStats( "info", "$dt, STATUS: $server->{'name'}: docs: $status" );
			}
		}
	}

	alarm(0);
}

sub checkPid {
  if (-f "$pidFile") {
    my $P = qx(cat $pidFile);
    chomp $P;
    if ($P ne "") {
      system("kill -0 $P 2> /dev/null");
      if ($? == 0) {
        print "$0 already running with pid $P\n";
        exit 0;
      }
    }
  }
  qx(echo $$ > "$pidFile");
}

sub clearPid {
  unlink($pidFile);
}

sub catchAlarm {
		Zextras::Mon::Logger::LogStats( "info", "zmstatuslog timeout after $TIMEOUT seconds"); 
    exit 1;
}