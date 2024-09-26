#!/usr/bin/perl
# 
# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only
# 

use strict;
use Getopt::Std;
my %options = ();

unless ( getopts( 'vhaH:u:p:l:skP:f:c:', \%options ) ) {usage();}

if ($options{h} || (!$options{r} && !$options{a})) {usage();}

if ($options{a}) {
	if (!($options{a} && (
		$options{u} &&
		$options{H} &&
		$options{p} &&
		$options{l} &&
		$options{P})
		)) {usage();}

	if ($options{P} ne "IMAP" && $options{f}) {
		print STDERR "Can't specify -f with $options{P}\n\n";
		usage();
	}
}

my @cflines = ();

if ($options{c}) {
	readConfig();
}

if ($options{a}) {
	my $confline;

	my $server = $options{H};
	$server =~ s/:.*//;
	my $port = $options{H};
	$port =~ s/.*://;
	my $user = $options{u};
	my $password = $options{p};
	my $protocol = $options{P};
	my $folder = $options{f};
	my $keep = $options{k};
	my $plugin = $options{s};
	my $localuser = $options{l};

	my %uhash = ();

	$uhash{user} = $user;
	$uhash{server} = $server;
	$uhash{port} = $port;
	$uhash{protocol} = $protocol;
	$uhash{plugin} = $plugin;
	$uhash{password} = $password;
	$uhash{folder} = $folder;
	$uhash{keep} = $keep;
	$uhash{localuser} = $localuser;
	push (@cflines, \%uhash);
}

if ($options{c}) {
	open (FILE, ">$options{c}") or die "Can't write to $options{c}: $!";
	foreach my $user (@cflines) {
		my $folder = $$user{folder}?"folder \"$$user{folder}\"":"";
		my $keep = $$user{keep}?"keep":"";
		my $plugin = $$user{plugin}?"plugin \"openssl s_client -quiet -connect $$user{server}:$$user{port}\"":"";
		my $smtpname = $$user{localuser}?"smtpname $$user{localuser}":"";
		my $confline = sprintf ("poll %s port %s protocol %s %s user %s password '%s' %s %s %s",
			$$user{server}, $$user{port}, $$user{protocol}, 
			$plugin, $$user{user}, $$user{password}, $smtpname, $folder, $keep);

		print FILE "$confline\n";
	}
	close FILE;

}

sub readConfig {
	if (!-f $options{c}) {return};
	open (FILE, $options{c}) or die "Can't open $options{c}: $!";
	my @lines = <FILE>;
	close FILE;

	my ($server, $port, $protocol, $plugin, $user, $password, $folder, $keep, $smtpname);
	foreach (@lines) {
		my @fields = split;
		for (my $i = 0; $i <= $#fields; $i++) {
			if ($fields[$i] eq "poll") {
				$i++;
				$server = $fields[$i];
				next;
			}
			if ($fields[$i] eq "port") {
				$i++;
				$port = $fields[$i];
				next;
			}
			if ($fields[$i] eq "protocol") {
				$i++;
				$protocol = $fields[$i];
				next;
			}
			if ($fields[$i] eq "user") {
				$i++;
				$user = $fields[$i];
				next;
			}
			if ($fields[$i] eq "smtpname") {
				$i++;
				$smtpname = $fields[$i];
				next;
			}
			if ($fields[$i] eq "keep") {
				$keep = 1;
				next;
			}
			if ($fields[$i] eq "plugin") {
				$i++;
				$plugin = $fields[$i];
				while ($plugin !~ /.*"$/) {
					$i++;
					$plugin .= " $fields[$i]";
				}
				$plugin =~ s/^"//;
				$plugin =~ s/"$//;
				next;
			}
			if ($fields[$i] eq "password") {
				$i++;
				$password = $fields[$i];
				while ($password !~ /.*'$/) {
					$i++;
					$password .= " $fields[$i]";
				}
				$password =~ s/^'//;
				$password =~ s/'$//;
				next;
			}
			if ($fields[$i] eq "folder") {
				$i++;
				$folder = $fields[$i];
				while ($folder !~ /.*"$/) {
					$i++;
					$folder .= " $fields[$i]";
				}
				$folder =~ s/^"//;
				$folder =~ s/"$//;
				next;
			}
		}

		my %uhash = ();
		$uhash{user} = $user;
		$uhash{server} = $server;
		$uhash{port} = $port;
		$uhash{protocol} = $protocol;
		$uhash{plugin} = $plugin;
		$uhash{password} = $password;
		$uhash{folder} = $folder;
		$uhash{keep} = $keep;
		$uhash{localuser} = $smtpname;
		push (@cflines, \%uhash);

	}
}

sub usage {
	my $msg = shift;
	print STDERR<<EOF;
$msg

Usage: $0 [-v] [-h] -c <config file> -a [options]
	-a add user
		-H <host> in host:port format
		-u <remote user>
		-p <remote user password>
		-l <local username for delivery>
		-s enable ssl
		-k keep messages on server
		-f <folder> (IMAP only)
		-P <POP|IMAP> protocol

	-h this help message
	-v verbose
	-c config file name 
EOF
	exit 1;
}
