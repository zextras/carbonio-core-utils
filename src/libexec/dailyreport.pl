#!/usr/bin/perl

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2023 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

=head1 NAME

zmdailyreport - report on email usage

=head1 SYNOPSIS

  zmdailyreport [options]

  Options:
    --mail                 Send report via email, default is stdout
    --help                 This help message
    --user                 User to deliver report to, default is localconfig smtp_destination

=cut
use warnings;
use strict;
use Pod::Usage qw(pod2usage);
use lib "/opt/zextras/common/lib/perl5";
use Zextras::Util::Common;
use Zextras::Mon::Logger;
use Getopt::Long qw(GetOptions);
use Mail::Mailer ();
use POSIX qw(strftime setlocale LC_TIME);
use Time::Local qw(timelocal);

my ( %Opt, $Debug );

GetOptions( \%Opt, "mailreport", "debug", "user=s", "help" )
  or pod2usage( -exitval => 2 );
  
pod2usage( -exitval => 1, -verbose => 0 ) if ( $Opt{help} );

$Debug = $Opt{debug};

setlocale(LC_TIME, "C");
my $stdout;
open($stdout, ">&STDOUT") || die $!;
pipe(PFIN, PFOUT);
pipe(MIN, MOUT);
my $fhin = fileno(PFIN);
close(STDIN);
open(STDIN, "<&=$fhin") || die $!;


if (fork()) {
	close(MOUT);
	my $todayShort = strftime("%b %e ", localtime);
	my $todayLong = strftime("%Y-%m-%d", localtime);
	my $datestring = strftime("%F", localtime);
	my $ymd = strftime("%Y%m%d", localtime);
	
	my $old_log;
	if (-f "/var/log/carbonio.log.1.gz") {
		$old_log = "gzip -dc /var/log/carbonio.log.1.gz |";
	} elsif (-f "/var/log/carbonio.log-$ymd.gz") {
		$old_log = "gzip -dc /var/log/carbonio.log-$ymd.gz |";
	} elsif (-f "/var/log/carbonio.log.1.bz2") {
		$old_log = "bzip2 -dc /var/log/carbonio.log.1.bz2 |";
	} elsif (-f "/var/log/carbonio.log-$ymd.bz2") {
		$old_log = "bzip2 -dc /var/log/carbonio.log-$ymd.bz2 |";
	}
	if (defined($old_log)) {

		if (open(LOG, $old_log)) {
	    	
            while (<LOG>) {
		        my $line = $_;
		        if (($line =~ /$todayShort/o) or ($line =~ /$todayLong/o)) {
   		             print PFOUT $line;
	            } 
	        }
		    close(LOG);
	    }
		
	}
	open(LOG, "</var/log/carbonio.log") || die $!;
	while (<LOG>) {
		my $line = $_;
		if (($line =~ /$todayShort/o) or ($line =~ /$todayLong/o)) {
   		     print PFOUT $line;
	    } 
	}
	close(LOG);
	close(PFOUT);
	# exit 1;
	my $server = getLocalConfig("zimbra_server_hostname");
	my @Report = ("Report created on $server\n");
	while (<MIN>) {
		push(@Report, $_);
	}
	close (MIN);
	
	if ($Opt{mailreport}) {
		sendEmailReport(day => $datestring, data => \@Report);
	} else {
		print @Report;
	}
} else {
	close(PFOUT);
	close(MIN);
	open(STDOUT, ">&MOUT") || die $!;
	my $user_limit = getLocalConfig('zimbra_mtareport_max_users') || 50;
	my $host_limit = getLocalConfig('zimbra_mtareport_max_hosts') || 50;
	$user_limit = 50 if $user_limit !~ /^\d+/;
	$host_limit = 50 if $host_limit !~ /^\d+/;
    @ARGV = ('-u', $user_limit, '-h', $host_limit);
    do '/opt/zextras/common/bin/pflogsumm';
    close(STDOUT);
}

{    # avoid making $LocalConfig global
    my $LocalConfig;

    sub getLocalConfig {
        my $key = shift;
        $LocalConfig = loadLocalConfig() unless ($LocalConfig);
        return $LocalConfig->{$key};
    }
}

sub loadLocalConfig {
    my %conf;

    open( CONF, "/opt/zextras/bin/zmlocalconfig -s -q -m shell |" )
      or die("Open local config failed: $!\n");

    while (<CONF>) {
        chomp;
        my ( $key, $val ) = split( /=/, $_, 2 );
        $val =~ s/';$//;
        $val =~ s/^'//;
        $conf{$key} = $val;
    }
    die("No data returned from local config") unless ( keys %conf );
    return \%conf;
}

sub getLdapConfigValue {
    my $attrib = shift;

    return (undef) unless ($attrib);

    my $val = getLdapServerConfigValue($attrib);
    print "Server value for $attrib: $val\n" if $Debug;
    if ($val eq "") {
      $val = getLdapGlobalConfigValue($attrib);
      print "Global value for $attrib: $val\n" if $Debug;
    }
    return $val;
}

sub getLdapServerConfigValue {
    my $attrib = shift;

    return (undef) unless ($attrib);
    my $server = getLocalConfig("zimbra_server_hostname");
    # could consider redirecting STDERR to /dev/null
    open( CONF, "/opt/zextras/bin/zmprov -l gs $server '$attrib' |" )
      or die("Open global config failed: $!");

    my ( $key, $val );
    while (<CONF>) {
        chomp;
        next if (/^#/);
        ( $key, $val ) = split( /:\s*/, $_, 2 );
        # for now just assume a single value/attribute is requested
        last if ($val);
    }
    return $val;
}

sub getLdapGlobalConfigValue {
    my $attrib = shift;

    return (undef) unless ($attrib);

    # could consider redirecting STDERR to /dev/null
    open( CONF, "/opt/zextras/bin/zmprov -l gcf '$attrib' |" )
      or die("Open global config failed: $!");

    my ( $key, $val );
    while (<CONF>) {
        chomp;
        ( $key, $val ) = split( /:\s*/, $_, 2 );
        # for now just assume a single value/attribute is requested
        last if ($val);
    }
    return $val;
}

sub sendEmailReport {
    my %arg = @_;

    my $data = $arg{data};    # @Report data for message body

    my $subject      = "Daily mail report for $arg{day}";
    my $from_address = getLocalConfig("smtp_source");
    my $to_address;
    if ($Opt{user}) {
      $to_address = $Opt{user};
    } else {
      $to_address   = getLocalConfig("smtp_destination");
    }
    my $smtphost     = getLdapConfigValue("zimbraSmtpHostname") || "localhost";
    my $smtpport     = getLdapConfigValue("zimbraSmtpPort") || 25;

    warn("DEBUG: Sending daily report to $to_address via $smtphost\n")
      if ($Debug);

    eval {
	$ENV{MAILADDRESS} = $from_address;
        my $mailer = Mail::Mailer->new( "smtp", Server => $smtphost, Port => $smtpport );
        $mailer->open(
            {
                From    => $from_address,
                To      => $to_address,
                Subject => $subject,
            }
        );
        print $mailer @$data;
        $mailer->close();
    };
    if ($@) {
        logError("Failed to email report using SMTP via '$smtphost': $@\n");
    }
    else {
        warn("DEBUG: Email report sent to $to_address\n") if ($Debug);
    }
}

sub logError {
  my $msg = shift;
  print STDERR $msg;
  return;
}

