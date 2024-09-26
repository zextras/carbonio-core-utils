#!/usr/bin/perl

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

use strict;

BEGIN {
    eval { require Mail::Mailer } || exit 0;
}

use Getopt::Long;
use IPC::Open3;
use FileHandle;
my ( $sendmail, $mailto, $verbose, $days, $debug, $help );
unless ( GetOptions( "verbose" => \$verbose, "days:s" => \$days, "mailto:s" => \$mailto, "emailreport" => \$sendmail, "debug" => \$debug, "help" => \$help ) ) { usage(); }

usage() if $help;

my $report = [];
my $cmd    = "/opt/zextras/bin/zmcertmgr checkcrtexpiration -days $days";
unless ( open( CERTMGR, "$cmd|" ) ) {
    logError("Unabled to execute zmcertmgr: $!");
    exit -1;
}
my @text = <CERTMGR>;
foreach (@text) { addToReport($_); }
close(CERTMGR);

sendEmailReport($report) if ( $sendmail && $? != 0 );
print @$report           if $verbose;
exit 0;

# Functions

sub getLocalConfig {
    my $key = shift;
    if ( defined( $ENV{zmsetvars} ) ) {
        return $ENV{$key};
    }
    open CONF, "/opt/zextras/bin/zmlocalconfig -q -m shell |" or die "Can't open local config: $!";
    my @conf = <CONF>;
    close CONF;

    chomp @conf;

    foreach (@conf) {
        my ( $key, $val ) = split '=', $_, 2;
        $val =~ s/;$//;
        $val =~ s/'$//;
        $val =~ s/^'//;
        $ENV{$key} = $val;
    }
    chomp($key);
    $ENV{zmsetvars} = 'true';
    return $ENV{$key};
}

sub sendEmailReport {
    my $msg                    = shift;
    my $subject                = "Carbonio: SSL Certificates approaching expiration!";
    my $from_address           = getLocalConfig("smtp_source");
    my $to_address             = ( $mailto ? $mailto : getLocalConfig("smtp_destination") );
    my $smtphost               = getLdapConfigValue("zimbraSmtpHostname") || "localhost";
    my $smtpport               = getLdapConfigValue("zimbraSmtpPort")     || 25;
    my $zimbra_server_hostname = getLocalConfig("zimbra_server_hostname");
    push( @$msg, "\n\nThe Administration Console and CLI Certificate Tools guide provides\n" );
    push( @$msg, "instructions on how to replace you self-signed or commercial certificate.\n" );
    push( @$msg, "http://wiki.zimbra.com/index.php?title=Administration_Console_and_CLI_Certificate_Tools\n" );
    push( @$msg, "\n\nSSL Certificate expiration checked with $0 on $zimbra_server_hostname.\n" );

    print "Sending report to $to_address via $smtphost\n" if $debug;
    eval {
        my $mailer = Mail::Mailer->new( "smtp", Server => $smtphost, Port => $smtpport );
        $mailer->open(
            {
                From    => $from_address,
                To      => $to_address,
                Subject => $subject,
            }
        ) or warn "ERROR: Can't open: $!\n";
        print $mailer $msg;
        $mailer->close();
    };
    if ($@) {
        logError("Failed to email report: $@\n");
    }
    else {
        print "Email report sent to $to_address\n" if $debug;
    }
}

sub getLdapConfigValue {
    my $attrib = shift;
    my ( $val, $err );
    $val = getLdapServerConfigValue($attrib);
    $val = getLdapGlobalConfigValue($attrib) if ( $val eq "" );
    logError("Failed to lookup $attrib\n") if ( $val eq "" );
    return $val;
}

sub getLdapServerConfigValue {
    my $attrib = shift;
    my ( $val, $err );
    my ( $rfh, $wfh, $efh, $cmd, $rc );
    my $server = getLocalConfig("zimbra_server_hostname");
    $rfh = new FileHandle;
    $wfh = new FileHandle;
    $efh = new FileHandle;
    $cmd = "/opt/zextras/bin/zmprov -l gs $server $attrib";
    my $pid = open3( $wfh, $rfh, $efh, $cmd );

    unless ( defined($pid) ) {
        return undef;
    }
    close $wfh;
    my @d = <$rfh>;
    chomp( $val = ( split( /\s+/, $d[-2] ) )[-1] );
    chomp( $err = join "", <$efh> );
    waitpid( $pid, 0 );
    if ( $? == -1 ) {

        # failed to execute
        return undef;
    }
    elsif ( $? & 127 ) {

        # died with signal
        return undef;
    }
    else {
        $rc = $? >> 8;
        return undef if ( $rc != 0 );
    }
    return $val;
}

sub getLdapGlobalConfigValue {
    my $attrib = shift;
    my ( $val, $err );
    my ( $rfh, $wfh, $efh, $cmd, $rc );
    $rfh = new FileHandle;
    $wfh = new FileHandle;
    $efh = new FileHandle;
    $cmd = "/opt/zextras/bin/zmprov -l gcf $attrib";
    my $pid = open3( $wfh, $rfh, $efh, $cmd );

    unless ( defined($pid) ) {
        return undef;
    }
    close $wfh;
    chomp( $val = ( split( /\s+/, <$rfh> ) )[-1] );
    chomp( $err = join "", <$efh> );
    waitpid( $pid, 0 );
    if ( $? == -1 ) {

        # failed to execute
        return undef;
    }
    elsif ( $? & 127 ) {

        # died with signal
        return undef;
    }
    else {
        $rc = $? >> 8;
        return undef if ( $rc != 0 );
    }

    return $val;
}

sub addToReport {
    my ($line) = @_;
    push( @$report, $line );
}

sub logError {
    my $msg = shift;
    print STDERR $msg;
    return;
}

sub usage {
    print STDERR "Usage: $0 [-h] [-v] [-d] [-m]\n";
    print STDERR "-days N  Certificates must be expiring within N days before sending warning.\n";
    print STDERR "-help    This usage page.\n";
    print STDERR "-verbose Verbose output.\n";
    print STDERR "-mailto  SMTP Address to send report.\n";
    print STDERR "-email   Mail output to admin account \n";
}
