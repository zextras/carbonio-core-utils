#!/usr/bin/perl

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

use strict;
use lib '/opt/zextras/common/lib/perl5';
use Net::LDAP;
use Net::LDAP::Util qw ( ldap_error_name );
use XML::Simple;
use Getopt::Long qw(:config no_ignore_case);

if ( !-x "/opt/zextras/common/bin/cbpolicyd" ) {
    print
"ERROR: cluebringer policy daemon does not appear to be installed - exiting\n";
    exit(1);
}

my $id = getpwuid($<);
chomp $id;
if ( $id ne "zextras" ) {
    print STDERR "Error: must be run as zextras user\n";
    exit(1);
}

if ( !@ARGV ) {
    print STDERR "Error: Must supply an argument.\n";
    exit(1);
}

my $localxml              = XMLin("/opt/zextras/conf/localconfig.xml");
my $ldap_url              = $localxml->{key}->{ldap_url}->{value};
my $zimbra_admin_dn       = $localxml->{key}->{zimbra_ldap_userdn}->{value};
my $zimbra_admin_password = $localxml->{key}->{zimbra_ldap_password}->{value};
chomp($zimbra_admin_password);
my $ldap_starttls_supported =
  $localxml->{key}->{ldap_starttls_supported}->{value};
my $zimbra_require_interprocess_security =
  $localxml->{key}->{zimbra_require_interprocess_security}->{value};

my $cbpadmin = "/opt/zextras/common/bin/cbpadmin";

my $mesg;
my @servers    = split( / /, $ldap_url );
my $server_ref = \@servers;

my $server_base = "cn=servers,cn=zimbra";
my $hostname    = qx(/opt/zextras/bin/zmhostname);

my $ldap = Net::LDAP->new($server_ref) or die "$@";

if ( $ldap_url !~ /^ldaps/i ) {
    if ($ldap_starttls_supported) {
        $mesg = $ldap->start_tls(
            verify => 'none',
            capath => "/opt/zextras/conf/ca",
        ) or die "start_tls: $@";
        $mesg->code && die "Could not execute StartTLS\n";
    }
}
if ( !defined($ldap) ) {
    die "Server down\n";
}
$mesg = $ldap->bind( $zimbra_admin_dn, password => $zimbra_admin_password );
$mesg->code && die "Bind: " . $mesg->error . "\n";

if ( -f '/opt/zextras/conf/cbpolicyd.conf' ) {
    $mesg = $ldap->search(
        base   => "cn=$hostname,$server_base",
        filter => "(zimbraServiceEnabled=cbpolicyd)",
        scope  => "base",
    );

    my $size = $mesg->count;
    if ( $size == 0 ) {
        print STDERR "cluebringer not enabled.\n";
        exit(1);
    }
    system( "/opt/zextras/common/bin/cbpadmin",
        "--config=/opt/zextras/conf/cbpolicyd.conf", @ARGV );
    exit($?);
}
else {
    print STDERR "cluebringer not enabled.\n";
    exit(1);
}
