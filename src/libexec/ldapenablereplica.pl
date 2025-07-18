#!/usr/bin/perl

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

use strict;
use lib '/opt/zextras/common/lib/perl5';
use Net::LDAP;
use XML::Simple;
use Getopt::Long;
use File::Copy qw/ cp /;
use File::Path;
use Zextras::Util::Systemd;

my $id = getpwuid($<);
chomp $id;
if ( $id ne "root" ) {
    print STDERR "Error: must be run as root user\n";
    exit(1);
}

if ( !-d "/opt/zextras/common/etc/openldap/schema" ) {
    print "ERROR: openldap does not appear to be installed - exiting\n";
    exit(1);
}

my ($help);

my $opts_good = GetOptions( 'h|help' => \$help, );

if ( !$opts_good ) {
    print STDERR "\n";
    usage();
}
if ($help) {
    usage(0);
}

my $localxml = XMLin("/opt/zextras/conf/localconfig.xml");

my $ldap_root_password = $localxml->{key}->{ldap_root_password}->{value};
chomp($ldap_root_password);
my $ldap_replication_password =
  $localxml->{key}->{ldap_replication_password}->{value};
my $ldap_starttls_supported =
  $localxml->{key}->{ldap_starttls_supported}->{value};
my $zimbra_require_interprocess_security =
  $localxml->{key}->{zimbra_require_interprocess_security}->{value};
my $zimbra_server_hostname =
  $localxml->{key}->{zimbra_server_hostname}->{value};
my $ldap_master_url      = $localxml->{key}->{ldap_master_url}->{value};
my $ldap_port            = $localxml->{key}->{ldap_port}->{value};
my $zimbra_ldap_password = $localxml->{key}->{zimbra_ldap_password}->{value};
my $zimbra_ldap_userdn   = $localxml->{key}->{zimbra_ldap_userdn}->{value};

my $zmprov = "/opt/zextras/bin/zmprov";

my ( $lmr, $junk ) = split ' ', $ldap_master_url, 2;
my $ldap_master_host = $lmr;
$ldap_master_host =~ s/ldaps*:\/\///;
$ldap_master_host =~ s/:.*//;

my $proto;

if ( $ldap_port == 636 ) {
    $proto = "ldaps";
}
else {
    $proto = "ldap";
}

sub verifyLdap {

    # Ensure we can bind to the master server before doing anything else

    print "Verifying ldap on $lmr...\n";
    my $ldap = Net::LDAP->new("$lmr") or die "$@";

    # startTLS Operation
    my $mesg;
    if ( $lmr !~ /^ldaps/i ) {
        if ($ldap_starttls_supported) {
            $mesg = $ldap->start_tls(
                verify => 'none',
                capath => "/opt/zextras/conf/ca",
            ) or die "start_tls: $@";
            $mesg->code && die "TLS: " . $mesg->error . "\n";
        }
    }
    $mesg =
      $ldap->bind( "$zimbra_ldap_userdn", password => "$zimbra_ldap_password" );
    $mesg->code
      && die "ERROR: Unable to verify ldap connection on $lmr - exiting\n";
    $ldap->unbind;
    print "succeeded\n";
}

sub verifyAccesslog {

    # Verify that accesslog DB doesn't already exist.

    my $ldap = Net::LDAP->new('ldapi://%2frun%2fcarbonio%2frun%2fldapi/')
      or die "$@";
    my $mesg;
    $mesg = $ldap->bind( "cn=config", password => "$ldap_root_password" );

    my $base = "cn=accesslog";
    $mesg = $ldap->search(
        base   => "$base",
        filter => "(objectClass=*)",
        scope  => "base",
        attrs  => ['1.1'],
    );
    my $size = $mesg->count;
    $ldap->unbind;

    if ( $size > 0 ) {
        print "Accesslog is already enabled. Exiting...\n";
        exit(1);
    }
}

sub verifySyncProv {
    my $ldap = Net::LDAP->new('ldapi://%2frun%2fcarbonio%2frun%2fldapi/')
      or die "$@";
    my $mesg;

    $mesg = $ldap->bind( "cn=config", password => "$ldap_root_password" );
    my $base = "olcDatabase={2}mdb,cn=config";

    $mesg = $ldap->search(
        base   => "$base",
        filter => "(olcOverlay=syncprov)",
        scope  => "sub",
        attrs  => ['1.1'],
    );
    my $size = $mesg->count;
    $ldap->unbind;
    if ( $size > 0 ) {
        print "Error: Syncprov already enabled. Exiting...\n";
        exit 1;
    }
}

sub enableSyncProv {
    print "Enabling sync provider on master...\n";
    File::Path::mkpath("/opt/zextras/data/ldap/accesslog/db");
    system("chown -R zextras:zextras /opt/zextras/data/ldap/accesslog");

    my $ldap = Net::LDAP->new('ldapi://%2frun%2fcarbonio%2frun%2fldapi/')
      or die "$@";
    my $mesg = $ldap->bind( "cn=config", password => "$ldap_root_password" );
    $mesg->code && die "Bind: " . $mesg->error . "\n";

    my $bdn = "olcDatabase={2}mdb,cn=config";
    $mesg = $ldap->add(
        $bdn,
        attr => [
            objectClass    => [ "olcDatabaseConfig", "olcMdbConfig" ],
            olcDatabase    => "{2}mdb",
            olcDbDirectory => "/opt/zextras/data/ldap/accesslog/db",
            olcSuffix      => "cn=accesslog",
            olcAccess      =>
'{0}to dn.subtree="cn=accesslog"  by dn.exact="uid=zimbra,cn=admins,cn=zimbra" read  by dn.exact="cn=config" read  by dn.exact="uid=zmreplica,cn=admins,cn=zimbra" read',
            olcLastMod       => "TRUE",
            olcMaxDerefDepth => "15",
            olcReadOnly      => "FALSE",
            olcRootDN        => "cn=config",
            olcSizeLimit     => "unlimited",
            olcTimeLimit     => "unlimited",
            olcMonitoring    => "TRUE",
            olcDbCheckpoint  => "0 0",
            olcDbEnvFlags    => [ "writemap", "nometasync" ],
            olcDbNoSync      => "TRUE",
            olcDbIndex       => [
                "entryCSN eq",
                "objectClass eq",
                "reqEnd eq",
                "reqResult eq",
                "reqStart eq"
            ],
            olcDbMode        => "0600",
            olcDbSearchStack => "16",
            olcDbMaxsize     => "85899345920",
        ],
    );
    $mesg->code && die "Add Failed: " . $mesg->error . "\n";
    $mesg = $ldap->add(
        'olcOverlay=syncprov,olcDatabase={2}mdb,cn=config',
        attr => [
            objectClass     => [ "olcOverlayConfig", "olcSyncProvConfig" ],
            olcOverlay      => "syncprov",
            olcSpNoPresent  => "TRUE",
            olcSpReloadHint => "TRUE",
        ],
    );
    $mesg->code && die "Add Failed: " . $mesg->error . "\n";
    $mesg => $ldap->add(
        'olcOverlay={0}syncprov,olcDatabase={3}mdb,cn=config',
        attr => [
            objectClass     => [ 'olcOverlayConfig', 'olcSyncProvConfig' ],
            olcOverlay      => '{0}syncprov',
            olcSpCheckpoint => '20 10',
            olcSpSessionlog => '10000000',
        ],
    );
    $mesg->code && die "Add Failed: " . $mesg->error . "\n";
    $mesg => $ldap->add(
        'olcOverlay={1}accesslog,olcDatabase={3}mdb,cn=config',
        attr => [
            objectClass         => [ 'olcOverlayConfig', 'olcAccessLogConfig' ],
            olcOverlay          => '{1}accesslog',
            olcAccessLogDB      => 'cn=accesslog',
            olcAccessLogOps     => 'writes',
            olcAccessLogSuccess => 'TRUE',
            olcAccessLogPurge   => '01+00:00  00+04:00',
        ],
    );
    $mesg->code && die "Add Failed: " . $mesg->error . "\n";
    $ldap->unbind;
    print "succeeded\n";
}

sub createLdapConfig {

    # Verify syncprov isn't already enabled on the db
    print "Enabling sync replication on replica...";

    my $ldaps = 0;
    if ( $lmr =~ /^ldaps/ ) {
        $ldaps = 1;
    }

    my $ldap = Net::LDAP->new('ldapi://%2frun%2fcarbonio%2frun%2fldapi/')
      or die "$@";
    my $mesg = $ldap->bind( "cn=config", password => "$ldap_root_password" );
    $mesg->code && die "Bind: " . $mesg->error . "\n";

    my $bdn = "olcDatabase={2}mdb,cn=config";
    if ($ldaps) {
        $mesg = $ldap->modify(
            $bdn,
            add => [
                olcSyncrepl =>
"rid=100 provider=$lmr bindmethod=simple timeout=0 network-timeout=0 binddn=uid=zmreplica,cn=admins,cn=zimbra credentials=$ldap_replication_password filter=\"(objectclass=*)\" searchbase=\"\" logfilter=\"(&(objectClass=auditWriteObject)(reqResult=0))\" logbase=cn=accesslog scope=sub schemachecking=off type=refreshAndPersist retry=\"60 +\" syncdata=accesslog tls_cacertdir=/opt/zextras/conf/ca keepalive=240:10:30",
                olcUpdateRef => "$lmr",
            ],
        );
    }
    elsif ( $ldap_starttls_supported && $zimbra_require_interprocess_security )
    {
        $mesg = $ldap->modify(
            $bdn,
            add => [
                olcSyncrepl =>
"rid=100 provider=$lmr bindmethod=simple timeout=0 network-timeout=0 binddn=uid=zmreplica,cn=admins,cn=zimbra credentials=$ldap_replication_password starttls=critical filter=\"(objectclass=*)\" searchbase=\"\" logfilter=\"(&(objectClass=auditWriteObject)(reqResult=0))\" logbase=cn=accesslog scope=sub schemachecking=off type=refreshAndPersist retry=\"60 +\" syncdata=accesslog tls_cacertdir=/opt/zextras/conf/ca keepalive=240:10:30",
                olcUpdateRef => "$lmr",
            ],
        );
    }
    else {
        $mesg = $ldap->modify(
            $bdn,
            add => [
                olcSyncrepl =>
"rid=100 provider=$lmr bindmethod=simple timeout=0 network-timeout=0 binddn=uid=zmreplica,cn=admins,cn=zimbra credentials=$ldap_replication_password filter=\"(objectclass=*)\" searchbase=\"\" logfilter=\"(&(objectClass=auditWriteObject)(reqResult=0))\" logbase=cn=accesslog scope=sub schemachecking=off type=refreshAndPersist retry=\"60 +\" syncdata=accesslog tls_cacertdir=/opt/zextras/conf/ca keepalive=240:10:30",
                olcUpdateRef => "$lmr",
            ],
        );
    }
    if ( $mesg->code ) {
        print "FAILED\n";
        print
"ERROR: Unable to add syncrepl configuration to $zimbra_server_hostname - exiting\n";
        print "ERROR: " . $mesg->error . "\n";
        $ldap->unbind;
        &resetLdapUrl;
        exit 1;
    }

    # ADD SYNCPROV overlay to DB
    $bdn  = "olcOverlay={0}syncprov,olcDatabase={2}mdb,cn=config";
    $mesg = $ldap->add(
        $bdn,
        attr => [
            objectClass => [ 'olcOverlayConfig', 'olcSyncProvConfig' ],
            olcOverlay  => "{0}syncprov",
        ],
    );
    $ldap->unbind;
    if ( $mesg->code ) {
        print "FAILED";
        print
"ERROR: Unable to add syncprov overlay to ${zimbra_server_hostname} - exiting\n";
        print "ERROR: " . $mesg->error . "\n";
        &resetLdapUrl;
        exit 1;
    }
    else {
        print "succeeded\n";
    }
}

sub enableLdapService {
    print "Enabling LDAP service on ${zimbra_server_hostname}...";

    open( ZMPROV,
"${zmprov} -m -l gs ${zimbra_server_hostname} zimbraServiceEnabled=ldap 2> /dev/null|"
    );
    my @CONFIG = <ZMPROV>;
    close(ZMPROV);
    my $found = 0;
    foreach my $line (@CONFIG) {
        if ( $line =~ /^zimbraServiceEnabled: ldap$/ ) {
            $found = 1;
        }
    }

    if ( !$found ) {
        system(
"/opt/zextras/bin/zmprov -m -l ms ${zimbra_server_hostname} +zimbraServiceEnabled ldap"
        );
    }

    print "succeeded\n";
}

sub updateLdapHost {
    print "Setting ldap_url on ${zimbra_server_hostname}...";
qx(su - zextras -c "/opt/zextras/bin/zmlocalconfig -f -e ldap_url='${proto}://${zimbra_server_hostname}:${ldap_port} ${lmr}'");
    print "done\n";
}

sub resetLdapUrl {
    print "Resetting ldap_url on ${lmr}...";
qx(su - zextras -c "/opt/zextras/bin/zmlocalconfig -f -e ldap_url='${lmr}'");
    print "done\n";
}

sub startLdap {
    print "Starting LDAP on ${zimbra_server_hostname}...";
    my $isRunning;

    # Check if service is already running
    if ( isSystemd() ) {
        $isRunning = isSystemdActiveUnit("carbonio-openldap.service");
    }
    else {
        my $rc = system("su - zextras -c '/opt/zextras/bin/ldap status'");
        $isRunning = ( $rc == 0 );    # Normalize: 1 = running, 0 = not running
    }

    # Start service if not running
    if ( !$isRunning ) {
        my $rc;
        if ( isSystemd() ) {
            $rc = system("systemctl start carbonio-openldap.service");
            sleep 5;
        }
        else {
            $rc = system("su - zextras -c '/opt/zextras/bin/ldap start'");
        }

        $rc >>= 8;    # Normalize return code for both cases

        if ( $rc != 0 ) {    # 0 = success for both
            print "Error: Unable to start ldap, exiting.\n";
            &resetLdapUrl;
            exit 1;
        }
    }
    print "done\n";
}

sub usage {
    my ($msg) = (@_);
    $msg && print STDERR "\nERROR: $msg\n";

    print STDERR <<USAGE;
  Usage: zmldapenablereplica

  Use zmldapenablereplica to set up this server as an ldap replica
  or to enable the replication database on the master

  zmldapenablereplica must have been run on the master prior to being
  run on any replicas.  It is only necessary to run zmldapenablereplica
  once on the master.

USAGE
    exit(1);
}

if ( lc($ldap_master_host) eq lc($zimbra_server_hostname) ) {
    &verifyAccesslog;
    &verifySyncProv;
    &enableSyncProv;
    exit 0;
}

&verifyLdap;
&updateLdapHost;
&startLdap;
&verifyAccesslog;
&verifySyncProv;
&createLdapConfig;
&enableLdapService;
