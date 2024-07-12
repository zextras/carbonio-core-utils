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

if ( ! -d "/opt/zextras/common/etc/openldap/schema" ) {
  print "ERROR: openldap does not appear to be installed - exiting\n";
  exit(1);
}

my $id = getpwuid($<);
chomp $id;
if ($id ne "zextras") {
    print STDERR "Error: must be run as zextras user\n";
    exit (1);
}
my ($help,$sid,$mmrURI,$rid);
$sid=0;
$rid=100;

my $opts_good = GetOptions(
        'h|help' => \$help,
        's|sid=i' => \$sid,
        'm|mmr=s' => \$mmrURI,
        'r|rid=i' => \$rid,
);

if (!$opts_good) {
        print STDERR "\n";
        usage();
}
if ($help) {
        usage(0);
}

if (!($mmrURI)) {
  usage(0);
}

if ($mmrURI !~ /^ldaps?:\/\//) {
  usage(0);
}

if ($mmrURI !~ /\/$/) {
  usage(0);
}

my $localxml = XMLin("/opt/zextras/conf/localconfig.xml");
my $ldap_root_password = $localxml->{key}->{ldap_root_password}->{value};
chomp($ldap_root_password);
my $ldap_is_master = $localxml->{key}->{ldap_is_master}->{value};
chomp($ldap_is_master);
my $ldap_replication_password = $localxml->{key}->{ldap_replication_password}->{value};
my $ldap_starttls_supported = $localxml->{key}->{ldap_starttls_supported}->{value};
my $zimbra_require_interprocess_security = $localxml->{key}->{zimbra_require_interprocess_security}->{value};

if(lc($ldap_is_master) eq "true") {
  my $ldap = Net::LDAP->new('ldapi://%2frun%2fcarbonio%2frun%2fldapi/') or die "$@";
  my $mesg = $ldap->bind("cn=config", password=>"$ldap_root_password");
  $mesg->code && die "Bind: ". $mesg->error . "\n"; 

# Check to see if olcServerID is already configured.  If not, add it.

  my $dn="cn=config";
  $mesg = $ldap ->search(
                    base=>"$dn",
                    filter=>"(&(objectClass=olcGlobal)(olcServerID=*))",
                    scope=>"sub",
                    attrs => ['olcServerID'],
                );
  my $size = $mesg->count;
  if ($size == 0) {
    if($sid <= 0) {
      print "Error: No Server ID exists on master and none provided.\n";
      print "       Provide valid Server ID value via the -s option.\n";
      exit(1);
    } else {
      $mesg = $ldap->modify(
        $dn,
        add=>{olcServerID =>$sid},
      );
    }
  } else {
    if ($sid > 0) {
      print "Error: Server ID provided when the Server ID is already configured.\n";
      exit(1);
    }
    my $bdn="olcDatabase={3}mdb,cn=config";
    $mesg = $ldap->search(
            base => "$bdn",
            filter => "(olcSyncrepl=*)",
            attrs => ['olcSyncrepl']
    );
    $size = $mesg->count;
    if ($size > 0) {
      my $entry=$mesg->entry(0);
      my ($junk, $entryRID);
      foreach ($entry->get_value('olcSyncRepl')) {
        ($junk, $entryRID) = split (/rid=/, $_, 2);
        ($entryRID, $junk) = split (/ /, $entryRID, 2);
        if ($rid == $entryRID) {
          print "Error: A replication agreement for rid $rid already exists.\n";
          exit(1);
        }
      }
    }
  }

  my $bdn="olcDatabase={2}mdb,cn=config";

#Check if master is already enabled for replication.  If so, steps are simpler.  If not, more to do.
  $mesg = $ldap->search(
                        base=> "cn=accesslog",
                        filter=>"(objectClass=*)",
                        scope => "base",
                        attrs => ['1.1'],
                 );
  $size = $mesg->count;
  if ($size == 0 ) {
    # Create accesslog db, add syncprov overlay, etc.
    File::Path::mkpath("/opt/zextras/data/ldap/accesslog/db");
    $mesg=$ldap->add(
      $bdn,
      attr => [
        objectClass=>["olcDatabaseConfig","olcMdbConfig"],
        olcDatabase=>"{2}mdb",
        olcDbDirectory=>"/opt/zextras/data/ldap/accesslog/db",
        olcSuffix=>"cn=accesslog",
        olcAccess=>'{0}to dn.subtree="cn=accesslog"  by dn.exact="uid=zimbra,cn=admins,cn=zimbra" read  by dn.exact="cn=config" read  by dn.exact="uid=zmreplica,cn=admins,cn=zimbra" read',
        olcLastMod=>"TRUE",
        olcMaxDerefDepth=>"15",
        olcReadOnly=>"FALSE",
        olcRootDN=>"cn=config",
        olcSizeLimit=>"unlimited",
        olcTimeLimit=>"unlimited",
        olcMonitoring=>"TRUE",
        olcDbCheckpoint=>"0 0",
        olcDbEnvFlags=>["writemap","nometasync"],
        olcDbNoSync=>"TRUE",
        olcDbIndex=>["entryCSN eq", "objectClass eq", "reqEnd eq", "reqResult eq", "reqStart eq"],
        olcDbMode=>"0600",
        olcDbSearchStack=>"16",
	olcDbMaxsize=>"85899345920",
      ],
    );
    $mesg=$ldap->add(
      'olcOverlay=syncprov,olcDatabase={2}mdb,cn=config',
      attr => [
        objectClass=>["olcOverlayConfig", "olcSyncProvConfig"],
        olcOverlay=>"syncprov",
        olcSpNoPresent=>"TRUE",
        olcSpReloadHint=>"TRUE",
      ],
    );
    $mesg=>$ldap->add(
      'olcOverlay={0}syncprov,olcDatabase={3}mdb,cn=config',
      attr => [
        objectClass=>['olcOverlayConfig','olcSyncProvConfig'],
        olcOverlay=>'{0}syncprov',
        olcSpCheckpoint=>'20 10',
        olcSpSessionlog=>'10000000',
      ],
    );
    $mesg=>$ldap->add(
      'olcOverlay={1}accesslog,olcDatabase={3}mdb,cn=config',
      attr => [
        objectClass=>['olcOverlayConfig','olcAccessLogConfig'],
        olcOverlay=>'{1}accesslog',
        olcAccessLogDB=>'cn=accesslog',
        olcAccessLogOps=>'writes',
        olcAccessLogSuccess=>'TRUE',
        olcAccessLogPurge=>'01+00:00  00+04:00',
      ],
    );
  }
  $bdn="olcDatabase={3}mdb,cn=config";
  if ($mmrURI =~ /^ldaps:/) {
    $mesg = $ldap->modify(
      $bdn,
      add=>{olcSyncrepl=>"rid=$rid provider=$mmrURI bindmethod=simple timeout=0 network-timeout=0 binddn=uid=zmreplica,cn=admins,cn=zimbra credentials=$ldap_replication_password filter=\"(objectclass=*)\" searchbase=\"\" logfilter=\"(&(objectClass=auditWriteObject)(reqResult=0))\" logbase=cn=accesslog scope=sub schemachecking=off type=refreshAndPersist retry=\"60 +\" syncdata=accesslog tls_cacertdir=/opt/zextras/conf/ca keepalive=240:10:30"},
    );
  } elsif ($ldap_starttls_supported && $zimbra_require_interprocess_security) {
    $mesg = $ldap->modify(
      $bdn,
      add=>{olcSyncrepl=>"rid=$rid provider=$mmrURI bindmethod=simple timeout=0 network-timeout=0 binddn=uid=zmreplica,cn=admins,cn=zimbra credentials=$ldap_replication_password starttls=critical filter=\"(objectclass=*)\" searchbase=\"\" logfilter=\"(&(objectClass=auditWriteObject)(reqResult=0))\" logbase=cn=accesslog scope=sub schemachecking=off type=refreshAndPersist retry=\"60 +\" syncdata=accesslog tls_cacertdir=/opt/zextras/conf/ca keepalive=240:10:30"},
    );
  } else {
    $mesg = $ldap->modify(
      $bdn,
      add=>{olcSyncrepl=>"rid=$rid provider=$mmrURI bindmethod=simple timeout=0 network-timeout=0 binddn=uid=zmreplica,cn=admins,cn=zimbra credentials=$ldap_replication_password filter=\"(objectclass=*)\" searchbase=\"\" logfilter=\"(&(objectClass=auditWriteObject)(reqResult=0))\" logbase=cn=accesslog scope=sub schemachecking=off type=refreshAndPersist retry=\"60 +\" syncdata=accesslog tls_cacertdir=/opt/zextras/conf/ca keepalive=240:10:30"},
    );
  }
  $mesg = $ldap ->search(
                    base=>"$bdn",
                    filter=>"(&(objectClass=olcMdbConfig)(olcMirrorMode:booleanMatch:=TRUE))",
                    scope=>"sub",
                    attrs => ['olcMirrorMode'],
                );
  $size = $mesg->count;
  if ($size == 0 ) {
    $mesg = $ldap->modify(
      $bdn,
      replace=>{olcMirrorMode=>"TRUE"},
    );
  }
} else {
  print "Not a master, please use zmldappromote-replica-mmr\n";
  exit(0);
}

sub usage {

        my ($msg) = (@_);

        $msg && print STDERR "\nERROR: $msg\n";
        print STDERR <<USAGE;
  zmldapenable-mmr [-r RID] [-s SID] -m MMRURI

  Where:
  RID is a unique Integer Replication ID for this replication instance.  It must be unique inside this server.  Example: 100 Default: 100
  SID is an unique Integer Server ID for THIS LDAP Master.  It CANNOT be in use by any other LDAP master.  Example: 2
  MMRURI is the LDAP URI for an alternate master.  Example: ldap://ldap-master2.example.com:389/

USAGE
        exit (1);
}

