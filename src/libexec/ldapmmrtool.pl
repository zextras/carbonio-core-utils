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
my ($help,$masterURI,$rid,$tls,$replEntry,$entryNUM,$entryURI,$entryRID,$entryTLS,$query,$modify,$delete,$origRID,$found);
$rid=0;
$masterURI=0;
$tls=0;
$query=0;
$modify=0;
$delete=0;
$origRID=0;
$found=0;

my $opts_good = GetOptions(
        'h|help' => \$help,
    	'q|query' => \$query,
    	'd|delete' => \$delete,
    	'u|update' => \$modify,
    	'o|orig=i' => \$origRID,
        'm|master=s' => \$masterURI,
        'r|rid=i' => \$rid,
        't|tls=s' => \$tls,
);

if (!$opts_good) {
        print STDERR "\n";
        usage();
}
if ($help) {
        usage(0);
}
if (($modify || $delete) && !$origRID) {
  usage(0);
}

if (!$modify && !$delete && !$query) {
  usage(0);
}

if ($masterURI && $masterURI !~ /^ldaps?:\/\//) {
  usage(0);
}

if ($masterURI && $masterURI !~ /\/$/) {
  usage(0);
}

if ($tls && $tls ne "critical" && $tls ne "off") {
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

if(lc($ldap_is_master) ne "true") {
  usage(0);
}

if(lc($ldap_is_master) eq "true") {
  my $ldap = Net::LDAP->new('ldapi://%2frun%2fcarbonio%2frun%2fldapi/') or die "$@";
  my $mesg = $ldap->bind("cn=config", password=>"$ldap_root_password");
  $mesg->code && die "Bind: ". $mesg->error . "\n"; 

  my ($bdn,$size,$entry,$sid);
  if ($query) {
    $bdn="cn=config";
    $mesg = $ldap->search (
              base => "$bdn",
              scope => 'base',
              filter => "(olcServerID=*)",
              attrs => ['olcServerID']
    );
    $size = $mesg->count;
    if ($size > 0) {
      $entry=$mesg->entry(0);
      print "Master Server ID: " . $entry->get_value('olcServerID') . "\n";
    } else {
      $ldap->unbind;
      print "Error: No Server ID found.  This does not appear to be a multi-master server.\n";
      exit 0;
    }
  }
  $bdn="olcDatabase={3}mdb,cn=config";
  $mesg = $ldap->search(
            base => "$bdn",
            filter => "(olcSyncrepl=*)",
            attrs => ['olcSyncrepl']
  );
  $size = $mesg->count;
  my $count=0;
  if ($size > 0) {
    $entry=$mesg->entry(0);
    foreach ($entry->get_value('olcSyncRepl')) {
      $replEntry=$_;
      my $junk;
      my $tmpNum;
      ($tmpNum, $entryRID) = split (/rid=/, $_, 2);
      ($junk, $entryURI) = split (/provider=/, $_, 2);
      ($junk, $entryTLS) = split (/starttls=/, $_, 2);
      ($entryRID, $junk) = split (/ /, $entryRID, 2);
      ($entryURI, $junk) = split (/ /, $entryURI, 2);
      ($entryTLS, $junk) = split (/ /, $entryTLS, 2);
      if ($modify || $delete) {
        if ($origRID == $entryRID) {
          $found=1;
          $entryNUM=$tmpNum;
          if ($modify) {
            last;
          }
        }
      }
      if ($query) {
        print "Master replication agreement: " . ($count+1) . "\n";
        print "rid: $entryRID URI: $entryURI TLS: $entryTLS\n";
      }
      $count++;
    }
  } else {
    $ldap->unbind;
    print "Error: No sync replication entries found\n";
    exit 0;
  }
  if ($query) {
    $ldap->unbind;
    exit 0;
  }
  if ($found == 0) {
    print "RID $origRID not found, exiting.\n";
    exit(0);
  }

  my $err;
  if ($modify) {
    if ($tls) {
      if ($masterURI && $masterURI !~ /^ldaps/) {
        if ($tls eq "critical") {
          $tls="starttls=critical";
        }
      } else {
        if ($tls eq "critical" && $entryURI !~ /^ldaps/) {
          $tls="starttls=critical";
        }
      }
    } else {
      if ($masterURI && $masterURI !~ /^ldaps/) {
        if ($ldap_starttls_supported && $zimbra_require_interprocess_security) {
          $tls="starttls=critical";
        }
      }
    }
    if ($tls && $tls =~ /starttls/ && $replEntry !~ /starttls/) {
      $replEntry =~ s/filter=/$tls filter=/;
    } elsif ($tls && $tls !~ /starttls/ && $replEntry =~ /starttls/) {
      $replEntry =~ s/starttls=critical //;
    }
  
    if ($masterURI) {
      $replEntry =~ s/provider=$entryURI/provider=$masterURI/;
    }
  
    if ($rid) {
      $replEntry =~ s/rid=$entryRID/rid=$rid/;
    }
    $mesg = $ldap->modify(
      $bdn,
      delete=>{olcSyncrepl=>"$entryNUM"},
    );
    $mesg = $ldap->modify(
      $bdn,
      add=>{olcSyncrepl=>"$replEntry"},
    );
    $err=$mesg->code;
  } elsif ($delete) {
    if ($count == 1) {
      print "Error: It is illegal to delete the last remaining replication agreement.\n";
      print "You must define a new replication agreement prior to deleting the final one.\n";
      exit 0;
    }
    $mesg = $ldap->modify(
      $bdn,
      delete=>{olcSyncrepl=>"$entryNUM"},
    );
    $err=$mesg->code;
  } else {
    print "ERROR: Should be no way to reach this else block\n";
    $ldap->unbind;
    exit 1;
  }

  $ldap->unbind;
  exit($err);
}

sub usage {

        my ($msg) = (@_);

        $msg && print STDERR "\nERROR: $msg\n";
        print STDERR <<USAGE;
  zmldapmmrtool [-q] [-d] [-u] [-o RID] [-r RID] [-m masterURI] [-t critical|off]

  Where:
  -q: Query the current MMR configuration.  This option ignores -m, -r, and -t
  -d: Delete the configuration for the RID specified with -o
  -u: Update the configuration for the RID specified with -o
  -o: RID to select for modification or deletion
  -r: New RID to assign.  Must be unique. Example: 101
  -m: New master URI. Example: ldap://ldap3.example.com:389/
  -t: New startTLS setting for rid specified via -o.  Can be critical or off

USAGE
        exit (1);
}

