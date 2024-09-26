#!/usr/bin/perl

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

use strict;
use lib "/opt/zextras/common/lib/perl5";
use Zimbra::Util::Common;
use File::Grep qw (fgrep);
use File::Path;
use Net::LDAP;
use Net::LDAP::LDIF;
use Net::LDAP::Entry;
use Crypt::SaltedHash;
use MIME::Base64;

my $source_config_dir = "/opt/zextras/common/etc/openldap";
my $config_dir = "/opt/zextras/conf";
my $ldap_config_dir="/opt/zextras/data/ldap/config/cn\=config";

my $zimbra_user=getLocalConfig("zimbra_user");
my $zimbra_ldap_userdn = getLocalConfig("zimbra_ldap_userdn");
my $zimbra_ldap_password = getLocalConfig("zimbra_ldap_password");
my $ldap_root_password = getLocalConfig("ldap_root_password");
my $ldap_master_url = getLocalConfig("ldap_master_url");
my $ldap_is_master = getLocalConfig("ldap_is_master");
my $ldap_starttls_supported = getLocalConfig("ldap_starttls_supported");
my $zimbra_tmp_directory = getLocalConfig("zimbra_tmp_directory");

if (lc($ldap_is_master) ne "true" ) {
  exit 0;
}

if (!-d $zimbra_tmp_directory) {
  File::Path::mkpath("$zimbra_tmp_directory");
}

my $rc=qx(/opt/zextras/bin/ldap start);

my @masters=split(/ /, $ldap_master_url);
my $master_ref=\@masters;
my $ldap = Net::LDAP->new($master_ref)  or  die "$@";

# startTLS Operation
my $mesg;
if ($ldap_master_url !~ /^ldaps/i) {
  if ($ldap_starttls_supported) {
    $mesg = $ldap->start_tls(
         verify => 'none',
         capath => "/opt/zextras/conf/ca",
         ) or die "start_tls: $@";
    $mesg->code && die "TLS: " . $mesg->error . "\n";
  }
}

$mesg = $ldap->bind("cn=config", password=>"$ldap_root_password");

my $infile = "$source_config_dir/zimbra/carbonio.ldif";
my $ldifin = Net::LDAP::LDIF->new("$infile", "r", onerror => 'undef' );
while ( not $ldifin->eof() ) {
    my $entry = $ldifin->read_entry();
    if ( $ldifin->error() ) {
      print "Error msg: ", $ldifin->error ( ), "\n";
      print "Error lines:\n", $ldifin->error_lines ( ), "\n";
    } elsif ( $entry )  {
      $entry->changetype("add");
      $entry->update($ldap);
    }
}

$infile = "$source_config_dir/zimbra/zimbra_globalconfig.ldif";
$ldifin = Net::LDAP::LDIF->new("$infile", "r", onerror => 'undef' );
while ( not $ldifin->eof() ) {
    my $entry = $ldifin->read_entry();
    if ( $ldifin->error() ) {
      print "Error msg: ", $ldifin->error ( ), "\n";
      print "Error lines:\n", $ldifin->error_lines ( ), "\n";
    } elsif ( $entry ) {
      $entry->changetype("add");
      $entry->update($ldap);
    }
}

$infile = "$source_config_dir/zimbra/zimbra_defaultcos.ldif";
$ldifin = Net::LDAP::LDIF->new("$infile", "r", onerror => 'undef' );
while ( not $ldifin->eof() ) {
    my $entry = $ldifin->read_entry();
    if ( $ldifin->error() ) {
      print "Error msg: ", $ldifin->error ( ), "\n";
      print "Error lines:\n", $ldifin->error_lines ( ), "\n";
    } elsif ( $entry ) {
      $entry->changetype("add");
      $entry->update($ldap);
    }
}

$infile = "$source_config_dir/zimbra/zimbra_defaultexternalcos.ldif";
$ldifin = Net::LDAP::LDIF->new("$infile", "r", onerror => 'undef' );
while ( not $ldifin->eof() ) {
    my $entry = $ldifin->read_entry();
    if ( $ldifin->error() ) {
      print "Error msg: ", $ldifin->error ( ), "\n";
      print "Error lines:\n", $ldifin->error_lines ( ), "\n";
    } elsif ( $entry ) {
      $entry->changetype("add");
      $entry->update($ldap);
    }
}

if (-f "/opt/zextras/conf/ldap/mimehandlers.ldif") {
  $infile = "/opt/zextras/conf/ldap/mimehandlers.ldif";
} else {
  $infile = "$source_config_dir/zimbra/mimehandlers.ldif";
}
$ldifin = Net::LDAP::LDIF->new("$infile", "r", onerror => 'undef' );
while ( not $ldifin->eof() ) {
    my $entry = $ldifin->read_entry();
    if ( $ldifin->error() ) {
      print "Error msg: ", $ldifin->error ( ), "\n";
      print "Error lines:\n", $ldifin->error_lines ( ), "\n";
    } elsif ( $entry ) {
      $entry->changetype("add");
      $entry->update($ldap);
    }
}

if ( -d "/opt/zextras/lib/conf/" ) {
    opendir(DIR, "/opt/zextras/lib/conf") || die "can't opendir /opt/zextras/lib/conf: $!";
    while (my $file = readdir(DIR)) {
       next unless (-f "/opt/zextras/lib/conf/$file");
       next unless ( $file =~ m/ldif$/);
       $infile = "/opt/zextras/lib/conf/$file";
       $ldifin = Net::LDAP::LDIF->new("$infile", "r", onerror => 'undef' );
       while ( not $ldifin->eof() ) {
            my $entry = $ldifin->read_entry();
            if ( $ldifin->error() ) {
              print "Error msg: ", $ldifin->error ( ), "\n";
              print "Error lines:\n", $ldifin->error_lines ( ), "\n";
            } elsif ( $entry ) {
              $entry->changetype("modify");
              foreach my $attr ($entry->attributes()) {
                my $ref = $entry->get_value ( $attr, asref => 1 );
                #print "Processing $attr => @$ref\n";
                $entry->replace($attr => [@$ref]);
              }
              my $msg = $entry->update($ldap);
              if ($msg->code()) {
                print "Error msg: ", $entry->dn(), " ", $msg->error(), "\n";
              }
            }
       }
    }
    closedir DIR;
}

$ldap->unbind;

exit 0;

sub getLocalConfig {
  my $key = shift;

  return $main::loaded{lc}{$key}
    if (exists $main::loaded{lc}{$key});

  my $val = qx(/opt/zextras/bin/zmlocalconfig -x -s -m nokey ${key} 2> /dev/null);
  chomp $val;
  $main::loaded{lc}{$key} = $val;
  return $val;
}

