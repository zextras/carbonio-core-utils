#!/usr/bin/perl

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

# Add entries to or update master LDAP server
#
# Exit values
#
# 0 - success
# 1 - ldap start failed
# 2 - ldapmodify failed

package ldapinit;

use strict;
use lib "/opt/zextras/common/lib/perl5";
use Zextras::Util::Common;
use Getopt::Std;
use Net::LDAP;
use Net::LDAP::LDIF;
use Net::LDAP::Entry;
use Crypt::SaltedHash;
use MIME::Base64;
use File::Grep qw (fgrep);

my $config_dir = "/opt/zextras/conf";
my $infile;
my $ldap_root_password;
my $ldifin;
my $ldifout;
my $outfile;
my $source_config_dir = "/opt/zextras/common/etc/openldap";

our %loaded = ();
our %saved  = ();

sub preLdapStart {
  my $ldap_config_dir = "/opt/zextras/data/ldap/config/cn\=config";
  my $ldap_password;
  my $ldap_userdn;
  my $server_hostname;
  my $tmp_directory = getLocalConfig("zimbra_tmp_directory");
  my $user          = getLocalConfig("zimbra_user");

  my ( $self, $ldap_root_pw, $ldap_admin_pw ) = @_;
  setLocalConfig( "ldap_root_password",   "$ldap_root_pw" );
  setLocalConfig( "zimbra_ldap_password", "$ldap_admin_pw" );
  setLocalConfig( "ldap_is_master",       "true" );

  $ldap_password      = getLocalConfig("zimbra_ldap_password");
  $ldap_root_password = getLocalConfig("ldap_root_password");
  $ldap_userdn        = getLocalConfig("zimbra_ldap_userdn");
  $server_hostname    = getLocalConfig("zimbra_server_hostname");

  # Get the SHA password.
  my $ctx = Crypt::SaltedHash->new( algorithm => 'SHA-512', salt_len => '8' );
  $ctx->add("$ldap_root_password");
  my $root_ssha_password = $ctx->generate;

  $ctx = Crypt::SaltedHash->new( algorithm => 'SHA-512', salt_len => '8' );
  $ctx->add("$ldap_password");
  my $ssha_password = $ctx->generate;

  # Update config database
  #
  $infile  = "$ldap_config_dir/olcDatabase\=\{0\}config.ldif";
  $outfile = "$tmp_directory/olcDatabase\=\{0\}config.ldif.$$";
  my $mime_root_passwd = MIME::Base64::encode( $root_ssha_password, "" );
  chomp($mime_root_passwd);
  open( IN,  "<$infile" );
  open( OUT, ">$outfile" );
  while (<IN>) {
    if ( $_ =~ /^olcRootPW/ ) {
      $_ =~ s|^olcRootPW.*|olcRootPW:: $mime_root_passwd|;
      print OUT $_;
    } else {
      print OUT $_;
    }
  }
  close IN;
  close OUT;
  if ( -s $outfile ) {
    my $rc = 0xffff & system("mv -f $outfile $infile");
    if ( $rc != 0 ) {
      print "Warning: failed to write $infile\n";
    }
    qx(chown $user:$user $infile);
    qx(chmod 600 $infile);
  } else {
    print "Warning: Failed to update root password.\n";
  }

  # Update carbonio.ldif
  $infile  = "$source_config_dir/zimbra/carbonio.ldif";
  $outfile = "$config_dir/carbonio.ldif";
  $ldifin  = Net::LDAP::LDIF->new( "$infile",  "r", onerror => 'undef' );
  $ldifout = Net::LDAP::LDIF->new( "$outfile", "w", onerror => 'undef' );
  while ( not $ldifin->eof() ) {
    my $entry = $ldifin->read_entry();
    if ( $ldifin->error() ) {
      print "Error msg: ",    $ldifin->error(),       "\n";
      print "Error lines:\n", $ldifin->error_lines(), "\n";
      return 1;
    } elsif ($entry) {
      if ( $entry->dn() eq "uid=zimbra,cn=admins,cn=zimbra" ) {
        $entry->replace( userPassword => "$ssha_password", );
      }
      $ldifout->write($entry);
    }
  }
  $ldifin->done();
  $ldifout->done();
}

sub postLdapStart {
  my $ldap_master_url         = getLocalConfig("ldap_master_url");
  my $ldap_starttls_supported = getLocalConfig("ldap_starttls_supported");

  my $ldap = Net::LDAP->new("$ldap_master_url") or die "$@";

  # startTLS Operation
  my $mesg;
  if ( $ldap_master_url !~ /^ldaps/i ) {
    if ($ldap_starttls_supported) {
      $mesg = $ldap->start_tls(
        verify => 'none',
        capath => "/opt/zextras/conf/ca",
      ) or die "start_tls: $@";
      $mesg->code && die "TLS: " . $mesg->error . "\n";
    }
  }

  $mesg = $ldap->bind( "cn=config", password => "$ldap_root_password" );

  $infile = "$config_dir/carbonio.ldif";
  $ldifin = Net::LDAP::LDIF->new( "$infile", "r", onerror => 'undef' );
  while ( not $ldifin->eof() ) {
    my $entry = $ldifin->read_entry();
    if ( $ldifin->error() ) {
      print "Error msg: ",    $ldifin->error(),       "\n";
      print "Error lines:\n", $ldifin->error_lines(), "\n";
      return 1;
    } elsif ($entry) {
      $entry->changetype("add");
      $entry->update($ldap);
    }
  }

  $infile = "$source_config_dir/zimbra/zimbra_globalconfig.ldif";
  $ldifin = Net::LDAP::LDIF->new( "$infile", "r", onerror => 'undef' );
  while ( not $ldifin->eof() ) {
    my $entry = $ldifin->read_entry();
    if ( $ldifin->error() ) {
      print "Error msg: ",    $ldifin->error(),       "\n";
      print "Error lines:\n", $ldifin->error_lines(), "\n";
      return 1;
    } elsif ($entry) {
      $entry->changetype("add");
      $entry->update($ldap);
    }
  }

  $infile = "$source_config_dir/zimbra/zimbra_defaultcos.ldif";
  $ldifin = Net::LDAP::LDIF->new( "$infile", "r", onerror => 'undef' );
  while ( not $ldifin->eof() ) {
    my $entry = $ldifin->read_entry();
    if ( $ldifin->error() ) {
      print "Error msg: ",    $ldifin->error(),       "\n";
      print "Error lines:\n", $ldifin->error_lines(), "\n";
      return 1;
    } elsif ($entry) {
      $entry->changetype("add");
      $entry->update($ldap);
    }
  }

  $infile = "$source_config_dir/zimbra/zimbra_defaultexternalcos.ldif";
  $ldifin = Net::LDAP::LDIF->new( "$infile", "r", onerror => 'undef' );
  while ( not $ldifin->eof() ) {
    my $entry = $ldifin->read_entry();
    if ( $ldifin->error() ) {
      print "Error msg: ",    $ldifin->error(),       "\n";
      print "Error lines:\n", $ldifin->error_lines(), "\n";
      return 1;
    } elsif ($entry) {
      $entry->changetype("add");
      $entry->update($ldap);
    }
  }

  if ( -f "/opt/zextras/conf/ldap/mimehandlers.ldif" ) {
    $infile = "/opt/zextras/conf/ldap/mimehandlers.ldif";
  } else {
    $infile = "$source_config_dir/zimbra/mimehandlers.ldif";
  }
  $ldifin = Net::LDAP::LDIF->new( "$infile", "r", onerror => 'undef' );
  while ( not $ldifin->eof() ) {
    my $entry = $ldifin->read_entry();
    if ( $ldifin->error() ) {
      print "Error msg: ",    $ldifin->error(),       "\n";
      print "Error lines:\n", $ldifin->error_lines(), "\n";
      return 1;
    } elsif ($entry) {
      $entry->changetype("add");
      $entry->update($ldap);
    }
  }

  return 0;
}

sub setLocalConfig {
  my $key = shift;
  my $val = shift;

  if ( exists $main::saved{lc}{$key} && $main::saved{lc}{$key} eq $val ) {
    return;
  }
  $main::saved{lc}{$key} = $val;
  qx(su - zextras -c '/opt/zextras/bin/zmlocalconfig -f -e ${key}=\'${val}\' 2> /dev/null');
}

sub getLocalConfig {
  my $key = shift;

  return $main::loaded{lc}{$key}
    if ( exists $main::loaded{lc}{$key} );

  my $val =qx(/opt/zextras/bin/zmlocalconfig -x -s -m nokey ${key} 2> /dev/null);
  chomp $val;
  $main::loaded{lc}{$key} = $val;
  return $val;
}
1;    # End of module