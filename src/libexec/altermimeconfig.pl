#!/usr/bin/perl

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

use strict;
use lib qw(/opt/zextras/common/lib/perl5 /opt/zextras/libexec/scripts);
use Net::DNS;
use Socket;
use Net::LDAP;
use MIME::Base64;
use Getopt::Long;

my (%c,%loaded,%saved,$rc);
my ($help, $verbose, $force, $enable, $disable);

my (undef, undef,$uid,$gid) = getpwnam('zextras');
if ($> ne $uid) {
  print "Must be run as user zextras.\n";
  &usage
}

my $opts_good = GetOptions("h|help" => \$help, 
    "e|enable=s" => \$enable,
    "d|disable=s" => \$disable,
    "f|force" => \$force,
    "v|verbose+" => \$verbose);

if (!$opts_good) {
  print STDERR "\n";
  usage();
}

if ($enable && $disable) {
  &usage;
}

&usage if ($help);

$c{zmlocalconfig}="/opt/zextras/bin/zmlocalconfig";
$c{zmprov}="/opt/zextras/bin/zmprov -l --";

# ***** Main *****
my $ldappass = qx($c{zmlocalconfig} -s -m nokey zimbra_ldap_password);
my $ldapdn  = qx($c{zmlocalconfig} -s -m nokey zimbra_ldap_userdn);
my $ldapurl  = qx($c{zmlocalconfig} -s -m nokey ldap_master_url);
chop($ldappass);
chop($ldapdn);
chop($ldapurl);

my $replica_ref= [ split(" ", $ldapurl) ];

my $ldap = Net::LDAP->new( $replica_ref ) or die "Error connecting to LDAP server(s): $ldapurl";
my $mesg = $ldap->bind( $ldapdn, password => $ldappass );
$mesg->code && die "Error binding to LDAP server: $mesg->error";

if ($enable) {
  &enableDomain;
}

if ($disable) {
  &disableDomain;
}

my $ldapquery = "(objectClass=zimbraGlobalConfig)";
$mesg = $ldap->search(
                  base => '',
                  filter => $ldapquery,
                  attrs => [
                      'zimbraDomainMandatoryMailSignatureEnabled',
                  ]
              );
my $enabled = $mesg->entry(0)->get_value('zimbraDomainMandatoryMailSignatureEnabled');

if (lc($enabled) eq "true") {
  $ldapquery = "(&(objectClass=zimbraDomain)(amavisDisclaimerOptions=*))";
  $mesg = $ldap->search(
                  base => '',
                  filter => $ldapquery,
                  attrs => [
                      'amavisDisclaimerOptions',
                      'zimbraAmavisDomainDisclaimerText',
                      'zimbraAmavisDomainDisclaimerHTML'
                  ],
  );
  my $total = $mesg->count();
  my $domain;
  my $text;
  my $html;
  if ($total > 0) {
    my $loop=0;
    while($loop < $total) {
      $text = $mesg->entry($loop)->get_value('zimbraAmavisDomainDisclaimerText');
      $html = $mesg->entry($loop)->get_value('zimbraAmavisDomainDisclaimerHTML');
      $domain = $mesg->entry($loop)->get_value('amavisDisclaimerOptions');
      print "Generating disclaimers for domain $domain.\n";
      writeFile("/opt/zextras/data/altermime/$domain.txt", "$text");
      writeFile("/opt/zextras/data/altermime/$domain.html", "$html");
      if ( -f "/opt/zextras/data/altermime/$domain.txt") {
        open(FILE, "/opt/zextras/data/altermime/$domain.txt");
        my $buf;
        while (read(FILE, $buf, 60*57)) {
          my $b64 = MIME::Base64::encode_base64($buf);
          writeFile("/opt/zextras/data/altermime/$domain.b64", "$b64");
        }
        close(FILE);
      }
      $loop++;
    }
  }
}

exit 0;
# ***** End Main *****


# ***** Subroutines *****
sub usage {
  print "\n";
  print "Usage: $0 [-h] [-f] [-v] [-d <domain>] [-e <domain>]\n";
  print " -h|--help: print this usage statement.\n";
  print " -d|--disable <domain>: Disable domain-specific disclaimer for domain <domain>.\n";
  print " -e|--enable <domain>: Enable domain-specific disclaimer for domain <domain>.\n";
  print " -f|--force: Force the rename, bypassing safety checks.\n";
  print " -v|--verbose: Set the verbosity level.\n";
  print "\n";
  exit 1; 
}

sub writeFile($$) {
  my ($file, $content) = @_;
  open(DATA, ">$file");
  print DATA "$content";
  print DATA "\n";
  close(DATA);
}

sub enableDomain() {
  my $ldapquery = "(&(objectClass=zimbraDomain)(zimbraDomainName=$enable))";
  $mesg = $ldap->search(
                  base => '',
                  filter => $ldapquery,
                  attrs => [ 'zimbraDomainName' ],
              );
  if($mesg->count == 1) {
	my $dn=$mesg->entry(0)->dn();
	$mesg = $ldap->modify(
      $dn,
      add => { amavisDisclaimerOptions => "$enable", },
    );
	print "Enabled disclaimers for domain: $enable\n";
  } else {
    print "Warning: Domain $enable does not exist.  Disclaimer not enabled\n";
  }
}

sub disableDomain() {
  my $ldapquery = "(&(objectClass=zimbraDomain)(zimbraDomainName=$disable)(amavisDisclaimerOptions=*))";
  $mesg = $ldap->search(
                  base => '',
                  filter => $ldapquery,
                  attrs => [
                      'amavisDisclaimerOptions',
                  ],
              );
  if($mesg->count == 1) {
    my $dn=$mesg->entry(0)->dn();
    $mesg = $ldap->modify(
      $dn,
      delete => ['amavisDisclaimerOptions'],
    );
	print "Disabled disclaimers for domain: $disable\n";
  } else {
    print "Warning: Domain $disable does not have disclaimers enabled\n";
  }
  unlink("/opt/zextras/data/altermime/$disable.txt");
  unlink("/opt/zextras/data/altermime/$disable.html");
  unlink("/opt/zextras/data/altermime/$disable.b64");
}

sub getLocalConfig {
  my ($key,$force) = @_;

  return $loaded{lc}{$key}
    if (exists $loaded{lc}{$key} && !$force);
  print "Getting local config $key=";
  my $val = qx($c{zmlocalconfig} -x -s -m nokey ${key} 2> /dev/null);
  chomp $val;
  $loaded{lc}{$key} = $val;
  print "$val\n"; 
  return $val;
}

