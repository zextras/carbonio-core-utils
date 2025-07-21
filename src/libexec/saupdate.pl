#!/usr/bin/perl

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

use strict;
use lib '/opt/zextras/common/lib/perl5';
use Getopt::Long;
use Zextras::Util::Systemd;

# Skip manual saupdate when systemd is available
# Reason: carbonio-mailthreat-update.timer handles automated updates
# on systemd-only distros.
if ( isSystemd() ) {
  exit;
}

if ( !-d "/opt/zextras/data/spamassassin/localrules" ) {
  print "ERROR: SpamAssassin does not appear to be installed - exiting\n";
  exit(1);
}

my $id = getpwuid($<);
chomp $id;
if ( $id ne "zextras" ) {
  print STDERR "Error: must be run as zextras user\n";
  exit(1);
}

my ( $help, %loaded );

my $opts_good = GetOptions( 'h|help' => \$help, );

if ( !$opts_good ) {
  print STDERR "\n";
  usage();
}
if ($help) {
  usage(0);
}

my $zmlocalconfig        = "/opt/zextras/bin/zmlocalconfig";
my $rule_updates_enabled = getLocalConfig("antispam_enable_rule_updates");
if ( lc($rule_updates_enabled) =~ /true/ )  { $rule_updates_enabled = 1; }
if ( lc($rule_updates_enabled) =~ /false/ ) { $rule_updates_enabled = 0; }

if ( !$rule_updates_enabled ) {
  exit;
}

my $sa =
"/opt/zextras/common/bin/sa-update -v --reallyallowplugins --refreshmirrors >/dev/null 2>&1";
my $restart = "/opt/zextras/bin/zmamavisdctl restart norewrite >/dev/null 2>&1";
my $compile = "/opt/zextras/libexec/zmsacompile >/dev/null 2>&1";

my $restart_enabled = getLocalConfig("antispam_enable_restarts");
my $restart_required;

my $compile_rules = getLocalConfig("antispam_enable_rule_compilation");

if ( lc($restart_enabled) =~ /true/ )  { $restart_enabled = 1; }
if ( lc($restart_enabled) =~ /false/ ) { $restart_enabled = 0; }

if ( lc($compile_rules) =~ /true/ )  { $compile_rules = 1; }
if ( lc($compile_rules) =~ /false/ ) { $compile_rules = 0; }

qx($sa);
my $rc = $? >> 8;
if ( $rc == 1 ) {
  exit;
}elsif ( $rc == 0 ) {
  $restart_required = 1;
}else {
  print "zmsaupdate: Error code downloading update: $rc\n";
}

if ( $restart_required == 0 ) {
  exit;
}

if ($compile_rules) {
  qx($compile);
}

if ($restart_enabled) {
  qx($restart);
  $rc = $? >> 8;
}else {
  exit;
}

if ( $rc == 0 ) {
  exit;
}

print "zmsaupdate: Amavisd restart failed!\n";
exit 1;

sub usage {

  my ($msg) = (@_);

  $msg && print STDERR "\nERROR: $msg\n";
  print STDERR <<USAGE;
  zmsaupdate

  Updates SpamAssassin rules

USAGE
  exit(1);
}

sub getLocalConfig {
  my ( $key, $force ) = @_;

  return $loaded{lc}{$key}
    if ( exists $loaded{lc}{$key} && !$force );

  my $val = qx($zmlocalconfig -x -s -m nokey ${key} 2> /dev/null);
  chomp $val;
  $loaded{lc}{$key} = $val;
  return $val;
}
