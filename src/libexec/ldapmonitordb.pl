#!/usr/bin/perl

# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

use strict;
use lib qw (/opt/zextras/common/lib/perl5);
use XML::Simple;
use Getopt::Long;
use Filesys::Df;
use POSIX;
use Mail::Mailer;
use Net::LDAP;

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

my ($help, $debug);

my $opts_good = GetOptions(
  'd|debug' => \$debug,
  'h|help' => \$help,
);
if (!$opts_good) {
  print STDERR "\n";
  usage();
}
if ($help) {
  usage(0);
}

my $localxml = XMLin("/opt/zextras/conf/localconfig.xml");

my $ldap_monitor_mdb = $localxml->{key}->{ldap_monitor_mdb}->{value};
my $ldap_monitor_alert_only = $localxml->{key}->{ldap_monitor_alert_only}->{value};
my $ldap_monitor_warning = $localxml->{key}->{ldap_monitor_warning}->{value};
my $ldap_monitor_critical = $localxml->{key}->{ldap_monitor_critical}->{value};
my $ldap_monitor_growth = $localxml->{key}->{ldap_monitor_growth}->{value};
my $ldap_db_maxsize = $localxml->{key}->{ldap_db_maxsize}->{value};
my $ldap_accesslog_maxsize = $localxml->{key}->{ldap_accesslog_maxsize}->{value};
my $ldap_is_master = $localxml->{key}->{ldap_is_master}->{value};
my $server = $localxml->{key}->{zimbra_server_hostname}->{value};
my $report=[];

chomp($ldap_monitor_mdb);
chomp($ldap_monitor_alert_only);
chomp($ldap_monitor_warning);
chomp($ldap_monitor_critical);
chomp($ldap_monitor_growth);
chomp($ldap_db_maxsize);
chomp($ldap_accesslog_maxsize);
chomp($ldap_is_master);

if ($ldap_monitor_mdb eq "") {
  $ldap_monitor_mdb = "true";
}

if (isdigit($ldap_monitor_mdb) && $ldap_monitor_mdb == 1) {
  $ldap_monitor_mdb = "true";
}

if (isdigit($ldap_monitor_mdb) && $ldap_monitor_mdb == 0) {
  $ldap_monitor_mdb = "false";
}

if ($ldap_monitor_mdb ne "true") {
  exit 0;
}

if ($ldap_db_maxsize eq "") {
  $ldap_db_maxsize = 85899345920;
}

if ($ldap_accesslog_maxsize eq "") {
  $ldap_accesslog_maxsize = 85899345920;
}

if ($ldap_monitor_alert_only eq "") {
  $ldap_monitor_alert_only = "true";
}

if ($ldap_monitor_warning eq "") {
  $ldap_monitor_warning = .8;
}

if ($ldap_monitor_critical eq "") {
  $ldap_monitor_critical = .9;
}

if ($ldap_monitor_growth eq "") {
  $ldap_monitor_growth = .25;
}

if (isdigit($ldap_monitor_alert_only) && $ldap_monitor_alert_only == 1) {
  $ldap_monitor_alert_only = "true";
}

if (isdigit($ldap_monitor_alert_only) && $ldap_monitor_alert_only == 0) {
  $ldap_monitor_alert_only = "false";
}

if ($ldap_monitor_warning > 1) {
  $ldap_monitor_warning/=100;
}

if ($ldap_monitor_critical > 1) {
  $ldap_monitor_critical/=100;
}

if ($ldap_monitor_growth > 1) {
  $ldap_monitor_growth/=100;
}

my $zmlocalconfig="/opt/zextras/bin/zmlocalconfig";
my $mdb_stat="/opt/zextras/common/bin/mdb_stat -e";
my $db="/opt/zextras/data/ldap/mdb/db/data.mdb";
my $adb="/opt/zextras/data/ldap/accesslog/db/data.mdb";
my $dbdir="/opt/zextras/data/ldap/mdb/db";
my $adbdir="/opt/zextras/data/ldap/accesslog/db";
my $mdb_used=0;
my $alog_used=0;
my $is_master=0;

if ($ldap_is_master && -f "/opt/zextras/data/ldap/accesslog/db/data.mdb") {
  $is_master=1;
}

my @mdb_stat=qx($mdb_stat $dbdir);
my $page_size=0;
my $pages_used=0;
my $junk;
foreach my $bit (@mdb_stat) {
  chomp($bit);
  if ($bit =~ /Page size:/) {
    ($junk, $page_size)=split(/: /, $bit, 2);
  }
  if ($bit =~ /Number of pages used:/) {
    ($junk, $pages_used)=split(/: /, $bit, 2);
  }
}
$mdb_used=$page_size*$pages_used;

my @adb_stat;
$page_size=0;
$pages_used=0;
if ($is_master) {
  @adb_stat=qx($mdb_stat $adbdir);
  foreach my $bit (@adb_stat) {
    chomp($bit);
    if ($bit =~ /Page size:/) {
      ($junk, $page_size)=split(/: /, $bit, 2);
    }
    if ($bit =~ /Number of pages used:/) {
      ($junk, $pages_used)=split(/: /, $bit, 2);
    }
  }
  $alog_used=$page_size*$pages_used;
}

my $partUsage=df("/opt/zextras/data/ldap/mdb/db");
my $totalspace = $partUsage->{blocks}*1024;
my $freespace = $partUsage->{bfree}*1024;
my $usedspace = $partUsage->{used}*1024;
if(defined($partUsage) && $debug) {
  print "Total space: ".$totalspace."\n";
  print "Total free: ".$freespace."\n";
  print "Total used: ".$usedspace."\n";
}

if ($ldap_db_maxsize > $totalspace) {
  if ($totalspace > 10485760 )  {
    setLocalConfig("ldap_db_maxsize", $totalspace);
    $ldap_db_maxsize=$totalspace;
  }
}

if ($ldap_accesslog_maxsize > $totalspace) {
  if ($totalspace > 10485760 )  {
    setLocalConfig("ldap_accesslog_maxsize", $totalspace);
    $ldap_accesslog_maxsize=$totalspace;
  }
}

my $mdb_warning_size = int($ldap_monitor_warning * $ldap_db_maxsize);
my $mdb_critical_size = int($ldap_monitor_critical * $ldap_db_maxsize);
my $alog_warning_size = int($ldap_monitor_warning * $ldap_accesslog_maxsize);
my $alog_critical_size = int($ldap_monitor_critical * $ldap_accesslog_maxsize);

my $mdb_alarm=0;
if ($mdb_used >= $mdb_critical_size) {
   $mdb_alarm=2;
} elsif ($mdb_used >= $mdb_warning_size) {
   $mdb_alarm=1;
}

my $mdb_growth_size=0;
if ($mdb_alarm) {
  $mdb_growth_size = int($ldap_monitor_growth * $ldap_db_maxsize);
}

my $alog_alarm=0;
if($is_master) {
  if ($alog_used >= $alog_critical_size) {
    $alog_alarm=2;
  } elsif ($alog_used >= $alog_warning_size) {
    $alog_alarm=1;
  }
}

my $alog_growth_size=0;
if ($alog_alarm) {
  $alog_growth_size = int($ldap_monitor_growth * $ldap_accesslog_maxsize);
}
my $space_alarm=0;
if ($mdb_alarm && $mdb_growth_size > $freespace && !$space_alarm) {
  $space_alarm=6;
}

if ($alog_alarm && $alog_growth_size > $freespace && !$space_alarm) {
  $space_alarm=5;
}

if ($alog_alarm && $mdb_alarm && $alog_growth_size+$mdb_growth_size > $freespace && !$space_alarm) {
  $space_alarm=4;
}

if ($debug) {
  print "ldap_db_maxsize=$ldap_db_maxsize\n";
  print "ldap_accesslog_maxsize=$ldap_accesslog_maxsize\n";
  print "mdb_used=$mdb_used\n";
  print "alog_used=$alog_used\n";
  print "mdb_warning_size=$mdb_warning_size\n";
  print "alog_warning_size=$alog_warning_size\n";
  print "mdb_critical_size=$mdb_critical_size\n";
  print "alog_critical_size=$alog_critical_size\n";
  print "mdb_alarm=$mdb_alarm\n";
  print "alog_alarm=$alog_alarm\n";
  print "space_alarm=$space_alarm\n";
  print "mdb_growth_size=$mdb_growth_size\n";
  print "alog_growth_size=$alog_growth_size\n";
  print "server:$server\n";
}

if ($space_alarm == 6) {
  if ($mdb_alarm ==2) {
    my $subject="CRITICAL DATABASE ALERT for $server\n";
    my $msg="CRITICAL! LDAP primary MDB database is nearly full and cannot expand due to limited free disk space.\n";
	push (@$report,$msg);
	sendEmailReport($subject, $report);
  } else {
    my $subject="WARNING DATABASE ALERT for $server.\n";
    my $msg="WARNING! LDAP primary MDB database is near the maximum size and cannot expand due to limited free disk space.\n";
	push (@$report,$msg);
	sendEmailReport($subject, $report);
  }
  exit 0;
}

if ($space_alarm == 5) {
  if ($alog_alarm ==2) {
    my $subject="CRITICAL DATABASE ALERT for $server\n";
    my $msg="CRITICAL! LDAP accesslog MDB database is nearly full and cannot expand due to limited free disk space.\n";
	push (@$report,$msg);
	sendEmailReport($subject, $report);
  } else {
    my $subject="WARNING DATABASE ALERT for $server.\n";
    my $msg="WARNING! LDAP accesslog MDB database is near the maximum size and cannot expand due to limited free disk space.\n";
	push (@$report,$msg);
	sendEmailReport($subject, $report);
  }
  exit 0;
}

if ($space_alarm == 4) {
  my $subject="CRITICAL DATABASE ALERT for $server.\n";
  my $msg="CRITICAL! LDAP primary and accesslog MDB databases are nearly full and cannot expand due to limited free disk space.\n";
  push (@$report,$msg);
  sendEmailReport($subject, $report);
  exit 0;
}

my $growth=0;
if ($mdb_alarm) { 
  if ($ldap_monitor_alert_only eq "false") {
    $growth =$mdb_growth_size + $ldap_db_maxsize;
	if ($debug) {
	  print "growth:$growth\n";
    }
	my $subject="LDAP PRIMARY DATABASE GROWTH ALERT\n";
    my $msg="Growing primary MDB database size from $ldap_db_maxsize to $growth.\n"; 
    if ($growth > 0) {
      setLocalConfig("ldap_db_maxsize", "$growth");
    }
    push (@$report,$msg);
	sendEmailReport($subject, $report);
  } elsif ($mdb_alarm == 2) {
    my $subject="CRITICAL DATABASE ALERT for $server.\n";
    my $msg="CRITICAL! LDAP primary MDB database is " . $ldap_monitor_critical*100 . "% full.\n";
    push (@$report,$msg);
    sendEmailReport($subject, $report);
  } else {
    my $subject="WARNIG DATABASE ALERT for $server.\n";
    my $msg="WARNING! LDAP primary MDB database is " . $ldap_monitor_warning*100 . "% full.\n";
    push (@$report,$msg);
    sendEmailReport($subject, $report);
  }
}

$growth=0;
if ($alog_alarm) {
  if ($ldap_monitor_alert_only eq "false") {
    $growth =$alog_growth_size + $ldap_db_maxsize;
	if ($debug) {
	  print "growth:$growth\n";
    }
	my $subject="LDAP ACCESSLOG DATABASE GROWTH ALERT\n";
    my $msg="Growing accesslog MDB database size from $ldap_accesslog_maxsize to $growth.\n";
    if ($growth > 0) {
      setLocalConfig("ldap_db_maxsize", "$growth");
    }
    push (@$report,$msg);
    sendEmailReport($subject, $report);
  } elsif ($alog_alarm == 2) {
    my $subject="CRITICAL DATABASE ALERT for $server.\n";
    my $msg="CRITICAL! LDAP accesslog MDB database is " . $ldap_monitor_critical*100 . "% full.\n";
    push (@$report,$msg);
    sendEmailReport($subject, $report);
  } else {
    my $subject="WARNIG DATABASE ALERT for $server.\n";
    my $msg="WARNING! LDAP accesslog MDB database is " . $ldap_monitor_warning*100 . "% full.\n";
    push (@$report,$msg);
    sendEmailReport($subject, $report);
  }
}

exit 0;

sub setLocalConfig {
  my $key = shift;
  my $val = shift;
  print "Setting local config $key=$val\n" if $debug;
  runCommand("$zmlocalconfig -f -e ${key}=\'${val}\' 2> /dev/null");
}

sub runCommand {
  my $cmd = shift;
  my $rc;
  $rc = 0xffff & system("$cmd > /dev/null 2>&1 ");
  return $rc;
}

sub getLdapConfigValue {
    my $attrib = shift;

    return (undef) unless ($attrib);

    my $val = getLdapServerConfigValue($attrib);
    print "Server: $val\n" if $debug;
    $val = getLdapGlobalConfigValue($attrib) if ($val eq "");
    print "Global: $val\n" if $debug;
    return $val;
}

sub getLdapServerConfigValue {
    my $attrib = shift;

    return (undef) unless ($attrib);
    open( CONF, "/opt/zextras/bin/zmprov -l gs $server '$attrib' |" )
      or die("Open server config failed: $!");

    my ( $key, $val );
    while (<CONF>) {
        chomp;
        next if (/^#/);
        ( $key, $val ) = split( /:\s*/, $_, 2 );
        last if ($val);
    }
    return $val;
}

sub getLdapGlobalConfigValue {
    my $attrib = shift;

    return (undef) unless ($attrib);

    open( CONF, "/opt/zextras/bin/zmprov -l gcf '$attrib' |" )
      or die("Open global config failed: $!");

    my ( $key, $val );
    while (<CONF>) {
        chomp;
        ( $key, $val ) = split( /:\s*/, $_, 2 );
        last if ($val);
    }
    return $val;
}

sub sendEmailReport {
  my $subject = shift;
  my $msg = shift;
  my $localxml = XMLin("/opt/zextras/conf/localconfig.xml");

  my $from_address= $localxml->{key}->{smtp_source}->{value};
  my $to_address = $localxml->{key}->{smtp_destination}->{value};

  my $smtphost = getLdapConfigValue("zimbraSmtpHostname") || "localhost";
  my $smtpport = getLdapConfigValue("zimbraSmtpPort") || "25";

  return if (scalar @$msg == 0);
  print "Sending ldap MDB error report to $to_address via $smtphost\n" if $debug;
  eval {
    my $mailer = Mail::Mailer->new("smtp", Server => $smtphost, Port => $smtpport);
    $mailer->open( { From => $from_address,
                   To   => $to_address,
                   Subject => $subject,
                })
    or warn "ERROR: Can't open: $!\n";
    print $mailer $msg;
    $mailer->close();
  };
  if ($@) {
    print("Failed to email report: $@\n");
  } else {
    print "Email report sent to $to_address\n" if $debug;
  }
}

sub usage() {
  print "Usage: $0 [-d] [-h]\n";
  print "  -d: debug information.\n";
  print "  -h: this help message.\n";
}
