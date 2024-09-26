#!/usr/bin/perl

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

use strict;
use lib '/opt/zextras/common/lib/perl5';
use Net::LDAP;
use Net::DNS::Resolver;
use Getopt::Long;

our %loaded = ();

my $id = getpwuid($<);
chomp $id;
if ($id ne "zextras") {
    print STDERR "Error: must be run as zextras user\n";
    exit (1);
}

my ($help, $dryrun, $mode);

my $opts_good = GetOptions(
  'h|help' => \$help,
  'd|dryrun' => \$dryrun,
  'm|mode=s' => \$mode,
);

if (!$opts_good) {
  print STDERR "\n";
  usage();
}

if ($help) {
  usage(0);
}

if ($mode && !$dryrun) {
  usage(0);
}

if ($mode && $mode ne "ipv4" && $mode ne "both" && $mode ne "ipv6") {
  usage(0);
}

my $ldapurl = getLocalConfig("ldap_url");
my $zdn = getLocalConfig("zimbra_ldap_userdn");
my $zps = getLocalConfig("zimbra_ldap_password");
my $ldap_starttls_supported = getLocalConfig("ldap_starttls_supported");
my $host = getLocalConfig("zimbra_server_hostname");

my $zmlocalconfig="/opt/zextras/bin/zmlocalconfig";

my $replica_ref=[ split(" ", $ldapurl) ];
my $ldap = Net::LDAP->new( $replica_ref ) or die "Error connecting to LDAP server: $ldapurl";

my $mesg;
if ($ldapurl !~ /^ldaps/i) {
  if ($ldap_starttls_supported) {
    $mesg = $ldap->start_tls(
         verify => 'none',
         capath => "/opt/zextras/conf/ca",
         ) or die "start_tls: $@";
    $mesg->code && die "TLS: " . $mesg->error . "\n";
  }
}

my $mesg = $ldap->bind("$zdn", password=>"$zps");
$mesg->code && die "Bind: ". $mesg->error . "\n";

my $zimbraIPMode;
my $size;
if ($mode) {
  $zimbraIPMode=$mode;
} else {
  $mesg = $ldap->search(
            base=>"",
            filter=>"(&(objectClass=zimbraServer)(cn=$host))",
            scope=>"sub",
            attrs => ['zimbraIPMode'],
          );
  
  $size = $mesg->count;
  if ($size == 0) {
    print "Error: Server $host not found\n";
    exit 1;
  }
  
  my $entry=$mesg->entry(0);
  $zimbraIPMode = $entry->get_value("zimbraIPMode");
}

$mesg = $ldap->search(
          base=>"",
          filter=>"(&(objectClass=zimbraServer)(cn=$host)(zimbraServiceEnabled=mailbox))",
          scope=>"sub",
        );

$size = $mesg->count;
my $storeserver=0;
if ($size > 0) {
  $storeserver=1;
}

$mesg = $ldap->search(
          base=>"",
          filter=>"(&(objectClass=zimbraServer)(cn=$host)(zimbraServiceEnabled=mta))",
          scope=>"sub",
        );

$size = $mesg->count;
my $mtaserver=0;
if ($size > 0) {
  $mtaserver=1;
}

$size = $mesg->count;

my $mailboxd_java_options = getLocalConfigRaw("mailboxd_java_options");
my $zimbra_zmjava_options = getLocalConfigRaw("zimbra_zmjava_options");

my $antispam_mysql_host = getLocalConfig("antispam_mysql_host");
my $mysql_bind_address = getLocalConfig("mysql_bind_address");
my $postjournal_enabled = getLocalConfig("postjournal_enabled");

if ($zimbraIPMode eq "ipv4") {
  my $ans = getDnsRecords($host, 'A');
  if (!defined($ans)) {
    print "Error: Unable to resolve $host A record\n";
  }
  if ($zimbra_zmjava_options !~ /-Djava.net.preferIPv4Stack=true/) {
      $zimbra_zmjava_options .= " -Djava.net.preferIPv4Stack=true";
  }
  if ($zimbra_zmjava_options =~ /-Djava.net.preferIPv6Addresses=true/) {
      $zimbra_zmjava_options =~ s/ -Djava.net.preferIPv6Addresses=true//;
  }
  if ($dryrun) {
    print "Would set zimbra_zmjava_options to $zimbra_zmjava_options\n";
  } else {
    setLocalConfig("zimbra_zmjava_options", $zimbra_zmjava_options);
  }
  if ($storeserver) {
    if ($mailboxd_java_options !~ /-Djava.net.preferIPv4Stack=true/) {
      $mailboxd_java_options .= " -Djava.net.preferIPv4Stack=true";
    }
    if ($mailboxd_java_options =~ /-Djava.net.preferIPv6Addresses=true/) {
      $mailboxd_java_options =~ s/ -Djava.net.preferIPv6Addresses=true//;
    }
    if ($dryrun) {
      print "Would set mailboxd_java_options to $mailboxd_java_options\n";
    } else {
      setLocalConfig("mailboxd_java_options", $mailboxd_java_options);
    }
    if ( $mysql_bind_address eq "" || $mysql_bind_address =~ /localhost/ || $mysql_bind_address =~ /::1/ || $mysql_bind_address =~ /127.0.0.1/ ) {
      if ($dryrun) {
        print "Would set mysql_bind_address to 127.0.0.1\n";
      } else {
        setLocalConfig("mysql_bind_address", "127.0.0.1");
        my $mysql_mycnf = getLocalConfig("mysql_mycnf");
        system("/opt/zextras/libexec/zminiutil --backup=.pre --section=mysqld --key=bind-address --unset ${mysql_mycnf}");
        system("/opt/zextras/libexec/zminiutil --backup=.pre-bind --section=mysqld --key=bind-address --set --value=127.0.0.1 ${mysql_mycnf}");
      }
    }
  }
  if($mtaserver){
    if ( $antispam_mysql_host eq "" || $antispam_mysql_host =~ /localhost/ || $antispam_mysql_host =~ /::1/ || $antispam_mysql_host =~ /127.0.0.1/ ) {
      if ($dryrun) {
        print "Would set antispam_mysql_host to 127.0.0.1\n";
      } else {
        setLocalConfig("antispam_mysql_host", "127.0.0.1");
        my $mysql_mycnf = getLocalConfig("antispam_mysql_mycnf");
        if (-f $mysql_mycnf) {
           system("/opt/zextras/libexec/zminiutil --backup=.pre --section=mysqld --key=bind-address --unset ${mysql_mycnf}");
          system("/opt/zextras/libexec/zminiutil --backup=.pre-bind --section=mysqld --key=bind-address --set --value=127.0.0.1 ${mysql_mycnf}");
        }
      }
    }
    if ($postjournal_enabled eq "true") {
      if ($dryrun) {
        print "Would set postjournal_reinject_host to 127.0.0.1\n";
        print "Would set postjournal_archive_host to 127.0.0.1\n";
      } else {
        setLocalConfig("postjournal_reinject_host", "127.0.0.1");
        setLocalConfig("postjournal_archive_host", "127.0.0.1");
      }
    }
  }
} elsif ($zimbraIPMode eq "both") {
  my $ans = getDnsRecords($host, 'A');
  if (!defined($ans)) {
    print "Error: Unable to resolve $host A record\n";
  }
  my $ans = getDnsRecords($host, 'AAAA');
  if (!defined($ans)) {
    print "Error: Unable to resolve $host AAAA record\n";
  }
  if ($zimbra_zmjava_options =~ /-Djava.net.preferIPv4Stack=true/) {
    $zimbra_zmjava_options =~ s/ -Djava.net.preferIPv4Stack=true//;
  }
  if ($zimbra_zmjava_options =~ /-Djava.net.preferIPv6Addresses=true/) {
    $zimbra_zmjava_options =~ s/ -Djava.net.preferIPv6Addresses=true//;
  }
  if ($dryrun) {
    print "Would set zimbra_zmjava_options to $zimbra_zmjava_options\n";
  } else {
    setLocalConfig("zimbra_zmjava_options", $zimbra_zmjava_options);
  }
  if ($storeserver) {
    if ($mailboxd_java_options =~ /-Djava.net.preferIPv4Stack=true/) {
      $mailboxd_java_options =~ s/ -Djava.net.preferIPv4Stack=true//;
    }
    if ($mailboxd_java_options =~ /-Djava.net.preferIPv6Addresses=true/) {
      $mailboxd_java_options =~ s/ -Djava.net.preferIPv6Addresses=true//;
    }
    if ($dryrun) {
      print "Would set mailboxd_java_options to $mailboxd_java_options\n";
    } else {
      setLocalConfig("mailboxd_java_options", $mailboxd_java_options);
    }
    if ( $mysql_bind_address eq "" || $mysql_bind_address =~ /localhost/ || $mysql_bind_address =~ /::1/ || $mysql_bind_address =~ /127.0.0.1/ ) {
      if ($dryrun) {
        print "Would set mysql_bind_address to ::1\n";
      } else {
        setLocalConfig("mysql_bind_address", "::1");
        my $mysql_mycnf = getLocalConfig("mysql_mycnf");
        system("/opt/zextras/libexec/zminiutil --backup=.pre --section=mysqld --key=bind-address --unset ${mysql_mycnf}");
        system("/opt/zextras/libexec/zminiutil --backup=.pre-bind --section=mysqld --key=bind-address --set --value=::1 ${mysql_mycnf}");
      }
    }
  }
  if ($mtaserver) {
    if ( $antispam_mysql_host eq "" || $antispam_mysql_host =~ /localhost/ || $antispam_mysql_host =~ /::1/ || $antispam_mysql_host =~ /127.0.0.1/ ) {
      if ($dryrun) {
        print "Would set antispam_mysql_host to ::1\n";
      } else {
        setLocalConfig("antispam_mysql_host", "::1");
        my $mysql_mycnf = getLocalConfig("antispam_mysql_mycnf");
        if (-f $mysql_mycnf) {
          system("/opt/zextras/libexec/zminiutil --backup=.pre --section=mysqld --key=bind-address --unset ${mysql_mycnf}");
          system("/opt/zextras/libexec/zminiutil --backup=.pre-bind --section=mysqld --key=bind-address --set --value=::1 ${mysql_mycnf}");
        }
      }
    }
    if ($postjournal_enabled eq "true") {
      if ($dryrun) {
        print "Would set postjournal_reinject_host to ::1\n";
        print "Would set postjournal_archive_host to ::1\n";
      } else {
        setLocalConfig("postjournal_reinject_host", "::1");
        setLocalConfig("postjournal_archive_host", "::1");
      }
    }
  }
} elsif ($zimbraIPMode eq "ipv6") {
  my $ans = getDnsRecords($host, 'AAAA');
  if (!defined($ans)) {
    print "Error: Unable to resolve $host AAAA record\n";
  }
  if ($zimbra_zmjava_options =~ /-Djava.net.preferIPv4Stack=true/) {
    $zimbra_zmjava_options =~ s/ -Djava.net.preferIPv4Stack=true//;
  }
  if ($zimbra_zmjava_options !~ /-Djava.net.preferIPv6Addresses=true/) {
    $zimbra_zmjava_options .= " -Djava.net.preferIPv6Addresses=true";
  }
  if ($dryrun) {
    print "Would set zimbra_zmjava_options to $zimbra_zmjava_options\n";
  } else {
    setLocalConfig("zimbra_zmjava_options", $zimbra_zmjava_options);
  }
  if ($storeserver) {
    if ($mailboxd_java_options =~ /-Djava.net.preferIPv4Stack=true/) {
      $mailboxd_java_options =~ s/ -Djava.net.preferIPv4Stack=true//;
    }
    if ($mailboxd_java_options !~ /-Djava.net.preferIPv6Addresses=true/) {
      $mailboxd_java_options .= " -Djava.net.preferIPv6Addresses=true";
    }
    if ($dryrun) {
      print "Would set mailboxd_java_options to $mailboxd_java_options\n";
    } else {
      setLocalConfig("mailboxd_java_options", $mailboxd_java_options);
    }
    if ( $mysql_bind_address eq "" || $mysql_bind_address =~ /localhost/ || $mysql_bind_address =~ /::1/ || $mysql_bind_address =~ /127.0.0.1/ ) {
      if ($dryrun) {
        print "Would set mysql_bind_address to ::1\n";
      } else {
        setLocalConfig("mysql_bind_address", "::1");
        my $mysql_mycnf = getLocalConfig("mysql_mycnf");
        system("/opt/zextras/libexec/zminiutil --backup=.pre --section=mysqld --key=bind-address --unset ${mysql_mycnf}");
        system("/opt/zextras/libexec/zminiutil --backup=.pre-bind --section=mysqld --key=bind-address --set --value=::1 ${mysql_mycnf}");
      }
    }
  }
  if ($mtaserver) {
    if ( $antispam_mysql_host eq "" || $antispam_mysql_host =~ /localhost/ || $antispam_mysql_host =~ /::1/ || $antispam_mysql_host =~ /127.0.0.1/ ) {
      if ($dryrun) {
        print "Would set antispam_mysql_host to ::1\n";
      } else {
        setLocalConfig("antispam_mysql_host", "::1");
        my $mysql_mycnf = getLocalConfig("antispam_mysql_mycnf");
        if (-f $mysql_mycnf) {
          system("/opt/zextras/libexec/zminiutil --backup=.pre --section=mysqld --key=bind-address --unset ${mysql_mycnf}");
          system("/opt/zextras/libexec/zminiutil --backup=.pre-bind --section=mysqld --key=bind-address --set --value=::1 ${mysql_mycnf}");
        }
      }
    }
    if ($postjournal_enabled eq "true") {
      if ($dryrun) {
        print "Would set postjournal_reinject_host to ::1\n";
        print "Would set postjournal_archive_host to ::1\n";
      } else {
        setLocalConfig("postjournal_reinject_host", "::1");
        setLocalConfig("postjournal_archive_host", "::1");
      }
    }
  }
} else {
  print "Error: Unknown IP mode $zimbraIPMode\n";
  exit 1;
}

sub usage {
  my ($msg) = (@_);

  $msg && print STDERR "\nERROR: $msg\n";
  print STDERR <<USAGE;
  zmiptool [-d [-m ipmode]]

  Where:
  -d: dry run   Do not make any changes, just print what would be done.
  -m: IP Mode to test for if dryrun is enabled.  Optional

USAGE
        exit (1);

}

sub getLocalConfigRaw {
  my $key = shift;

  return $main::loaded{lc}{$key}
    if (exists $main::loaded{lc}{$key});

  my $val = qx(/opt/zextras/bin/zmlocalconfig -s -m nokey ${key} 2> /dev/null);
  chomp $val;
  $main::loaded{lc}{$key} = $val;
  return $val;
}

sub getLocalConfig{
  my $key = shift;

  return $main::loaded{lc}{$key}
    if (exists $main::loaded{lc}{$key});

  my $val = qx(/opt/zextras/bin/zmlocalconfig -x -s -m nokey ${key} 2> /dev/null);
  chomp $val;
  $main::loaded{lc}{$key} = $val;
  return $val;
}

sub setLocalConfig {
  my $key = shift;
  my $val = shift;
  print "Setting local config $key=$val\n";
  runCommand("$zmlocalconfig -f -e ${key}=\'${val}\' 2> /dev/null");
}

sub runCommand {
  my $cmd = shift;
  my $rc;
  $rc = 0xffff & system("$cmd > /dev/null 2>&1 ");
  return $rc;
}

sub getDnsRecords {
  my $name = shift;
  my $qtype = shift;

  my $res = Net::DNS::Resolver->new;
  my @servers = $res->nameservers();
  my $ans = $res->search ($name, $qtype);

  return $ans;
}
