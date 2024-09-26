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
use Net::LDAP::LDIF;
use Getopt::Long;
use File::Basename;


my (%c,%loaded,%saved,$rc);
my ($oldServerName, $newServerName, $help, $verbose, $force, $delete, $skipusers, $usersonly);

my (undef, undef,$uid,$gid) = getpwnam('zextras');
if ($> ne $uid) {
  print "Must be run as user zextras.\n";
  &usage
}

GetOptions("help" => \$help, 
    "oldservername=s" => \$oldServerName,
    "newservername=s" => \$newServerName,
    "force" => \$force,
    "deletelogger" => \$delete,
    "skipusers" => \$skipusers,
    "usersonly" => \$usersonly,
    "verbose+" => \$verbose);

&usage if ($help or !$newServerName);

$c{zmlocalconfig}="/opt/zextras/bin/zmlocalconfig";
$c{zmprov}="/opt/zextras/bin/zmprov -l -m --";
$c{zmcertmgr}="/opt/zextras/bin/zmcertmgr";

if ($usersonly && !$oldServerName) {
  print "--usersonly requries --oldServerName.\n";
  exit 0;
}

if ($oldServerName) {
  $c{zimbra_server_hostname} = $oldServerName;
} else {
  $c{zimbra_server_hostname} = getLocalConfig("zimbra_server_hostname");
}

if ($c{zimbra_server_hostname} eq $newServerName) {
  print "Hostname is already $newServerName.\n";
  exit 0 unless $force;
}

if (!$force) {
  my $dns=1;
  my $res = Net::DNS::Resolver->new;
  my $answer = $res->search($newServerName);
  if (!defined($answer)) {
    print "Warning: Hostname $newServerName is not resolvable via DNS\n";
    $dns=0;
  }
  if (!$dns) {
    my @a=gethostbyname("$newServerName");
    my $iaddr=splice(@a,4);
    if (!defined($iaddr)) {
      print "Error: Hostname $newServerName is not resolvable via /etc/hosts or DNS.\n";
      exit 1;
    }
  }
}

$c{zimbra_ldap_userdn} = getLocalConfig("zimbra_ldap_userdn");
$c{zimbra_ldap_password} = getLocalConfig("zimbra_ldap_password");
$c{ldap_is_master} = getLocalConfig("ldap_is_master");
$c{ldap_url} = getLocalConfig("ldap_url");
$c{ldap_master_url} = getLocalConfig("ldap_master_url");
$c{ldap_starttls_supported} = getLocalConfig("ldap_starttls_supported");
my @masters=split(/ /, $c{ldap_master_url});
my $master_ref=\@masters;

&startLdap if (lc($c{ldap_is_master}) eq "true");
$c{zimbra_log_host} = getLdapGlobalConfig("zimbraLogHostname") if ($delete);

if ($delete && $c{zimbra_log_host} eq "") {
  print "Unabled to determine zimbra_log_host to delete.\n";
  exit 1;
}

# ***** Main *****

if (!$usersonly) {
  print "Renaming $c{zimbra_server_hostname} to $newServerName\n";
  print "Shutting down zimbra...";
  my $rc = runCommand("/opt/zextras/bin/zmcontrol stop");
  print (($rc==0) ? "done.\n" : "failed.\n");


  updateLocalConfig("ldap_master_url");
  updateLocalConfig("ldap_url");
  updateLocalConfig("ldap_host");
  updateLocalConfig("av_notify_user");
  updateLocalConfig("av_notify_domain");
  updateLocalConfig("smtp_source");
  updateLocalConfig("smtp_destination");
  updateLocalConfig("zimbra_server_hostname");

  &startLdap if (lc($c{ldap_is_master}) eq "true");

  $c{zimbraServiceEnabled} = getLdapServerConfig("zimbraServiceEnabled");

  modifyServerName($newServerName);

  if (!$skipusers) {
    modifyAccountData($newServerName);
  }
  modifyListData($newServerName);

  print "Services: $c{zimbraServerEnabled}\n";
  # Reinitialize mta config
  if (index($c{zimbraServiceEnabled}, "mta") != -1) {
    $c{ldap_host} = getLocalConfig("ldap_host");
    $c{ldap_port} = getLocalConfig("ldap_port");
    print "Reinitializing the mta config...";
    $rc = runCommand("/opt/zextras/libexec/zmmtainit $c{ldap_host} $c{ldap_port}");
    print (($rc==0) ? "done.\n" : "failed.\n");
  }

  #remap or delete logger data for the host
  if (index($c{zimbraServiceEnabled}, "logger") != -1) {
    if ($delete) {
      runCommand("/opt/zextras/bin/zmloggerhostmap -d $oldServerName $oldServerName");
    } else {
      runCommand("/opt/zextras/bin/zmloggerhostmap $oldServerName $newServerName");
    }
  } else {
    if ($delete) {
      runCommand("/opt/zextras/libexec/zmrc $c{zimbra_log_host} HOST:$c{zimbra_log_host} zmloggerhostmap -d $oldServerName $oldServerName");
    } else {
      runCommand("/opt/zextras/libexec/zmrc $c{zimbra_log_host} HOST:$c{zimbra_log_host} zmloggerhostmap $oldServerName $newServerName");
    }
  }

  # Regenerate Self-signed certs
  if (!-f "/opt/zextras/ssl/carbonio/commercial/commercial.crt") {
    if(lc($c{ldap_is_master}) eq "true") {
      runCommand("$c{zmcertmgr} createca -new");
      runCommand("$c{zmcertmgr} deployca");
    }
    runCommand("$c{zmcertmgr} createcrt -new");
    runCommand("$c{zmcertmgr} deploycrt self -allserver");
  }
} else {
  modifyAccountData($newServerName);
}

exit 0;
# ***** End Main *****

# ***** Subroutines *****
sub usage {
  print "\n";
  print "Usage: " . basename($0) . " [-h] [-d] [-f] [-s] [-o <oldServerName>] [-v+] -n <newServerName>\n";
  print "Changes the name of the local zimbra server.\n";
  print " -h | --help                                 Print this usage statement.\n";
  print " -f | --force                                Force the rename, bypassing safety checks.\n";
  print " -o <oldServerName> | --oldServerName <oldServerName>\n";
  print "                                             Previous name for the server.  Defaults to LC zimbra_server_hostname.\n";
  print " -n <newServerName> | --newServerName <newServerName>\n";
  print "                                             New name for the server.\n";
  print " -d | --deletelogger                         Delete the logger database for the old server.  Default is to remap\n";
  print "                                             its data to the new hostname.\n";
  print " -s | --skipusers                            Skips modifying the user database with the new server.\n"; 
  print " -u | --usersonly                            Only updates the user database.  This way, you can run once to do all\n";
  print "                                             the server updates, and then a second time to update the accounts.\n";
  print "                                             Likely requires --force.\n";
  print " -v | --verbose:                             Set the verbosity level.  Can be specified multiple times to increase\n";
  print "                                             the level.\n";
  print "\n";
  exit 0; 
}

sub modifyServerName($) {
  my ($server) = @_;
  my $config_base = "cn=config,cn=zimbra";
  my $server_base = "cn=servers,cn=zimbra";
  my $cos_base = "cn=cos,cn=zimbra";
  my $zimbra_base = "cn=zimbra";
  my $root_base = "";
  my $ldap;
  unless($ldap = Net::LDAP->new($master_ref)) {
    print ("Unable to contact $c{ldap_master_url}: $!\n");
    return 1;
  }
  my $result;
  if ($c{ldap_master_url} !~ /^ldaps/i) {
    if ($c{ldap_starttls_supported}) {
      $result = $ldap->start_tls(
        verify => 'none',
        capath => "/opt/zextras/conf/ca",
        ) or die "start_tls: $@";
      $result->code && die "TLS: " . $result->error . "\n";
    }
  }
  $result = $ldap->bind($c{zimbra_ldap_userdn}, 
    password => $c{zimbra_ldap_password});
  if ($result->code()) {
    print("ldap bind failed for $c{zimbra_ldap_userdn}\n");
    return 1;
  } else {
    print("ldap bind done for $c{zimbra_ldap_userdn}\n") if ($verbose > 1);
    print "Searching for ldap server entry...";
    $result = $ldap->search(base => $server_base, 
      scope => 'one', 
      filter => "(cn=$c{zimbra_server_hostname})");
    print ($result->code() ? "failed.\n" : "done.\n");
    return $result if ($result->code());

    # Rename server entry
    foreach my $entry ($result->all_entries) {
      print "Renaming ", $entry->dn(), "...";
      $result = $ldap->moddn(
        $entry->dn,
        newrdn=>"cn=$server",
        deleteoldrdn => 1
        );
      print ($result->code() ? "failed.\n" : "done.\n");
    }
    print("Updating zimbraServiceHostname attribute\n") if ($verbose > 1);
    $result = $ldap->search(base => $server_base,
      scope =>'one',
      attrs => ['1.1'],
      filter => "(&(objectClass=zimbraServer)(zimbraServiceHostname=$c{zimbra_server_hostname}))");
    return $result if ($result->code());
    foreach my $entry ($result->all_entries) {
      print "Updating zimbraServiceHostname for ", $entry->dn(), "...";
      $result = $ldap->modify(
        $entry->dn,
        replace => {zimbraServiceHostname => "$server"},
        );
      print ($result->code() ? "failed.\n" : "done.\n");
    }
    print("Updating zimbraSpellCheckURL attribute\n") if ($verbose > 1);
    $result = $ldap->search(base => $zimbra_base,
      scope =>'sub',
      attrs => ['zimbraSpellCheckURL'],
      filter => "(&(|(objectClass=zimbraServer)(objectClass=zimbraGlobalConfig))(zimbraSpellCheckURL=*://$c{zimbra_server_hostname}:*))");
    return $result if ($result->code());
    foreach my $entry ($result->all_entries) {
      print "Updating zimbraSpellCheckURL for ", $entry->dn(), "...";
      my @value=$entry->get_value("zimbraSpellCheckURL");
      foreach my $val (@value) {
        if ($val =~ /$c{zimbra_server_hostname}/) {
          my $new_val= $val;
          $new_val =~ s/$c{zimbra_server_hostname}/$server/g;
          $result = $ldap->modify(
            $entry->dn,
            add => {zimbraSpellCheckURL => "$new_val"},
            delete => {zimbraSpellCheckURL => "$val"},
            );
          print ($result->code() ? "failed.\n" : "done.\n");
        }
      }
    }
    print("Updating zimbraSmtpHostname attribute\n") if ($verbose > 1);
    $result = $ldap->search(base => $root_base,
      scope =>'sub',
      attrs => ['1.1'],
      filter => "(&(|(objectClass=zimbraServer)(objectClass=zimbraGlobalConfig)(objectClass=zimbraDomain))(zimbraSmtpHostname=$c{zimbra_server_hostname}))");
    return $result if ($result->code());
    foreach my $entry ($result->all_entries) {
      print "Updating zimbraSmtpHostname for ", $entry->dn(), "...";
      $result = $ldap->modify(
        $entry->dn,
        add => {zimbraSmtpHostname => "$server"},
        delete => {zimbraSmtpHostname => "$c{zimbra_server_hostname}"},
        );
      print ($result->code() ? "failed.\n" : "done.\n");
    }
    print("Updating zimbraWebClientAdminReference attribute\n") if ($verbose > 1);
    $result = $ldap->search(base => $root_base,
      scope =>'sub',
      attrs => ['zimbraWebClientAdminReference'],
      filter => "(&(|(objectClass=zimbraDomain)(objectClass=zimbraGlobalConfig))(zimbraWebClientAdminReference=*://$c{zimbra_server_hostname}:*))");
    return $result if ($result->code());
    foreach my $entry ($result->all_entries) {
      print "Updating zimbraWebClientAdminReference for ", $entry->dn(), "...";
      my $value=$entry->get_value("zimbraWebClientAdminReference");
      $value =~ s/$c{zimbra_server_hostname}/$server/g;
      $result = $ldap->modify(
        $entry->dn,
        replace => {zimbraWebClientAdminReference => "$value"},
        );
      print ($result->code() ? "failed.\n" : "done.\n");
    }
    print("Updating zimbraVirtualHostname attribute\n") if ($verbose > 1);
    $result = $ldap->search(base => $root_base,
      scope =>'sub',
      attrs => ['zimbraVirtualHostname'],
      filter => "(&(objectClass=zimbraDomain)(zimbraVirtualHostname=$c{zimbra_server_hostname}))");
    return $result if ($result->code());
    foreach my $entry ($result->all_entries) {
      print "Updating zimbraVirtualHostname for ", $entry->dn(), "...";
      $result = $ldap->modify(
        $entry->dn,
        add => {zimbraVirtualHostname => "$server"},
        delete => {zimbraVirtualHostname => "$c{zimbra_server_hostname}"},
        );
      print ($result->code() ? "failed.\n" : "done.\n");
    }
    print("Updating zimbraDNSCheckHostname attribute\n") if ($verbose > 1);
    $result = $ldap->search(base => $root_base,
      scope =>'sub',
      attrs => ['1.1'],
      filter => "(&(|(objectClass=zimbraDomain)(objectClass=zimbraGlobalConfig))(zimbraDNSCheckHostname=$c{zimbra_server_hostname}))");
    return $result if ($result->code());
    foreach my $entry ($result->all_entries) {
      print "Updating zimbraDNSCheckHostname for ", $entry->dn(), "...";
      $result = $ldap->modify(
        $entry->dn,
        replace => {zimbraDNSCheckHostname => "$server"},
        );
      print ($result->code() ? "failed.\n" : "done.\n");
    }
    print("Updating zimbraDataSourceHost attribute\n") if ($verbose > 1);
    $result = $ldap->search(base => $root_base,
      scope =>'sub',
      attrs => ['1.1'],
      filter => "(&(objectClass=zimbraDataSource)(zimbraDataSourceHost=$c{zimbra_server_hostname}))");
    return $result if ($result->code());
    foreach my $entry ($result->all_entries) {
      print "Updating zimbraDataSourceHost for ", $entry->dn(), "...";
      $result = $ldap->modify(
        $entry->dn,
        replace => {zimbraDataSourceHost => "$server"},
        );
      print ($result->code() ? "failed.\n" : "done.\n");
    }
    print("Updating zimbraMtaMyHostname attribute\n") if ($verbose > 1);
    $result = $ldap->search(base => $zimbra_base,
      scope =>'sub',
      attrs => ['1.1'],
      filter => "(&(|(objectClass=zimbraServer)(objectClass=zimbraGlobalConfig))(zimbraMtaMyHostname=$c{zimbra_server_hostname}))");
    return $result if ($result->code());
    foreach my $entry ($result->all_entries) {
      print "Updating zimbraMtaMyHostname for ", $entry->dn(), "...";
      $result = $ldap->modify(
        $entry->dn,
        replace => {zimbraMtaMyHostname => "$server"},
        );
      print ($result->code() ? "failed.\n" : "done.\n");
    }
    print("Updating zimbraMtaRelayHost attribute\n") if ($verbose > 1);
    $result = $ldap->search(base => $zimbra_base,
      scope =>'sub',
      attrs => ['1.1'],
      filter => "(&(|(objectClass=zimbraServer)(objectClass=zimbraGlobalConfig))(zimbraMtaRelayHost=$c{zimbra_server_hostname}))");
    return $result if ($result->code());
    foreach my $entry ($result->all_entries) {
      print "Updating zimbraMtaRelayHost for ", $entry->dn(), "...";
      $result = $ldap->modify(
        $entry->dn,
        add => {zimbraMtaRelayHost => "$server"},
        delete => {zimbraMtaRelayHost => "$c{zimbra_server_hostname}"},
        );
      print ($result->code() ? "failed.\n" : "done.\n");
    }
    print("Updating zimbraLogHostname attribute\n") if ($verbose > 1);
    $result = $ldap->search(base => $config_base,
      scope =>'sub',
      attrs => ['1.1'],
      filter => "(&(objectClass=zimbraGlobalConfig)(zimbraLogHostname=$c{zimbra_server_hostname}))");
    return $result if ($result->code());
    foreach my $entry ($result->all_entries) {
      print "Updating zimbraLogHostname for ", $entry->dn(), "...";
      $result = $ldap->modify(
        $entry->dn,
        add => {zimbraLogHostname => "$server"},
        delete => {zimbraLogHostname => "$c{zimbra_server_hostname}"},
        );
      print ($result->code() ? "failed.\n" : "done.\n");
    }
    print("Updating zimbraPublicServiceHostname attribute\n") if ($verbose > 1);
    $result = $ldap->search(base => $root_base,
      scope =>'sub',
      attrs => ['1.1'],
      filter => "(&(|(objectClass=zimbraDomain)(objectClass=zimbraGlobalConfig))(zimbraPublicServiceHostname=$c{zimbra_server_hostname}))");
    return $result if ($result->code());
    foreach my $entry ($result->all_entries) {
      print "Updating zimbraPublicServiceHostname for ", $entry->dn(), "...";
      $result = $ldap->modify(
        $entry->dn,
        replace => {zimbraPublicServiceHostname => "$server"},
        );
      print ($result->code() ? "failed.\n" : "done.\n");
    }
    print("Updating zimbraServerHostPool attribute\n") if ($verbose > 1);
    $result = $ldap->search(base => $cos_base,
      scope =>'one',
      attrs => ['1.1'],
      filter => "(&(objectClass=zimbraCOS)(zimbraServerHostPool=$c{zimbra_server_hostname}))");
    return $result if ($result->code());
    foreach my $entry ($result->all_entries) {
      print "Updating zimbraServerHostPool for ", $entry->dn(), "...";
      $result = $ldap->modify(
        $entry->dn,
        add => {zimbraServerHostPool => "$server"},
        delete => {zimbraServerHostPool => "$c{zimbra_server_hostname}"},
        );
      print ($result->code() ? "failed.\n" : "done.\n");
    }
  }
  $result = $ldap->unbind;
  return 0;
}

sub modifyAccountData($) {
  my ($server) = @_;
  my $ldap_base = "";
  my $ldap;
  unless($ldap = Net::LDAP->new($master_ref)) {
    print ("Unable to contact $c{ldap_master_url}: $!\n");
    return 1;
  }
  my $result;
  if ($c{ldap_master_url} !~ /^ldaps/i) {
    if ($c{ldap_starttls_supported}) {
      $result = $ldap->start_tls(
        verify => 'none',
        capath => "/opt/zextras/conf/ca",
        ) or die "start_tls: $@";
      $result->code && die "TLS: " . $result->error . "\n";
    }
  }
  $result = $ldap->bind($c{zimbra_ldap_userdn}, 
    password => $c{zimbra_ldap_password});
  if ($result->code()) {
    print("ldap bind failed for $c{zimbra_ldap_userdn}");
    return 1;
  } else {
    print("ldap bind done for $c{zimbra_ldap_userdn}\n") if ($verbose > 1);
    print("Updating zimbraMailHost attributes\n") if ($verbose > 1);
    $result = $ldap->search(base => $ldap_base,
      scope =>'sub',
      attrs => ['1.1'],
      filter => "(&(objectClass=zimbraAccount)(zimbraMailHost=$c{zimbra_server_hostname}))");
    return $result if ($result->code());
    foreach my $entry ($result->all_entries) {
      print "Updating zimbraMailHost for ", $entry->dn(), "...";
      $result = $ldap->modify(
        $entry->dn,
        replace => {zimbraMailHost => "$server"},
        );
      print ($result->code() ? "failed.\n" : "done.\n");
    }
    print("Updating zimbraMailTransport attribute\n") if ($verbose > 1);
    $result = $ldap->search(base => $ldap_base,
      scope =>'sub',
      attrs => ['zimbraMailTransport'],
      filter => "(&(objectClass=zimbraAccount)(zimbraMailTransport=*:$c{zimbra_server_hostname}:*))");
    return $result if ($result->code());
    foreach my $entry ($result->all_entries) {
      print "Updating zimbraMailTransport for ", $entry->dn(), "...";
      my $value=$entry->get_value("zimbraMailTransport");
      $value =~ s/$c{zimbra_server_hostname}/$server/g;
      $result = $ldap->modify(
        $entry->dn,
        replace => {zimbraMailTransport => "$value"},
        );
      print ($result->code() ? "failed.\n" : "done.\n");
    }
  }
  $result = $ldap->unbind;
  return 0;
}

sub modifyListData($) {
  my ($server) = @_;
  my $ldap_base = "";
  my $ldap;
  unless($ldap = Net::LDAP->new($master_ref)) {
    print ("Unable to contact $c{ldap_master_url}: $!\n");
    return 1;
  }
  my $result;
  if ($c{ldap_master_url} !~ /^ldaps/i) {
    if ($c{ldap_starttls_supported}) {
      $result = $ldap->start_tls(
        verify => 'none',
        capath => "/opt/zextras/conf/ca",
        ) or die "start_tls: $@";
      $result->code && die "TLS: " . $result->error . "\n";
    }
  }
  $result = $ldap->bind($c{zimbra_ldap_userdn}, 
    password => $c{zimbra_ldap_password});
  if ($result->code()) {
    print("ldap bind failed for $c{zimbra_ldap_userdn}");
    return 1;
  } else {
    print("ldap bind done for $c{zimbra_ldap_userdn}\n") if ($verbose > 1);
    print("Updating zimbraMailHost attribute for distribution lists\n") if ($verbose > 1);
    $result = $ldap->search(base => $ldap_base,
      scope =>'sub',
      attrs => ['1.1'],
      filter => "(&(objectClass=zimbraDistributionList)(zimbraMailHost=$c{zimbra_server_hostname}))");
    return $result if ($result->code());
    foreach my $entry ($result->all_entries) {
      print "Updating zimbraMailHost for ", $entry->dn(), "...";
      $result = $ldap->modify(
        $entry->dn,
        replace => {zimbraMailHost => "$server"},
        );
      print ($result->code() ? "failed.\n" : "done.\n");
    }
  }
  $result = $ldap->unbind;
  return 0;
}

sub updateLocalConfig($) {
  my ($key) = @_;
  my $tmpval = getLocalConfig($key);
  my $newval = $tmpval;
  $newval =~ s/$c{zimbra_server_hostname}/$newServerName/g;
  return if ($tmpval eq $newval);
  my $rc = setLocalConfig($key, $newval) ;
  return $tmpval if ($rc==0);
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

sub setLocalConfig {
  my $key = shift;
  my $val = shift;

  if (exists $saved{lc}{$key} && $saved{lc}{$key} eq $val) {
    return;
  }
  $saved{lc}{$key} = $val;
  $loaded{lc}{$key} = $val;
  print "Setting local config $key=$val\n";
  runCommand("$c{zmlocalconfig} -f -e ${key}=\'${val}\' 2> /dev/null");
}

sub setLdapServerConfig($$$) {
  my ($hn,$key,$val) = @_;
  return 
    if (exists $saved{gs}{$key} && $saved{gs}{$key} eq $val);
  if ($val eq "") {
      $val="\'\'";
  }
  $loaded{gs}{$key} = $val;
  $saved{gs}{$key} = $val;
  print "Setting server config $key=$val\n" if ($verbose > 0);
  runCommand("$c{zmprov} ms $hn $key $val");
}

sub removeLdapServerConfig($$$) {
  my ($hn,$key,$val) = @_;
  print "Removing server config $key=$val\n" if ($verbose > 0);
  runCommand("$c{zmprov} ms $hn -$key $val");
}

sub addLdapServerConfig($$$) {
  my ($hn,$key,$val) = @_;
  print "Adding server config $key=$val\n" if ($verbose > 0);
  runCommand("$c{zmprov} ms $hn +$key $val");
}

sub getLdapServerConfig($$) {
  my ($key,$hn) = @_;
  $hn = $c{zimbra_server_hostname} if ($hn eq ""); 
  my $val;
  return $loaded{gs}{$hn}{$key}
    if (exists $loaded{gs}{$hn}{$key});

  print "$loaded{gs}{$hn}{$key}\n";

  print "Running $c{zmprov} gs $hn\n" if ($verbose > 1);
  unless (open(ZMPROV, "$c{zmprov} gs $hn 2> /dev/null|")) {
    print "Failed to get server config for $hn.\n";
    return;
  }
  my @CONFIG = <ZMPROV>;
  unless (close(ZMPROV)) {
    print "Failed to get server config for $hn. $@\n";
    return;
  }

  while (scalar(@CONFIG) > 0)  {
    chomp(my $line = shift(@CONFIG));
    my ($k, $v) = $line =~ m/^(\w+):\s(.*)/;
    while ($CONFIG[0] !~ m/^\w+:\s.*/ && scalar(@CONFIG) > 0) {
      chomp($v .= shift(@CONFIG));
    }

    next if ($k =~ m/cn|objectClass/);
    $loaded{gs}{$hn}{$k} .= 
      (($loaded{gs}{$hn}{$k} eq "") ? "$v" : " $v");;
  }

  return $loaded{gs}{$hn}{$key};
}

sub setLdapGlobalConfig($$) {
  my ($key,$val) = @_;
  return 
    if (exists $saved{gcf}{$key} && $saved{gcf}{$key} eq $val);
  if ($val eq "") {
      $val="\'\'";
  }
  $loaded{gcf}{$key} = $val;
  $saved{gcf}{$key} = $val;
  print "Setting global config $key=$val\n" if ($verbose > 0);
  runCommand("$c{zmprov} mcf $key $val");
}

sub removeLdapGlobalConfig($$) {
  my ($key,$val) = @_;
  print "Removing global config $key=$val\n" if ($verbose > 0);
  runCommand("$c{zmprov} mcf -$key $val");
}

sub addLdapGlobalConfig($$) {
  my ($key,$val) = @_;
  print "Adding global config $key=$val\n" if ($verbose > 0);
  runCommand("$c{zmprov} mcf +$key $val");
}

sub getLdapGlobalConfig($) {
  my ($key) = @_;
  my ($val); 
  return $loaded{gcf}{$key}
    if (exists $loaded{gcf}{$key});

  print "Getting global config $key=";
  unless (open(ZMPROV, "$c{zmprov} gcf $key 2> /dev/null|")) {
    print "Failed to get global config key $key.\n";
    return;
  }
  my @CONFIG = <ZMPROV>;
  close(ZMPROV);

  while (scalar(@CONFIG) > 0)  {
    chomp(my $line = shift(@CONFIG));
    my ($k, $v) = $line =~ m/^(\w+):\s(.*)/;
    while ($CONFIG[0] !~ m/^\w+:\s.*/ && scalar(@CONFIG) > 0) {
      chomp($v .= shift(@CONFIG));
    }

    next if ($k =~ m/cn|objectClass/);
    $val .= (($val eq "") ? "$v" : " $v") if ($k eq $key);
    $loaded{gcf}{$k} .= 
      (($loaded{gcf}{$k} eq "") ? "$v" : " $v");;
  }
  print "$loaded{gcf}{$key}\n";
  return $loaded{gcf}{$key};
}

sub runCommand {
  my $cmd = shift;
  my $rc;
  $rc = 0xffff & system("$cmd > /dev/null 2>&1 ");
  return $rc;
}

sub isLdapRunning {
  if (index($c{ldap_url}, "/".$c{zimbra_server_hostname}) != -1) {
    my $isrunning = 0xffff & system("/opt/zextras/bin/ldap status > /dev/null 2>&1");
    return ($isrunning)?0:1;
  } 
}

sub startLdap {
  print "Starting ldap...";
  if (&isLdapRunning) {
    print "already running.\n";
    return;
  }
  $rc = runCommand("/opt/zextras/bin/ldap start");
  if ($rc==0) {
    print "done.\n";
  } else {
    print "failed.\n";
    exit 1;
  }
}
