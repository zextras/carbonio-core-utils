#!/usr/bin/perl

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

use strict;
use lib '/opt/zextras/common/lib/perl5';
use Sys::Syslog qw(:DEFAULT setlogsock);
use Net::LDAPapi;
use XML::Simple;

#
# Syslogging options for verbose mode and for fatal errors.
# NOTE: comment out the $syslog_socktype line if syslogging does not
# work on your system.
#
my $syslog_socktype = 'unix';
my $syslog_facility="mail";
my $syslog_options="pid";
our $syslog_priority="info";
our ($verbose, %attr, @ldap_url, $ldap_starttls_supported, $postfix_pw);
my ($option, $action, $ldap_url, @val);

$ENV{'HOME'}='/opt/zextras';
setlogsock $syslog_socktype;
openlog $0, $syslog_options, $syslog_facility;

my $localxml = XMLin("/opt/zextras/conf/localconfig.xml");

$ldap_starttls_supported = $localxml->{key}->{ldap_starttls_supported}->{value};
chomp ($ldap_starttls_supported);
$postfix_pw = $localxml->{key}->{ldap_postfix_password}->{value};
chomp($postfix_pw);
$ldap_url = $localxml->{key}->{ldap_url}->{value};
chomp($ldap_url);
@ldap_url = split / /, $ldap_url;

sub smtpd_access_policy {
  my($domain, $ldap, $mesg, $user, $daddr, @attrs, $result);
  $daddr = lc $attr{recipient};
  ($user, $domain) = split /\@/, lc $attr{recipient};
  syslog $syslog_priority, "Recipient Domain: %s", $domain if $verbose;
  syslog $syslog_priority, "Recipient userid: %s", $user if $verbose;
  foreach my $url (@ldap_url) {
    $ldap=Net::LDAPapi->new(-url=>$url);
    if ( $ldap_starttls_supported ) {
      $mesg = $ldap->start_tls_s();
	  if ($mesg != 0) {
	    next;
	  }
    }
    $mesg = $ldap->bind_s("uid=zmpostfix,cn=appaccts,cn=zimbra",$postfix_pw);
	if ($mesg != 0) {
	  next;
	} else {
	  last;
	}
  }
  if ($mesg != 0) {
     syslog $syslog_priority, "Error: zmpostfixpolicyd unable to find working LDAP server";
	 return "dunno";
  }
  @attrs=('zimbraDomainType', 'zimbraMailCatchAllForwardingAddress');
  $mesg = $ldap->search_s(
            "",
            LDAP_SCOPE_SUBTREE,
            "(&(zimbraDomainName=$domain)(objectClass=zimbraDomain))",
            \@attrs,
            0,
            $result
          );
  my $ent = $ldap->first_entry();
  if ($ent != 0) {
    if (lc(($ldap->get_values("zimbraDomainType"))[0]) eq "alias") {
      my $robject = ($ldap->get_values("zimbraMailCatchAllForwardingAddress"))[0];
      syslog $syslog_priority, "Real Domain: %s", $robject if $verbose;
      @attrs=('1.1');
      $mesg = $ldap->search_s(
                "",
                LDAP_SCOPE_SUBTREE,
                "(&(|(zimbraMailDeliveryAddress=$user"."$robject)(zimbraMailDeliveryAddress=$daddr)(zimbraMailAlias=$user".
                "$robject)(zimbraMailAlias=$daddr)(zimbraMailCatchAllAddress=$user"."$robject)(zimbraMailCatchAllAddress=$robject)".
		"(zimbraMailCatchAllAddress=$daddr))(zimbraMailStatus=enabled))",
                \@attrs,
                0,
                $result
              );
      $ent = $ldap->first_entry();
      $ldap->unbind;
      if ($ent != 0) {
        return "dunno";
      } else { 
        return "reject 5.1.1 Mailbox unavailable";
      }
    } else {
      $ldap->unbind;
      return "dunno"; 
    }
  }
  $ldap->unbind;
  return "dunno";
}

#
# Log an error and abort.
#
sub fatal_exit {
    my($first) = shift(@_);
    syslog "err", "fatal: $first", @_;
    exit 1;
}

#
# We don't need getopt() for now.
#
while ($option = shift(@ARGV)) {
    if ($option eq "-v") {
        $verbose = 1;
    } else {
        syslog $syslog_priority, "Invalid option: %s. Usage: %s [-v]",
                $option, $0;
        exit 1;
    }
}

#
# Unbuffer standard output.
#
select((select(STDOUT), $| = 1)[0]);

#
# Receive a bunch of attributes, evaluate the policy, send the result.
#
while (<STDIN>) {
    if (/([^=]+)=(.*)\n/) {
        $attr{substr($1, 0, 512)} = substr($2, 0, 512);
    } elsif ($_ eq "\n") {
        if ($verbose) {
            for (keys %attr) {
                syslog $syslog_priority, "Attribute: %s=%s", $_, $attr{$_};
            }
        }
        fatal_exit "unrecognized request type: '%s'", $attr{"request"}
            unless $attr{"request"} eq "smtpd_access_policy";
        $action = smtpd_access_policy();
        syslog $syslog_priority, "Action: %s", $action if $verbose;
        print STDOUT "action=$action\n\n";
        %attr = ();
    } else {
        chop;
        syslog $syslog_priority, "warning: ignoring garbage: %.100s", $_;
    }
}
