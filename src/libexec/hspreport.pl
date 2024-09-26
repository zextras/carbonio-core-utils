#!/usr/bin/perl -w

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

use strict;
use English '-no_match_vars';
use FileHandle;
use Time::Local;
use POSIX qw(strftime);
use File::Basename;

use lib "/opt/zextras/common/lib/perl5";
use Net::LDAP;
use Net::LDAP::LDIF;
use Net::LDAP::Entry;
use Net::LDAP::Search;

use Getopt::Std;

sub usage () {
	my $cmd = basename($0);

	print "\n";
	print "Usage: $cmd [OPTION]\n";
	print "\n";
	print "   -v         verbose output\n";
	print "   -d         debug level output\n";
	print "   -h         give this help\n";
	print "\n"; 
	exit;
}

my %options=();
if ((! getopts('dvh', \%options)) || ($options{h})) {
	usage();
};

my $id = getpwuid($<);
chomp $id;
if ($id ne "zextras") {
    print STDERR "Error: must be run as zextras user\n";
    exit (1);
}

$FORMAT_LINES_PER_PAGE = 100;
$FORMAT_FORMFEED = "\n";

my $ldappass = qx(/opt/zextras/bin/zmlocalconfig -s -m nokey zimbra_ldap_password);
my $ldapdn  = qx(/opt/zextras/bin/zmlocalconfig -s -m nokey zimbra_ldap_userdn);
my $ldapurl  = qx(/opt/zextras/bin/zmlocalconfig -s -m nokey ldap_url);
chop($ldappass);
chop($ldapdn);
chop($ldapurl);

my $replica_ref= [ split(" ", $ldapurl) ];
my $ldap = Net::LDAP->new( $replica_ref ) or die "Error connecting to LDAP server: $ldapurl";
my $mesg = $ldap->bind( $ldapdn, password => $ldappass );

$mesg->code && die "Error binding to LDAP server: $mesg->error";


# Load COS information
my $ldapquery = "(objectclass=zimbraCOS)";

$mesg = $ldap->search(
					base => '',
					filter => $ldapquery,
					attrs => [
						'cn',
						'zimbraId',
						'description',
						'zimbraFeatureMobileSyncEnabled',
						'zimbraFeatureCalendarEnabled'
					]
				);

my $COSes = {};
my $default_COS_Id;

my $i;
for ($i = 0; $i < $mesg->count ; $i++) {
	my $entry = {};

	$entry->{'cn'} = $mesg->entry($i)->get_value('cn');
	$entry->{'zimbraId'} = $mesg->entry($i)->get_value('zimbraId');
	$entry->{'description'} = $mesg->entry($i)->get_value('description');
	$entry->{'zimbraFeatureMobileSyncEnabled'} = $mesg->entry($i)->get_value('zimbraFeatureMobileSyncEnabled');
	$entry->{'zimbraFeatureCalendarEnabled'} = $mesg->entry($i)->get_value('zimbraFeatureCalendarEnabled');
	
	if ( $entry->{'cn'} eq 'default' ) {
		$COSes->{$entry->{'zimbraId'}}->{'description'} = 'default';
		$default_COS_Id = $mesg->entry($i)->get_value('zimbraId');
	} else {
		if ( ! $COSes->{$entry->{'zimbraId'}} ) {
			$COSes->{$entry->{'zimbraId'}} = { stats => {}, accounts => {}, description => '', mobileEnabled => '', calEnabled =>'' };
		}
		$COSes->{$entry->{'zimbraId'}}->{'description'} = $entry->{'cn'};
	}
	if ( $entry->{'zimbraFeatureMobileSyncEnabled'} ) {
		$COSes->{$entry->{'zimbraId'}}->{'mobileEnabled'} = $entry->{'zimbraFeatureMobileSyncEnabled'};
	} else {
		$COSes->{$entry->{'zimbraId'}}->{'mobileEnabled'} = 'FALSE';
	}
	if ( $entry->{'zimbraFeatureCalendarEnabled'} ) {
		$COSes->{$entry->{'zimbraId'}}->{'calEnabled'} = $entry->{'zimbraFeatureCalendarEnabled'};
	} else {
		$COSes->{$entry->{'zimbraId'}}->{'calEnabled'} = 'FALSE';
	}
}

# Load domain information
$ldapquery = "(objectclass=zimbraDomain)";

$mesg = $ldap->search(
					base => '',
					filter => $ldapquery,
						attrs => [
							'zimbraId',
							'description',
							'zimbraDomainName',
							'zimbraDomainDefaultCOSId'
						]
					);

my $domain_list = {};

for ($i = 0 ; $i < $mesg->count ; $i++) {
	my $entry = {};

	$entry->{'zimbraId'} = $mesg->entry($i)->get_value('zimbraId');
	$entry->{'description'} = $mesg->entry($i)->get_value('description');
	$entry->{'zimbraDomainName'} = $mesg->entry($i)->get_value('zimbraDomainName');
	$entry->{'zimbraDomainDefaultCOSId'} = $mesg->entry($i)->get_value('zimbraDomainDefaultCOSId');

	if ( ! $domain_list->{$entry->{'zimbraDomainName'}} ) {
		$domain_list->{$entry->{'zimbraDomainName'}} = { zimbraId => $entry->{'zimbraId'}, stats => {}, accounts => {}, description => '', zimbraDomainDefaultCOSId => '', mobileEnabled => '', calEnabled => '' };
		my $COSId;
		if ( $entry->{'zimbraDomainDefaultCOSId'} && $COSes->{$entry->{'zimbraDomainDefaultCOSId'}} ) {
			$COSId = $entry->{'zimbraDomainDefaultCOSId'};
		} else {
			$COSId = $default_COS_Id;
		}
		if ( $COSes->{$COSId}->{'mobileEnabled'} eq 'TRUE' ) {
			$domain_list->{$entry->{'zimbraDomainName'}}->{'mobileEnabled'} = 'TRUE';
		} else {
			$domain_list->{$entry->{'zimbraDomainName'}}->{'mobileEnabled'} = 'FALSE';
		}
		if ( $COSes->{$COSId}->{'calEnabled'} eq 'TRUE' ) {
			$domain_list->{$entry->{'zimbraDomainName'}}->{'calEnabled'} = 'TRUE';
		} else {
			$domain_list->{$entry->{'zimbraDomainName'}}->{'calEnabled'} = 'FALSE';
		}
		$domain_list->{$entry->{'zimbraDomainName'}}->{'zimbraDomainDefaultCOSId'} = $COSId;
	}
}


# Load account information

$ldapquery = "(&(objectclass=zimbraAccount)(!(|(objectclass=zimbraCalendarResource)(zimbraIsSystemResource=TRUE))))";

$mesg = $ldap->search(
					base => '',
					filter => $ldapquery,
					attrs => [
						'zimbraMailDeliveryAddress',
						'displayName',
						'zimbraAccountStatus',
						'createTimestamp',
						'zimbraLastLogonTimestamp',
						'zimbraCOSId',
						'zimbraFeatureMobileSyncEnabled',
						'zimbraFeatureCalendarEnabled'
					]
				);

for ($i = 0 ; $i < $mesg->count ; $i++) {
	my $entry = {};

    $entry->{'zimbraMailDeliveryAddress'} = $mesg->entry($i)->get_value('zimbraMailDeliveryAddress');
    $entry->{'displayName'} = $mesg->entry($i)->get_value('displayName');
    $entry->{'zimbraAccountStatus'} = $mesg->entry($i)->get_value('zimbraAccountStatus');
    $entry->{'createTimestamp'} = $mesg->entry($i)->get_value('createTimestamp');
    $entry->{'zimbraLastLoginTimestamp'} = $mesg->entry($i)->get_value('zimbraLastLoginTimestamp');
    $entry->{'zimbraCOSId'} = $mesg->entry($i)->get_value('zimbraCOSId');
    $entry->{'zimbraFeatureMobileSyncEnabled'} = $mesg->entry($i)->get_value('zimbraFeatureMobileSyncEnabled');
    $entry->{'zimbraFeatureCalendarEnabled'} = $mesg->entry($i)->get_value('zimbraFeatureCalendarEnabled');

	if ($entry->{'zimbraMailDeliveryAddress'}) {
		my($local, $domain) = split /@/, $entry->{'zimbraMailDeliveryAddress'};

		# Determine appropriate COS for account
		my $COSId = $default_COS_Id;
		if ($entry->{'zimbraCOSId'}) {
			$COSId = $entry->{'zimbraCOSId'};
		} elsif ($domain_list->{$domain}->{'zimbraDomainDefaultCOSId'}) {
			$COSId = $domain_list->{$domain}->{'zimbraDomainDefaultCOSId'};
		}

		# Record COS statistics
		my $cd = $COSes->{$COSId};
		if (!$cd) {
			$cd = $COSes->{$COSId} = { stats => {}, accounts => {}, description => '(none)', mobileEnabled => '', calEnabled => ''};
		}
		$cd->{'stats'}->{'total'}++;
		$cd->{'stats'}->{$entry->{'zimbraAccountStatus'}}++;
		my $account_name = "$domain\@$local";
		$cd->{'accounts'}->{$account_name} = $entry;

		# Record domain statistics
		my $dd = $domain_list->{$domain};
		if (!$dd) {
			# Uh, oh!  We should NEVER get to this secton of code!
			$dd = $domain_list->{$domain} = { zimbraId => '(unknown)', stats => {}, accounts => {}, description => '', zimbraDomainDefaultCOSId => '', mobileEnabled => '', calEnabled => '' };
		}
		$dd->{'stats'}->{'total'}++;
		$dd->{'stats'}->{$entry->{'zimbraAccountStatus'}}++;

		if ( $entry->{'zimbraFeatureMobileSyncEnabled'} ) {
			if ( $entry->{'zimbraFeatureMobileSyncEnabled'} eq 'TRUE') {
				$cd->{'accounts'}->{$account_name}->{'zimbraFeatureMobileSyncEnabled'} = 'TRUE';
				$cd->{'stats'}->{'zimbraFeatureMobileSyncEnabled'}++;
				$dd->{'stats'}->{'zimbraFeatureMobileSyncEnabled'}++;
			}
		} elsif ( $domain_list->{$domain}->{'mobileEnabled'} eq 'TRUE' ) {
			$cd->{'accounts'}->{$account_name}->{'zimbraFeatureMobileSyncEnabled'} = 'TRUE';
			$cd->{'stats'}->{'zimbraFeatureMobileSyncEnabled'}++;
			$dd->{'stats'}->{'zimbraFeatureMobileSyncEnabled'}++;
			# Explicit COSId overrides the domain level setting
			if ( $cd->{'mobileEnabled'} eq 'FALSE' ) {
				$cd->{'accounts'}->{$account_name}->{'zimbraFeatureMobileSyncEnabled'} = 'FALSE';
				$cd->{'stats'}->{'zimbraFeatureMobileSyncEnabled'}++;
				$dd->{'stats'}->{'zimbraFeatureMobileSyncEnabled'}++;
			}
		}

		if ( $entry->{'zimbraFeatureCalendarEnabled'} ) {
			if ( $entry->{'zimbraFeatureCalendarEnabled'} eq 'TRUE') {
				$cd->{'accounts'}->{$account_name}->{'zimbraFeatureCalendarEnabled'} = 'TRUE';
				$cd->{'stats'}->{'zimbraFeatureCalendarEnabled'}++;
				$dd->{'stats'}->{'zimbraFeatureCalendarEnabled'}++;
			}
		} elsif ( $domain_list->{$domain}->{'calEnabled'} eq 'TRUE' ) {
			$cd->{'accounts'}->{$account_name}->{'zimbraFeatureCalendarEnabled'} = 'TRUE';
			$cd->{'stats'}->{'zimbraFeatureCalendarEnabled'}++;
			$dd->{'stats'}->{'zimbraFeatureCalendarEnabled'}++;
			# Explicit COSId overrides the domain level setting
			if ( $cd->{'calEnabled'} eq 'FALSE' ) {
				$cd->{'accounts'}->{$account_name}->{'zimbraFeatureCalendarEnabled'} = 'FALSE';
				$cd->{'stats'}->{'zimbraFeatureCalendarEnabled'}++;
				$dd->{'stats'}->{'zimbraFeatureCalendarEnabled'}++;
			}
		}
	}
}


my ($COSId, $COSName);
if ( $options{d} ) {

	my ($name, $dname, $status, $created, $logon, $zimbraMobile, $calendar);
format ACCOUNT_TOP = 

		       COS:  @<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<  @<<<<<<<<<<<<<<<<<<<<
$COSId, $COSName

                account                                 user name                status        created         last logon      mobile     cal
-----------------------------------------  ----------------------------------  -----------  ---------------  ---------------  --------  -------
.

format ACCOUNT = 
@<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<  @<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<  @<<<<<<<<<<  @<<<<<<<<<<<<<<  @<<<<<<<<<<<<<<  @<<<<<<<  @<<<<<<
$name, $dname, $status, $created, $logon, $zimbraMobile, $calendar
.

	format_name     STDOUT "ACCOUNT";
	format_top_name STDOUT "ACCOUNT_TOP";

	my $ctime = time();
	foreach $COSId (sort keys %$COSes) {

		my $cd = $COSes->{$COSId};
		my $accounts = $cd->{'accounts'};

		$COSName = $cd->{'description'} || 'unknown';
		foreach my $account (sort keys %$accounts) {
			my $entry = $accounts->{$account};

			my ($domain, $local) = split /@/, $account;
			$name = "$local\@$domain";
			$dname = $entry->{'displayName'} || '';
			$status = $entry->{'zimbraAccountStatus'};
			$created = $entry->{'createTimestamp'};
			$logon = $entry->{'zimbraLastLogonTimestamp'} || 'never';
			$zimbraMobile = $entry->{'zimbraFeatureMobileSyncEnabled'} || '';
			$calendar = $entry->{'zimbraFeatureCalendarEnabled'} || '';

			if ($created =~ /(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z/) {
				my $time = timegm($6, $5, $4, $3, $2-1, $1);
				$created = strftime("%D %H:%M", localtime($time));
			}
			if ($logon =~ /(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z/) {
				my $time = timegm($6, $5, $4, $3, $2-1, $1);
				$logon = strftime("%D %H:%M", localtime($time));
			}

		write;
		}
		$FORMAT_LINES_LEFT = 0;
	}

	$FORMAT_LINES_LEFT = 0;
}


if ($options{v} || $options{d}) {
	my ($numActive, $numLockout, $numLocked, $numMaint, $numPending, $numClosed, $numTotal, $numMobile, $numCal);
	my ($totActive, $totLockout, $totLocked, $totMaint, $totPending, $totClosed, $totTotal, $totMobile, $totCal);

format vCOS_TOP =

                                         COS Summary

            COS Name                          COS ID                         Active    Lockout    Locked    Maintenance    Pending    Closed    Total    Mobile     Cal
------------------------------------  ------------------------------------  --------  ---------  --------  -------------  ---------  --------  --------  -------  -------
.

format vCOS =
@<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<  @<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<  @>>>>>>>  @>>>>>>>>  @>>>>>>>  @>>>>>>>>>>>>  @>>>>>>>>  @>>>>>>>  @>>>>>>>  @>>>>>>  @>>>>>>
$COSName, $COSId, $numActive, $numLockout, $numLocked, $numMaint, $numPending, $numClosed, $numTotal, $numMobile, $numCal
.

format vCOS_TOTAL =
------------------------------------  ------------------------------------  --------  ---------  --------  -------------  ---------  --------  --------  -------  -------
                                                             Grand Totals:  @>>>>>>>  @>>>>>>>>  @>>>>>>>  @>>>>>>>>>>>>  @>>>>>>>>  @>>>>>>>  @>>>>>>>  @>>>>>>  @>>>>>>
$totActive, $totLockout, $totLocked, $totMaint, $totPending, $totClosed, $totTotal, $totMobile, $totCal
.

format COS_TOP =

                                         COS Summary

        COS ID                         Active    Lockout    Locked    Maintenance    Pending    Closed    Total    Mobile     Cal
------------------------------------  --------  ---------  --------  -------------  ---------  --------  --------  -------  -------
.

format COS =
@<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<  @>>>>>>>  @>>>>>>>>  @>>>>>>>  @>>>>>>>>>>>>  @>>>>>>>>  @>>>>>>>  @>>>>>>>  @>>>>>>  @>>>>>>
$COSId, $numActive, $numLockout, $numLocked, $numMaint, $numPending, $numClosed, $numTotal, $numMobile, $numCal
.

format COS_TOTAL =
------------------------------------  --------  ---------  --------  -------------  ---------  --------  --------  -------  -------
                       Grand Totals:  @>>>>>>>  @>>>>>>>>  @>>>>>>>  @>>>>>>>>>>>>  @>>>>>>>>  @>>>>>>>  @>>>>>>>  @>>>>>>  @>>>>>>
$totActive, $totLockout, $totLocked, $totMaint, $totPending, $totClosed, $totTotal, $totMobile, $totCal
.

									    
if ( $options{d} ) {
	format_top_name STDOUT "vCOS_TOP";
	format_name     STDOUT "vCOS";
} else {
    format_top_name STDOUT "COS_TOP";
    format_name     STDOUT "COS";
}

	$totActive = $totLockout = $totLocked = $totMaint = $totPending = $totClosed = $totTotal = $totMobile = $totCal = 0;
	foreach $COSId (sort keys %$COSes) {
		my $cd = $COSes->{$COSId};
		my $stats = $cd->{'stats'};
		$COSName = $cd->{'description'};
		$numActive = $stats->{'active'} || 0;
		$numLockout = $stats->{'lockout'} || 0;
		$numLocked = $stats->{'locked'} || 0;
		$numMaint = $stats->{'maintenance'} || 0;
		$numPending = $stats->{'pending'} || 0;
		$numClosed = $stats->{'closed'} || 0;
		$numTotal = $stats->{'total'} || 0;
		$numMobile = $stats->{'zimbraFeatureMobileSyncEnabled'} || 0;
		$numCal = $stats->{'zimbraFeatureCalendarEnabled'} || 0;
		write;
		$totActive += $numActive;
		$totLocked += $numLocked;
		$totLockout += $numLockout;
		$totMaint += $numMaint;
		$totPending += $numPending;
		$totClosed += $numClosed;
		$totTotal += $numTotal;
		$totMobile += $numMobile;
		$totCal += $numCal;
	}

	if ( $options{d} ) {
		format_name		STDOUT "vCOS_TOTAL";
	} else {
		format_name		STDOUT "COS_TOTAL";
	}
	write;

	$FORMAT_LINES_LEFT = 0;


	my ($DomainName, $DomainId);
format vDOMAIN_TOP =

                                         Domain Summary

            Domain Name                          Domain ID                   Active    Lockout    Locked    Maintenance    Pending    Closed    Total    Mobile     Cal
------------------------------------  ------------------------------------  --------  ---------  --------  -------------  ---------  --------  --------  -------  -------
.

format vDOMAIN =
@<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<  @<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<  @>>>>>>>  @>>>>>>>>  @>>>>>>>  @>>>>>>>>>>>>  @>>>>>>>>  @>>>>>>>  @>>>>>>>  @>>>>>>  @>>>>>>
$DomainName, $DomainId, $numActive, $numLockout, $numLocked, $numMaint, $numPending, $numClosed, $numTotal, $numMobile, $numCal
.

format vDOMAIN_TOT =
------------------------------------  ------------------------------------  --------  ---------  --------  -------------  ---------  --------  --------  -------  -------
                                                             Grand Totals:  @>>>>>>>  @>>>>>>>>  @>>>>>>>  @>>>>>>>>>>>>  @>>>>>>>>  @>>>>>>>  @>>>>>>>  @>>>>>>  @>>>>>>
$totActive, $totLockout, $totLocked, $totMaint, $totPending, $totClosed, $totTotal, $totMobile, $totCal
.

format DOMAIN_TOP =

                                         Domain Summary

           Domain ID                   Active    Lockout    Locked    Maintenance    Pending    Closed    Total    Mobile     Cal
------------------------------------  --------  ---------  --------  -------------  ---------  --------  --------  -------  -------
.

format DOMAIN =
@<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<  @>>>>>>>  @>>>>>>>>  @>>>>>>>  @>>>>>>>>>>>>  @>>>>>>>>  @>>>>>>>  @>>>>>>>  @>>>>>>  @>>>>>>
$DomainId, $numActive, $numLockout, $numLocked, $numMaint, $numPending, $numClosed, $numTotal, $numMobile, $numCal
.

format DOMAIN_TOT =
------------------------------------  --------  ---------  --------  -------------  ---------  --------  --------  -------  -------
                       Grand Totals:  @>>>>>>>  @>>>>>>>>  @>>>>>>>  @>>>>>>>>>>>>  @>>>>>>>>  @>>>>>>>  @>>>>>>>  @>>>>>>  @>>>>>>
$totActive, $totLockout, $totLocked, $totMaint, $totPending, $totClosed, $totTotal, $totMobile, $totCal
.

if ( $options{d} ) {
	format_top_name STDOUT "vDOMAIN_TOP";
	format_name     STDOUT "vDOMAIN";
} else {
	format_top_name STDOUT "DOMAIN_TOP";
	format_name     STDOUT "DOMAIN";
}


	$totActive = $totLockout = $totLocked = $totMaint = $totPending = $totClosed = $totTotal = $totMobile = $totCal = 0;
	foreach $DomainName (sort keys %$domain_list) {
		my $dd = $domain_list->{$DomainName};
		my $stats = $dd->{'stats'};
		$DomainId = $dd->{'zimbraId'};
		$numActive = $stats->{'active'} || 0;
		$numLockout = $stats->{'lockout'} || 0;
		$numLocked = $stats->{'locked'} || 0;
		$numMaint = $stats->{'maintenance'} || 0;
		$numPending = $stats->{'pending'} || 0;
		$numClosed = $stats->{'closed'} || 0;
		$numTotal = $stats->{'total'} || 0;
		$numMobile = $stats->{'zimbraFeatureMobileSyncEnabled'} || 0;
		$numCal = $stats->{'zimbraFeatureCalendarEnabled'} || 0;
		write;
		$totActive += $numActive;
		$totLockout += $numLockout;
		$totLocked += $numLocked;
		$totMaint += $numMaint;
		$totPending += $numPending;
		$totClosed += $numClosed;
		$totTotal += $numTotal;
		$totMobile += $numMobile;
		$totCal += $numCal;
	}

	if ( $options{d} ) {
		format_name     STDOUT "vDOMAIN_TOT";
	} else {
		format_name     STDOUT "DOMAIN_TOT";
	}
	write;
	$FORMAT_LINES_LEFT = 0;

	print "\n";
 	print "    Calendar Month:  " . ((localtime(time))[4] + 1) . "/" . ((localtime(time))[5] + 1900) . "\n";
	print "    Standard Users:  " . ( $totTotal - $totMobile ) . "\n";
	print "Professional Users:  " . $totMobile . "\n";
	print "     Total Domains:  " . keys (%$domain_list) . "\n";
	print "\n";

} else {
	my ($numActive, $numLockout, $numLocked, $numMaint, $numPending, $numClosed, $numTotal, $numMobile, $numCal);
	my ($totActive, $totLockout, $totLocked, $totMaint, $totPending, $totClosed, $totTotal, $totMobile, $totCal);
	my $DomainName;

	foreach $DomainName (sort keys %$domain_list) {
		my $dd = $domain_list->{$DomainName};
		my $stats = $dd->{'stats'};
		$totTotal += $stats->{'total'} || 0;
		$totMobile += $stats->{'zimbraFeatureMobileSyncEnabled'} || 0;
	}
	print "\n\n";
 	print "    Calendar Month:  " . ((localtime(time))[4] + 1) . "/" . ((localtime(time))[5] + 1900) . "\n";
	print "    Standard Users:  " . ( $totTotal - $totMobile ) . "\n";
	print "Professional Users:  " . $totMobile . "\n";
	print "     Total Domains:  " . keys (%$domain_list) . "\n";
}

print "\n";

