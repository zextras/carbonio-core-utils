#!/usr/bin/perl -w

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

# revised 20090402

use strict;
use lib "/opt/zextras/common/lib/perl5";
use Getopt::Long;
use Net::LDAP;
use Zextras::Mon::Stat;
use Data::Dumper;

zmstatInit();

my ($CONSOLE, $LOGFH, $LOGFILE, $HEADING, $ROTATE_DEFER, $ROTATE_NOW);
my $SEEN_ERROR = 0;

my %attrs = (
    'read_waiters'   => { dn => 'cn=Read,cn=Waiters,cn=Monitor', attr => 'monitorCounter' },
    'write_waiters'  => { dn => 'cn=Write,cn=Waiters,cn=Monitor', attr => 'monitorCounter' },
    'connections'    => { dn => 'cn=Total,cn=Connections,cn=Monitor', attr => 'monitorCounter', delta => 1 },
    'bytes_sent'     => { dn => 'cn=Bytes,cn=Statistics,cn=Monitor', attr => 'monitorCounter', delta => 1 },
    'entries_sent'   => { dn => 'cn=Entries,cn=Statistics,cn=Monitor', attr => 'monitorCounter', delta => 1 },
    'referrals_sent' => { dn => 'cn=Referrals,cn=Statistics,cn=Monitor', attr => 'monitorCounter', delta => 1 },
    'initiated_ops'  => { dn => 'cn=Operations,cn=Monitor', attr => 'monitorOpInitiated', delta => 1 },
    'completed_ops'  => { dn => 'cn=Operations,cn=Monitor', attr => 'monitorOpCompleted', delta => 1 },
    'bind_ops'       => { dn => 'cn=Bind,cn=Operations,cn=Monitor', attr => 'monitorOpCompleted', delta => 1 },
    'unbind_ops'     => { dn => 'cn=Unbind,cn=Operations,cn=Monitor', attr => 'monitorOpCompleted', delta => 1 },
    'add_ops'        => { dn => 'cn=Add,cn=Operations,cn=Monitor', attr => 'monitorOpCompleted', delta => 1 },
    'delete_ops'     => { dn => 'cn=Delete,cn=Operations,cn=Monitor', attr => 'monitorOpCompleted', delta => 1 },
    'modify_ops'     => { dn => 'cn=Modify,cn=Operations,cn=Monitor', attr => 'monitorOpCompleted', delta => 1 },
    'modrdn_ops'     => { dn => 'cn=Modrdn,cn=Operations,cn=Monitor', attr => 'monitorOpCompleted', delta => 1 },
    'compare_ops'    => { dn => 'cn=Compare,cn=Operations,cn=Monitor', attr => 'monitorOpCompleted', delta => 1 },
    'search_ops'     => { dn => 'cn=Search,cn=Operations,cn=Monitor', attr => 'monitorOpCompleted', delta => 1 },
    'abandon_ops'    => { dn => 'cn=Abandon,cn=Operations,cn=Monitor', attr => 'monitorOpCompleted', delta => 1 },
    'extended_ops'   => { dn => 'cn=Extended,cn=Operations,cn=Monitor', attr => 'monitorOpCompleted', delta => 1 }
);

my @attrList = sort keys %attrs;

sub getHeading() {
    return join(', ', 'timestamp', @attrList);
}

sub logError($) {
    my $msg = shift;

    print STDERR getTstamp() . ": ERROR: $msg\n";

    foreach my $val (values %attrs) { delete $val->{prev} }
    $SEEN_ERROR=1;

}

sub usage() {
    print STDERR <<_USAGE_;
Usage: zmstat-ldap [options]
Monitor LDAP statistics
-i, --interval: output a line every N seconds
-l, --log:      log file (default is /opt/zextras/zmstat/slapd.csv)
-c, --console:  output to stdout

If logging to a file, rotation occurs when HUP signal is sent or when
date changes.  Current log is renamed to <dir>/YYYY-MM-DD/slapd.csv
and a new file is created.
_USAGE_
    exit(1);
}

sub sighup {
    if (!$CONSOLE) {
        if (!$ROTATE_DEFER) {
            $LOGFH = rotateLogFile($LOGFH, $LOGFILE, $HEADING);
        } else {
            $ROTATE_NOW = 1;
                }
    }
}

sub getZimbraLdapPassword() {
    my $pass = qx(zmlocalconfig -m nokey -s zimbra_ldap_password);
    chomp $pass;
    return $pass;
}

sub getZextrasUserDN() {
    my $userdn = qx(zmlocalconfig -m nokey -s zimbra_ldap_userdn);
    chomp $userdn;
    return $userdn;
}

#
# main
#

$| = 1; # Flush immediately

my $interval = getZmstatInterval();

my $opts_good = GetOptions(
    'interval=i' => \$interval,
    'log=s' => \$LOGFILE,
    'console' => \$CONSOLE,
);
if (!$opts_good) {
    print STDERR "\n";
    usage();
}

if (!defined($LOGFILE) || $LOGFILE eq '') {
    $LOGFILE = getLogFilePath('slapd.csv');
} elsif ($LOGFILE eq '-') {
    $CONSOLE = 1;
}
if ($CONSOLE) {
    $LOGFILE = '-';
}

createPidFile('ldap.pid');

$SIG{HUP} = \&sighup;

$HEADING = getHeading();
$LOGFH = openLogFile($LOGFILE, $HEADING);

my $date = getDate();
my $hostname = getZimbraServerHostname();
my $password = getZimbraLdapPassword();
my $user = getZextrasUserDN();

waitUntilNiceRoundSecond($interval);
while (1) {
    my @out;

    my $ldap = Net::LDAP->new('ldapi://%2frun%2fcarbonio%2frun%2fldapi/');
    unless (defined $ldap) {
        $SEEN_ERROR or logError("Could not connect to LDAP server: $hostname");
	sleep($interval);
        next;
    }
    unless ($ldap->bind("$user", password => $password ) ) {
        $SEEN_ERROR or logError("Could not bind to LDAP server: $hostname");
	sleep($interval);
        next;
    }

    $SEEN_ERROR=0;

    foreach my $key (@attrList) {
        my $out; 
        my $val = $attrs{$key};

        my $mesg = $ldap->search(
            base   => $val->{dn},
            filter => '(objectClass=*)',
            attrs  => [ $val->{attr} ],
        );

        print "val dn: ".$val->{dn}."\n";
        print "Retrieving attr: ".$val->{attr}."\n";

        $val->{curr} = $mesg->pop_entry->get_value($val->{attr});

        if ($val->{delta}) {
            $out = defined $val->{prev} ? ($val->{curr} - $val->{prev}) : ''; 
            $val->{prev} = $val->{curr}
        } else {
            $out = $val->{curr}
        }    
        push @out, $out;
    }

    $ldap->unbind;

    my $tstamp = getTstamp();
    my $currDate = getDate();
    if ($currDate ne $date) {
        $LOGFH = rotateLogFile($LOGFH, $LOGFILE, $HEADING, $date);
        $date = $currDate;
    }

    # Don't allow rotation in signal handler while we're writing.
    $ROTATE_DEFER = 1;
    $LOGFH->print(join(", ", $tstamp, @out) . "\n");
    $LOGFH->flush();
    $ROTATE_DEFER = 0;
    if ($ROTATE_NOW) {
        # Signal handler delegated rotation to main.
        $ROTATE_NOW = 0;
        $LOGFH = rotateLogFile($LOGFH, $LOGFILE, $HEADING);
    }

    sleep($interval);
}
