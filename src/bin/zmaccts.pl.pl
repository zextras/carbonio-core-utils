#!/usr/bin/perl

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

=head1 NAME

zmaccts - lists accounts and report status of accounts per domain

=head1 SYNOPSIS

Usage: zmaccts [options]

  Options:
    --help                 this help message

This command generates a report that lists all accounts, their status,
creation date and last logon time.  The report also includes a domain
summary showing the total number of accounts and their status per
domain.

=cut

use strict;
use warnings;
use File::Basename qw(basename);
use Getopt::Long qw(GetOptions);
use IO::File qw();
use IPC::Open3 qw(open3);
use Net::LDAP qw();
use Net::LDAP::Control::Paged qw();
use Net::LDAP::Constant qw(LDAP_CONTROL_PAGED);
use Pod::Usage qw(pod2usage);
use POSIX qw(strftime);
use Symbol qw(gensym);
use Time::Local qw(timegm);

use constant {
    ZMLOCALCONFIG => "/opt/zextras/bin/zmlocalconfig",
    LDAP_TIMEOUT  => 60,
    LDAP_PAGESIZE => 1000,
    ZACCT_FILTER =>
      "(&(objectclass=zimbraAccount)(!(objectclass=zimbraCalendarResource)))",
    ZACCT_ATTRS => [
        qw(zimbraMailDeliveryAddress zimbraAccountStatus createTimestamp zimbraLastLogonTimestamp)
    ],
};

my $Prog = basename($0);
my $conf = zmlocalconfig(
    qw(zimbra_ldap_password zimbra_ldap_userdn ldap_url ldap_starttls_supported)
);

{    # support a help option
    my %Opt;
    GetOptions( \%Opt, "help" )
      or pod2usage( -exitval => 2 );

    pod2usage( -exitval => 1, -verbose => 0 ) if ( $Opt{help} );
}

# ldap_url may have multiple uri's separated by spaces
my $ldap_url = $conf->{ldap_url};
my $replica_ref=[ split(" ", $ldap_url) ];

# connect to LDAP server
my $ldap = Net::LDAP->new(
    $replica_ref,
    timeout => LDAP_TIMEOUT,
    async   => 1,
) or fatal("connect to '$ldap_url' failed: $@");

# start TLS if supported
if ( $ldap_url !~ /^ldaps:/ and $conf->{ldap_starttls_supported} ) {
    $ldap->start_tls( verify => "none" )
      or fatal("start_tls to '$ldap_url' failed: $@");
}

my $mesg = $ldap->bind( $conf->{zimbra_ldap_userdn},
    password => $conf->{zimbra_ldap_password} )
  or fatal("bind failed\n");
fatal( "failed to bind to server: ", emesg($mesg) )
  if $mesg->code;

# do a (paged) search
my $cookie;
my $page = Net::LDAP::Control::Paged->new( size => LDAP_PAGESIZE );
my @args = (
    base     => "",
    scope    => "sub",
    filter   => ZACCT_FILTER,
    attrs    => ZACCT_ATTRS,
    callback => accountCallback(),
    control  => [$page],
);

while (1) {
    $mesg = $ldap->search(@args);
    last if $mesg->code;    # only continue on LDAP_SUCCESS

    # get cookie from paged control
    my ($resp) = $mesg->control(LDAP_CONTROL_PAGED) or last;
    $cookie = $resp->cookie or last;

    # set cookie in paged control
    $page->cookie($cookie);
}

# abnormal exit if cookie is set, let the server know we are done
if ($cookie) {
    $page->cookie($cookie);
    $page->size(0);
    $ldap->search(@args);
}

# Check for errors
fatal( "search unsuccessful: ", emesg($mesg) )
  if ( $mesg->code );

$mesg = $ldap->unbind();
fatal( "error in unbind from server: ", emesg($mesg) )
  if $mesg->code;

my $domains = getData();

# generate reports...

# column widths and separators
my @w = ( 36, 11, 15, 15 );
my @s = ( map( " " x $_, 3, 5, 2 ), "\n" );

# col 0 left aligned, others right aligned, all strings truncate at max length
my @f = ( "%-$w[0].$w[0]s", $s[0], map( "%$w[$_].$w[$_]s$s[$_]", 1 .. $#w ) );
my $fmt = join( "", @f );

foreach my $domainName ( sort keys %$domains ) {
    my $dd       = $domains->{$domainName};
    my $accounts = $dd->{'accounts'};

    printf( $fmt, ( " " x 11 ) . "account", "status", "created", "last logon" );
    printf( $fmt, map( "-" x $_, @w ) );

    foreach my $account ( sort keys %$accounts ) {
        my $entry   = $accounts->{$account};
        my $name    = "$account\@$domainName";
        my $status  = $entry->{'zimbraAccountStatus'};
        my $created = $entry->{'createTimestamp'};
        my $logon   = $entry->{'zimbraLastLogonTimestamp'} || 'never';

        if ( $created =~ /(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z/ ) {
            my $time = timegm( $6, $5, $4, $3, $2 - 1, $1 );
            $created = strftime( "%D %H:%M", localtime($time) );
        }
        if ( $logon =~ /(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z/ ) {
            my $time = timegm( $6, $5, $4, $3, $2 - 1, $1 );
            $logon = strftime( "%D %H:%M", localtime($time) );
        }
        printf( $fmt, $name, $status, $created, $logon );
    }
    printf("\n");
}

# column widths and separators
@w = ( 23, 8, 8, 8, 13, 8 );
@s = ( map( " " x $_, 3, 2, 2, 2, 2 ), "\n" );

# col 0 left aligned, others right aligned, all strings truncate at max length
@f = ( "%-$w[0].$w[0]s", $s[0], map( "%$w[$_].$w[$_]s$s[$_]", 1 .. $#w ) );
$fmt = join( "", @f );

my @statkeys = qw(active closed locked maintenance total);

print( ( " " x 33 ) . "domain summary\n\n" );
printf( $fmt, ( " " x 4 ) . "domain", @statkeys );
printf( $fmt, map( "-" x $_, @w ) );

foreach my $domainName ( sort keys %$domains ) {
    my $dd     = $domains->{$domainName};
    my $stats  = $dd->{'stats'};
    my @counts = map( $stats->{$_} || 0, @statkeys );
    printf( $fmt, $domainName, @counts );
}

# Callback function for async search
{

    # avoid making $data global
    my $data = {};

    sub getData {
        return $data;
    }

    sub accountCallback {
        return sub {
            my ( $mesg, $entry ) = @_;

            return if ( !defined($entry) );    # done processing

            # optimization: do not expect any references
            #return if ( $entry->isa("Net::LDAP::Reference") );

            my %acct;
            foreach my $attr ( $entry->attributes ) {

                # optimization: each attribute is single valued
                my $val = $entry->get_value($attr);
                $acct{$attr} = $val;
            }

            # ignore entries without the zimbraMailDeliveryAddress attribute
            my $zmda = delete $acct{zimbraMailDeliveryAddress};
            return unless ($zmda);

            my ( $local, $domain ) = split( /@/, $zmda, 2 );

            $data->{$domain} ||= { stats => {}, accounts => {} };

            my $dd = $data->{$domain};
            $dd->{stats}->{total}++;
            $dd->{stats}->{ $acct{zimbraAccountStatus} }++;
            $dd->{accounts}->{$local} = \%acct;

            $mesg->pop_entry;    # conserve memory
            return;
          }
    }
}

sub emesg {
    my ($mesg) = @_;
    chomp( my $etext = $mesg->error_text() );
    return $mesg->error_name() . ": $etext";
}

sub fatal {
    die( "$Prog: ERROR: ", @_, "\n" );
}

sub zmlocalconfig {
    my $args = { opts => ["--show"], };

    $args = shift(@_) if ( @_ and ref( $_[0] ) eq "HASH" );

    my @keys = @_;
    my @opts = ( $args->{opts} ? @{ $args->{opts} } : () );
    my @cmd  = ( ZMLOCALCONFIG, @opts, @keys );

    my $tout = IO::File->new
      or fatal("open OUT filehandle failed\n");
    my $terr = IO::File->new_tmpfile
      or fatal("open ERR filehandle failed\n");
    my $pid = open3( gensym, $tout, $terr, @cmd )
      or fatal("open zmlocalconfig failed\n");

    my %lc;
    while ( my $line = <$tout> ) {
        chomp($line);
        my ( $key, $val ) = split( /\s+=\s+/, $line, 2 );
        $lc{$key} = $val;
    }
    waitpid( $pid, 0 );
    seek( $terr, 0, 0 );

    my $err;
    while ( my $line = <$terr> ) {
        chomp($line);
        warn("$Prog: ERROR: zmlocalconfig: $line\n");
        $err++;
    }

    fatal("unable to continue due to errors\n") if ($err);
    fatal("zmlocalconfig returned no data\n") unless (%lc);

    return wantarray ? %lc : \%lc;
}
