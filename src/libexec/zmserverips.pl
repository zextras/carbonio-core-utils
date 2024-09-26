#!/usr/bin/perl

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

use lib "/opt/zextras/common/lib/perl5";

package Local::ServerIPs;

use strict;
use warnings;
use File::Basename qw(basename);
use Getopt::Long qw(GetOptionsFromArray);
use NetAddr::IP qw(:lower);
use Pod::Usage qw(pod2usage);

my %opt;

__PACKAGE__->run(@ARGV) unless caller();

sub run {
    my ( $class, @argv ) = @_;

    $class->process_options(@argv);
    exit( $class->print_output( $class->enumerate() ) ? 0 : 1 );
}

sub die {
    my $class = shift;
    $class->error(@_);
    exit(2);
}

sub error {
    my $class = shift;
    my $prog  = basename($0);
    warn("$prog: $_\n") for @_;
}

sub process_options {
    my ( $class, @argv ) = @_;

    GetOptionsFromArray( \@argv, \%opt, "help", "man", "networks" )
      or pod2usage( -verbose => 0 );

    $class->error("unknown arguments: @argv") if (@argv);
    pod2usage( -verbose => 1 ) if ( $opt{help} or @argv );
    pod2usage( -verbose => 2 ) if ( $opt{man} );
}

sub enumerate {
    my ( $class, $fh ) = @_;
    unless ($fh) {
        my @ipcmd = (qw(/sbin/ip addr));
        ( -x $ipcmd[0] )
          or $class->die("unable to execute: $ipcmd[0]\n");
        open( $fh, "-|", @ipcmd )
          or $class->die("error running: @ipcmd: $!\n");
    }

    my @iface;
    while (<$fh>) {
        next unless ( /^\s*inet/ and !/scope link/ );
        chomp;
        my ( $type, $ipmask, undef ) = split( " ", $_,      3 );
        my ( $ip,   $mask,   undef ) = split( "/", $ipmask, 3 );

        if ( $type eq "inet" ) {
            $mask = NetAddr::IP->new($ipmask)->mask;
        }
        if ( $opt{networks} ) {
            if ( $type eq "inet" ) {
                $ip = NetAddr::IP->new($ipmask)->network;
            }
            else {
                $ip = NetAddr::IP->new($ipmask)->network->short;
            }
        }
        if ( $type eq "inet6" && $opt{networks} ) {
            $ip = "[" . $ip . "]" . "/" . $mask;
        }
        push( @iface, [ $ip, $mask ] );
    }
    return \@iface;
}

sub print_output {
    my ( $class, $ifs ) = @_;
    if ( $opt{networks} ) {
        foreach my $if ( @{ $ifs || [] } ) {
            print( $if->[0], "\n" );
        }
    }
    else {
        foreach my $if ( @{ $ifs || [] } ) {
            print( "addr:", $if->[0], " Mask:", $if->[1], "\n" );
        }
    }
    return scalar @$ifs;
}

=pod

=head1 NAME

zmserverips - enumerate local server IP addresses for validation purposes

=head1 SYNOPSIS

zmserverips [options]

    --help                      display a brief help message
    --man                       display full documentation
    --networks                  generate mynetworks compatible interface data

=head1 DESCRIPTION

This utility is run on a server to enumerate available IP addresses.
The output is formatted specifically for use by dependent tools which
parse, and use the data during validation tasks.

=head1 EXAMPLE

The following is an example of the output:

 addr:127.0.0.1 Mask:255.0.0.0
 addr:::1 Mask:128
 addr:10.1.5.9 Mask:255.255.255.0

The following is an example of the output with --networks:
  127.0.0.0/8
  [::1]/128
  10.1.5.0/24

=head1 SEE ALSO

=over 4

=item *

L<bug 17753|https://bugzilla.zimbra.com/show_bug.cgi?id=17753>

=item *

L<bug 38877|https://bugzilla.zimbra.com/show_bug.cgi?id=38877>

=item *

L<bug 103143|https://bugzilla.zimbra.com/show_bug.cgi?id=103143>

=item *

GetServerNIfsRequest in Soap API documentation

=item *

L<ip(8)>

=back

=cut

# run test: perl -e 'require "path/to/zmserverips"; Local::ServerIPs->test(1);'
sub test {
    my $class = shift;

    require Test::More;
    Test::More->import( "tests" => 1 );

    my $tdata = do { local $/; <DATA> };
    open( my $dfh, "<", \$tdata )
      or $class->die("unable to read test data\n");

    my $ifs = $class->enumerate($dfh);
    is_deeply(
        $ifs,
        [
            [ "127.0.0.1",   "255.0.0.0" ],
            [ "::1",         128 ],
            [ "10.0.0.1",    "255.255.255.0" ],
            [ "10.1.2.3",    "255.255.255.255" ],
            [ "2001:db8::1", 64 ],
            [ "192.0.0.9",   "255.255.128.0" ],
        ]
    );
    if (@_) {
        print( "--- test data ---\n", $tdata, "--- results ---\n" );
        $class->print_output($ifs);
    }
}

__DATA__
    inet 127.0.0.1/8 scope host lo
    inet6 ::1/128 scope host
ignored stuff
    inet 10.0.0.1/24 brd 10.0.0.255 scope global br0
    inet 10.1.2.3 peer 10.1.2.9/32 brd 10.1.2.255 scope global eth0
    inet6 2001:db8::6/48 scope link
    inet6 2001:db8::1/64 scope global
    inet 192.0.0.9/17 scope global
