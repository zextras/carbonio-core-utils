#!/usr/bin/perl
#
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

package Zextras::Setup::DNS;
use strict;
use warnings;
use Net::DNS::Resolver;
use NetAddr::IP;
use Exporter 'import';

our @EXPORT = qw(getDnsRecords lookupHostName validateMxRecords);

sub getDnsRecords {
    my $hostname   = shift;
    my $query_type = shift;

    main::progress("\n\nQuerying DNS for \"$query_type\" record of $hostname...");

    my $resolver = Net::DNS::Resolver->new;
    my $ans      = $resolver->search( $hostname, $query_type );

    return $ans;
}

sub lookupHostName {
    my $hostname   = shift;
    my $query_type = shift;

    main::progress("\n\nQuerying DNS for \"$query_type\" record of current hostname $hostname...");

    my $resolver = Net::DNS::Resolver->new;
    my $ans      = $resolver->search( $hostname, $query_type );
    if ( !defined $ans ) {
        main::progress("\n\tNo results returned for \"$query_type\" record of current hostname $hostname\n");
        main::progress("\nChecked nameservers:\n");
        foreach my $server ( $resolver->nameservers() ) {
            main::progress("\t$server\n");
        }
        return 1;
    }

    foreach my $rr ( $ans->answer ) {
        next unless $rr->type eq 'A';
        my $ip = $rr->address;

        if ( $ip =~ /^127\.|^::1$/ ) {
            main::progress("\n\tERROR: Resolved IP address $ip for current hostname $hostname is pointing to a loopback device or interface");
            return 1;
        }

        my $ipo = `ip addr show $ip 2>&1`;
        if ( $? == 0 && $ipo =~ /scope host/ ) {
            main::progress("\n\tERROR: Resolved IP address $ip for current hostname $hostname is pointing to a loopback device or interface");
            return 1;
        }
    }

    return 0;
}

# Validate MX records for a domain against local interfaces.
# Displays MX records and checks if any resolve to this host.
# Args: $domain, $dns_answer, \@interfaces
# Returns 1 if a match is found, 0 otherwise.
sub validateMxRecords {
    my ( $domain, $ans, $interfaces_ref ) = @_;
    my @answer = $ans->answer;
    my %resolved_mx;

    foreach my $a (@answer) {
        next unless $a->type eq "MX";
        my $exchange = $a->exchange;
        my $h        = getDnsRecords( $exchange, 'A' );
        my $ipv6     = 0;
        if ( !defined $h ) {
            $h    = getDnsRecords( $exchange, 'AAAA' );
            $ipv6 = 1;
        }
        if ( defined $h ) {
            my @ha = $h->answer;
            $resolved_mx{$exchange} = \@ha;
            foreach $h (@ha) {
                my $type = $ipv6 ? 'AAAA' : 'A';
                if ( $h->type eq $type ) {
                    main::progress("\tMX: $exchange (" . $h->address . ")\n");
                }
            }
        }
        else {
            main::progress("\n\nDNS ERROR - No \"A\" or \"AAAA\" record for $domain.\n");
        }
    }

    main::progress("\n");
    foreach my $i (@$interfaces_ref) {
        main::progress("\tInterface: $i\n");
    }

    foreach my $a (@answer) {
        next unless $a->type eq "MX";
        my $ha_ref = $resolved_mx{ $a->exchange };
        next unless defined $ha_ref;
        foreach my $i (@$interfaces_ref) {
            foreach my $h (@$ha_ref) {
                if ( $h->type eq 'A' || $h->type eq 'AAAA' ) {
                    my $interIp   = NetAddr::IP->new("$i");
                    my $interface = lc( $interIp->addr );
                    if ( $h->address eq $interface ) {
                        return 1;
                    }
                }
            }
        }
    }
    return 0;
}

1;
