#!/usr/bin/perl

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

use strict;

use IO::File;
use File::Find;

if ( $> ne 0 ) {
    print "$0 must be executed as root.\n";
    exit 1;
}

my $readfiles = 0;

my %queue_stats = ();

my $hash_queue_depth;
my $queue_directory;

my $qfiles = 0;

# Map for Long Format Queue IDs
my $ALPHACHARS = "BCDFGHJKLMNPQRSTVWXYZ";

# Map of 52 characters for Long Format Queue IDs:
# ASCII digits and Lower/Upper Case ASCII letters without AEIOU/aeiou
my @CHARLIST = ( 0 .. 9, split( //, $ALPHACHARS . lc($ALPHACHARS) ) );
my %CHARMAP  = map { ( $CHARLIST[$_], $_ ) } 0 .. $#CHARLIST;

# Regexes for Postfix Queue IDs

# Short Format character: ASCII uppercase A-F range plus ASCII digits
my $SF_QID_CHAR = qr{[A-F0-9]};

# Long Format time portion character:  ASCII digits and ASCII uppercase/lowercase consonants
my $LF_QID_TIME_CHAR = qr{[0-9BCDFGHJKLMNPQRSTVWXYZ]}i;

# Long Format inode number portion character: ASCII digits and ASCII uppercase/lowercase consonants minus "z"
my $LF_QID_INODE_CHAR = qr{[0-9BCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxy]};

my $REGEX_POSTFIX_QID = qr{(?:${SF_QID_CHAR}{6,}+|${LF_QID_TIME_CHAR}{10,}z${LF_QID_INODE_CHAR}++)};

sub getLocalConfig {
    my $key = shift;
    if ( defined( $ENV{zmsetvars} ) ) {
        return $ENV{$key};
    }
    open CONF, "/opt/zextras/bin/zmlocalconfig -q -m shell |" or die "Can't open local config: $!";
    my @conf = <CONF>;
    close CONF;

    chomp @conf;

    foreach (@conf) {
        my ( $key, $val ) = split '=', $_, 2;
        $val =~ s/;$//;
        $val =~ s/'$//;
        $val =~ s/^'//;
        $ENV{$key} = $val;
    }
    $ENV{zmsetvars} = 'true';
    return $ENV{$key};
}

sub get_record {    # Borrowed from qshape
    my ($fh)  = shift;
    my $rec   = getc($fh) || return;
    my $len   = 0;
    my $shift = 0;
    while ( defined( my $lb = getc($fh) ) ) {
        my $dig = ord($lb);
        $len |= ( $dig & 0x7f ) << $shift;
        last if ( ( $dig & 0x80 ) == 0 );
        $shift += 7;
        return if ( $shift > 14 );    # XXX: max rec len of 2097151
    }
    my $data = "";
    return unless ( $len == 0 || read( $fh, $data, $len ) == $len );

    #print STDERR "Returning $rec, $len, $data\n";
    return ( $rec, $len, $data );
}

sub getHashPath {
    my $fn = shift;
    my $p  = "";
    if ( ( my $index = rindex( $fn, "z" ) ) != -1 ) {
        my @chars = reverse( split( //, substr( $fn, $index - 4, 4 ) ) );
        $fn = 0;
        for ( my $i = 0 ; $i <= 4 ; $i++ ) {
            $fn += $CHARMAP{ $chars[$i] } * 52**$i;
        }
        $fn = sprintf( "%05X", $fn );
    }
    for ( my $i = 0 ; $i < $hash_queue_depth ; $i++ ) {
        $p .= substr( $fn, $i, 1 );
        $p .= "/";
    }
    return $p;
}

sub processQ {
    if ( !-f $_ )                            { return; }
    if ( !m{(?:^|/)${REGEX_POSTFIX_QID}$}o ) { return; }
    $qfiles++;
    my ($cdir) = ( $File::Find::dir =~ m|([^/]*)| );

    #print STDERR "Processing $cdir - $_\n";
    $queue_stats{$cdir}{COUNT}++;

    if ($readfiles) {
        my %qf = ();
        my @st = lstat($_);
        if ( @st == 0 ) { return; }

        #print STDERR "Processing file $_\n";
        my $fh = new IO::File( $_, "r" ) || return;
        my ( $rec, $len, $data ) = get_record($fh);
        $qf{TO} = [];
        if ( $rec eq "C" ) {    # Size
            ( $qf{SIZE} ) = ( $data =~ m/\s*(\d+)\s*\d+\s*\d+/ );
        }
        while ( my ( $rec, $len, $data ) = get_record($fh) ) {

            #print STDERR "got $rec, $len, $data\n";
            if ( $rec eq "R" ) {
                push( @{ $qf{TO} }, $data );
            }
            elsif ( $rec eq "S" ) {
                $qf{FROM} = $data ? $data : 'MAILER-DAEMON';
            }
            elsif ( $rec eq "L" ) {
                $qf{FILTER} = $data;
            }
            elsif ( $rec eq "N" ) {
                if ( $data =~ /Received: from/ && $data !~ /127\.0\.0\.1/ && $data !~ /::1/ ) {
                    my ( $junk, $rip ) = split( /\[/, $data, 2 );
                    ( $rip, $junk ) = split( /\]/, $rip, 2 );
                    $qf{RECEIVED} = $rip;
                }
            }
            elsif ( $rec eq "A" ) {
                my ( $aname, $avalue ) = ( $data =~ /^([^=]+)=(.*)$/ );
                if ( $aname eq "client_address" && defined($avalue) ) {
                    $qf{ADDR} = $avalue;
                }
                elsif ( $aname eq "client_name" && defined($avalue) ) {
                    $qf{HOST} = $avalue;
                }
            }
            elsif ( $rec eq "T" ) {
                my $ix = index( $data, " " );
                if ( $ix >= -1 ) {
                    $qf{TIME} = substr( $data, 0, $ix );
                }
                else {
                    $qf{TIME} = $data;
                }
            }
            elsif ( $rec eq "p" ) {
                if ( $data > 0 ) {
                    seek( $fh, $data, 0 ) or return ();
                }
            }
            elsif ( $rec eq "E" ) {
                last;
            }
        }
        $fh->close();
        if ( $cdir eq "deferred" ) {
            my $dfile = getHashPath($_);
            $fh = new IO::File( "$queue_directory/defer/$dfile/$_", "r" ) || die "Can't open $dfile/$_: $!";
            my @reasons = grep /^reason=/, <$fh>;
            $qf{REASON} = $reasons[0];
            chomp $qf{REASON};
            $qf{REASON} =~ s/reason=//;
        }

        print "id=",   $_,        "\n";
        print "time=", $qf{TIME}, "\n";
        print "size=", $qf{SIZE}, "\n";
        print "from=", $qf{FROM}, "\n";
        if ( defined $qf{RECEIVED} ) { print "received=", $qf{RECEIVED}, "\n"; }
        if ( defined $qf{ADDR} )     { print "addr=",     $qf{ADDR},     "\n"; }
        if ( defined $qf{HOST} )     { print "host=",     $qf{HOST},     "\n"; }
        if ( defined $qf{FILTER} )   { print "filter=",   $qf{FILTER},   "\n"; }

        if ( $qf{REASON} ) {
            print "reason=", $qf{REASON}, "\n";
        }
        print "to=", join( ',', @{ $qf{TO} } ), "\n";
        print "\n";

    }

}

$queue_directory = qx(/opt/zextras/common/sbin/postconf -h queue_directory);
chomp $queue_directory;

$hash_queue_depth = qx(/opt/zextras/common/sbin/postconf -h hash_queue_depth);
chomp $hash_queue_depth;

#$queue_directory="/opt/zextras/data/postfix/spool";
#print STDERR "$queue_directory\n";

my @queues = qw/incoming hold active deferred corrupt/;

if ( $ARGV[0] ) {
    @queues    = $ARGV[0];
    $readfiles = 1;
}

map { $queue_stats{$_} = () } @queues;

foreach ( map "$queue_directory/$_", @queues ) {
    chdir $_ or die "Can't chdir to $_";
}

chdir $queue_directory;

find( \&processQ, @queues );

if ( !$readfiles ) {
    map { printf "%s=%d\n", $_, $queue_stats{$_}{COUNT} } keys %queue_stats;
}
