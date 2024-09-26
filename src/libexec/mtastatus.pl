#!/usr/bin/perl

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

use strict;
use Getopt::Std;
use File::Basename;

my $progname = basename($0);

# Need to be root to run "postfix status"
if ( $> != 0 ) {
    print "$0 must be run as root.\n";
    exit 1;
}

# Exit if software-only node.
exit(1) unless ( -f "/opt/zextras/conf/localconfig.xml" );

my %options = ();
unless ( getopts( 'dhv', \%options ) ) { usage(); }
usage() if ( $options{h} );
my $debug   = $options{d} ? 1 : 0;
my $verbose = $options{v} ? 1 : 0;
$verbose = 1 if $debug;

my $postfix = "/opt/zextras/common/sbin/postfix";

exit( mtaIsRunning() ? 0 : 1 );

sub mtaIsRunning {
    print "MTA process is " if $verbose;
    system("$postfix status 2> /dev/null");
    if ( $? == 0 ) {
        print "running.\n" if $verbose;
        return 1;
    }
    else {
        print "not running.\n" if $verbose;
    }
    return undef;
}

sub getLocalConfig {
    my $key = shift;
    if ( defined( $ENV{zmsetvars} ) ) {
        return $ENV{$key};
    }
    open CONF, "/opt/zextras/bin/zmlocalconfig -x -s -q -m shell |" or die "Can't open local config: $!";
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

sub usage {
    print "$progname [-h] [-v] [-d]\n";
    print "\t-h\tUsage\n";
    print "\t-v\tverbose output\n";
    print "\t-d\tdebug output\n";
    exit;
}

