#!/usr/bin/perl

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

# Prints out entire nginx configuration by following all file includes
#

use Getopt::Long;
Getopt::Long::Configure("bundling");

my $wdir      = undef;
my $nginxconf = "/opt/zextras/conf/nginx.conf";
my $fh;
my %options = undef;
my $sprefix = "";

if ( !-x "/opt/zextras/common/sbin/nginx" ) {
    print "Nginx not installed, exiting\n";
    exit 1;
}

sub printusage() {
    print STDERR "\n";
    print STDERR " Print NGINX configuration by following all file inclusions"
      . "\n";
    print STDERR " Prints $nginxconf unless overridden" . "\n";
    print STDERR "\n";

    print STDERR " Usage: zmnginxconf [OPTIONS] [NGINX-CONF-FILE]" . "\n";
    print STDERR "" . "\n";
    print STDERR "  -h|--help                print this help message" . "\n";
    print STDERR "  -m|--markers             print file inclusion markers"
      . "\n";
    print STDERR "  -i|--indent              indent included files" . "\n";
    print STDERR
      "  -n|--nocomments          do not print comment-lines (beginning with #)"
      . "\n";
    print STDERR "  -e|--noempty             do not print empty lines" . "\n";

    print STDERR "\n";
}

sub printconf {
    my $filename = shift;
    my $indent   = shift;
    my $prefix   = $sprefix x $indent;
    my $fh;
    my $line = 0;

    open( $fh, $filename )
      or { print $prefix . "# cannot open $filename: $!" . "\n" }
      and return;

    if ( defined $options{markers} ) {
        print $prefix . "# begin:$filename" . "\n";
    }

    while (<$fh>) {
        $line = $line + 1;

        my $l = $_;
        chomp $l;

        if ( $l =~ /^\s*working_directory\s+([^\s;]+);/ ) {
            $wdir = $1;
        }

        if ( $l =~ /^\s*include\s+([^\s;]+);/ ) {
            my $i = $1;
            if ( !defined $wdir ) {
                print $prefix
                  . "# working directory not defined while including $i at $filename:$line"
                  . "\n";
            }
            else {
                printconf( "$i", $indent + 1 );
            }
        }
        else {
            if ( ( $l =~ /^\s*#/ ) && ( defined $options{nocomments} ) ) {
            }
            elsif ( ( $l =~ /^\s*$/ ) && ( defined $options{noempty} ) ) {
            }
            else {
                print $prefix . $l . "\n";
            }
        }
    }

    if ( defined $options{markers} ) {
        print $prefix . "# end:$filename" . "\n";
    }
    close($fh);
}

sub processoptions {
    %options = ();
    GetOptions(
        "help|h"       => \$options{help},
        "indent|i"     => \$options{indent},
        "nocomments|n" => \$options{nocomments},
        "noempty|e"    => \$options{noempty},
        "markers|m"    => \$options{markers}
    );

    if ( $#ARGV != -1 ) {
        if ( $#ARGV == 0 ) {
            $nginxconf = $ARGV[0];
        }
        else {
            print STDERR "Too many arguments (-h for help)\n";
            exit 1;
        }
    }
}

# MAIN

processoptions();

if ( defined $options{help} ) {
    printusage();
    exit 0;
}

if ( defined $options{indent} ) {
    $sprefix = "  ";
}

printconf( $nginxconf, 0 );

