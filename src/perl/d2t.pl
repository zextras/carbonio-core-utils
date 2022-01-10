#!/usr/bin/perl

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

use Date::Parse;
use strict;

if ($ARGV[0] eq "") {
    print "USAGE: d2t DATE_STRING\n";
    exit(1);
}

my $argStr;
# there must be some extra-special easy perl way to do this...
my $i = 0;
do {
    $argStr = $argStr . $ARGV[$i] . " ";
    $i++;
} while($ARGV[$i] ne "");

my $val = str2time($argStr);
my $back = localtime($val);
my $msval = $val * 1000;
print "$val\n$msval\n$back\n";
