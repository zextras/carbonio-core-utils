#!/usr/bin/perl

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

use strict;
use Getopt::Long;
use English;

# Extracts all SQL statements logged to the sqltrace category
# from the specified logfile.  If a logfile is not specified,
# reads mailbox.log.

# Options
my $usage = 0;
my $logDir = "/opt/zextras/log";

if ($^O !~ /MSWin/i) {
    $logDir = qx(zmlocalconfig -x -m nokey zimbra_log_directory);
    chomp $logDir;
}

GetOptions("help" => \$usage);

if ($usage) {
    usage();
    exit(0);
}

if (scalar(@ARGV) == 0) {
    # No file was specified, so read mailbox.log
    push(@ARGV, $logDir . "/mailbox.log");
}

while (<>) {
    if (/sqltrace - (.*) - \d+ms/i) {
	print($1 . "\n");
	my $query = $1;
    }
}

#########################

sub usage() {
    print <<USAGE_EOF
Usage: $PROGRAM_NAME [logfile]

Extracts all SQL statements logged to the sqltrace category
from the specified logfile.  If a logfile is not specified,
reads mailbox.log.

  -h, --help           Display this usage message
USAGE_EOF
}
