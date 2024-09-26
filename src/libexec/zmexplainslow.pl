#!/usr/bin/perl

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

use strict;
use Getopt::Long;
use English;

# Options
my $user = "zextras";
my $password = "zextras";
my $database = "zimbra";
my $mySqlCommand = "mysql";
my $verbose = 0;
my $usage = 0;
my $logDir = "/opt/zextras/log";
my $ignore;

if (-f "/opt/zextras/bin/zmlocalconfig") {
    $password = qx(zmlocalconfig -s -m nokey zimbra_mysql_password);
    chomp $password;
    $user = qx(zmlocalconfig -m nokey zimbra_mysql_user);
    chomp $user;
    $logDir = qx(zmlocalconfig -x -m nokey zimbra_log_directory);
    chomp $logDir;
}

GetOptions("user=s" => \$user, "password=s" => \$password,
	   "database=s" => \$database, "mysql=s" => \$mySqlCommand,
	   "ignore=s" => \$ignore, "help" => \$usage);

if ($usage) {
    usage();
    exit(0);
}

if (scalar(@ARGV) == 0) {
    # No file was specified, so read slowQueries.csv
    push(@ARGV, $logDir . "/slowQueries.csv");
}

while (<>) {
    if (/\"(SELECT[^\"]+)\"/i) {
	my $query = $1;
	if (defined($ignore) && $query =~ /$ignore/) {
	    next;
	}

	my @notes;
	my $rows = 0;
	my %notes;
	my $totalRows = 1;

	print($query . "\n\n");
	my @output = runSql("EXPLAIN " . $1);

	foreach my $line (@output) {
	    if ($line =~ /type\: ALL/ ||
		$line =~ /key\: NULL/) {
		$notes{"Table scan"} = 1;
	    }
	    if ($line =~ /rows: (\d+)/) {
		$rows = $1;
		$totalRows = $totalRows * $rows;
	    }
	    if ($line =~ /filesort/) {
		if ($rows > 100) {
		    $notes{"Filesort"} = 1;
		}
	    }
	    if ($line =~ /temporary/) {
		if ($rows > 100) {
		    $notes{"Temporary table"} = 1;
		}
	    }

	    print($line . "\n");
	}
	print("\n");

	if ($totalRows > 1000) {
	    $notes{$totalRows . " rows scanned"} = 1;
	}

	if (scalar(keys(%notes)) > 0) {
	    print("### NOTES: " . join(",", keys(%notes)) . "\n\n");
	}
    }
}

exit(0);

############################

sub runSql($) {
    my ($script) = @_;

    # Write the last script to a text file for debugging
    # open(LASTSCRIPT, ">lastScript.sql") || die "Could not open lastScript.sql";
    # print(LASTSCRIPT $script);
    # close(LASTSCRIPT);

    # Run the mysql command and redirect output to a temp file
    my $tempFile = "mysql.out";
    my $command = "$mySqlCommand --user=$user --password=$password " .
        "--database=$database --vertical";
    open(MYSQL, "| $command > $tempFile") || die "Unable to run $command";
    print(MYSQL $script);
    close(MYSQL);

    if ($? != 0) {
        die "Error while running '$command'.";
    }

    # Process output
    open(OUTPUT, $tempFile) || die "Could not open $tempFile";
    my @output;
    while (<OUTPUT>) {
        s/\s+$//;
        push(@output, $_);
    }

    unlink($tempFile);
    return @output;
}

sub usage() {
    print <<USAGE_EOF
Usage: $PROGRAM_NAME [slowQueries.csv]

Runs EXPLAIN on SELECT statements in the specified file.  If
the path to slowQueries.csv is not specified, reads
$logDir/slowQueries.csv.

  -h, --help           Displays this usage message
  -i, --ignore=regexp  Ignore any SELECT statements that match the
                       specified regular expression
  -u, --user=name      MySQL user name (default: "zextras")
  -p, --password=name  MySQL password (default: "zextras")
  -d, --database=name  MySQL database (default: "zimbra")
  -m, --mysql=command  MySQL client command name (default: "mysql")
USAGE_EOF
}
