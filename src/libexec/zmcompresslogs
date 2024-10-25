#!/usr/bin/perl -w

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

use Getopt::Long;
use lib "/opt/zextras/common/lib/perl5";
use IO::Compress::Gzip qw(gzip $GzipError);
sub scanLogDirectory;
sub getLocalConfigValue;
sub usage;

my ($help, $verbose);
GetOptions("help" => \$help,
           "verbose" => \$verbose);

my $zimbra_log_directory="/opt/zextras/log";

my @logfiles = qw(mailbox.log audit.log sync.log synctrace.log wbxml.log milter.log);

usage() if $help;
scanLogDirectory($zimbra_log_directory);


sub usage() {
  print "$0 [-help] [-verbose]\n";
  exit;
}

sub scanLogDirectory($) {
  my ($logDirectory) = @_;
   if (opendir DIR, "$logDirectory") {
    my @logs = grep { !/^[\._]/ } readdir(DIR);
    foreach my $log (@logs) {
      next if ($log =~ /\.gz$/); # skip files already compressed.
      next if ($log !~ /\.\d{4}-\d{2}-\d{2}$/);
      foreach $str (@logfiles) {
        if ($log =~ /$str/) {
          compressLogFile("$logDirectory/$log");
        }
      }
    }
  }
}

sub compressLogFile($) {
  my ($logfile) = @_;
  if (gzip $logfile => "$logfile.gz") {
    print "Compressed $logfile.\n" if $verbose;
    unlink($logfile);
  } else {
    print "compression failed for $logfile. $GzipError\n";
  }
}

sub getLocalConfigValue($) {
  my ($key) = @_;
  my $val = qx(/opt/zextras/bin/zmlocalconfig -x -s -m nokey ${key} 2> /dev/null);
  chomp $val;
  return $val;
}
