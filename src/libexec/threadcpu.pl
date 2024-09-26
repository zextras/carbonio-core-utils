#!/usr/bin/perl -w
#
# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only
#

use strict;
use Getopt::Long;

my $procStatsFile1;
my $procStatsFile2;
my $threadDumpFile;
my $numThreads = 10;
my $useSysCpu = 0;
my $columnNumber = 14;
my $stackTrace = 0;
my %last;
my %first;

sub printUsage() {
  print STDERR <<EOF
Usage: zmthreadcpu [options] <thread-dump-file>

Print the list of threads that consume the most CPU cycles.  Reconcile data
in a Java thread dump file with data collected from /proc/stats.

  --proc-stats2       Second /proc/stats dump file.  Default is the file that
                        has the same suffix as the thread dump file.
  --proc-stats1       First /proc/stats dump file.  Default is
                        proc-stats.1.nn-nn-nn.
  -n, --num-threads   Number of threads listed (default is 10).
  -s, --stack-trace   Print the stack trace for each thread.
  -c, --column        Column number in proc-stats to use when calculating CPU
                        usage (default is 14).
  --sys-cpu           Calculate sys CPU usage (column 15) instead of user CPU.
EOF
}

sub assertFileExists($) {
  my $filename = shift();
  if (! -f $filename) {
    print STDERR "Could not find $filename.\n";
    exit(1);
  }
}

# main

GetOptions ("proc-stats1=s" => \$procStatsFile1,
	    "proc-stats2=s" => \$procStatsFile2,
	    "num-threads|n=i" => \$numThreads,
	    "sys-cpu" => \$useSysCpu,
	    "stack-trace|s" => \$stackTrace,
            "column|c=i" => \$columnNumber
	   );

if (scalar(@ARGV) != 1) {
  printUsage();
  exit(1);
}
$threadDumpFile = $ARGV[0];
assertFileExists($threadDumpFile);

# Determine proc-stats2 filename.
if (!defined($procStatsFile2)) {
  if ($threadDumpFile =~ /(.*)threaddump(.*)/) {
    $procStatsFile2 = $1 . "proc-stats" . $2;
  } else {
    print STDERR "Unexpected filename format: $threadDumpFile.  Please specify --proc-stats2.\n";
    exit(1);
  }
}
assertFileExists($procStatsFile2);

# Determine proc-stats1 filename.
if (!defined($procStatsFile1)) {
  if (($procStatsFile2 =~ /(.*)proc-stats.(\d\d?)\.(.*)/)) {
    if ($2 < 2) {
      print STDERR "Thread dump filename number must be greater than 1.\n";
      exit(1);
    }
    my $filespec = $1 . "proc-stats.1.*";
    my @filenames = glob($filespec);
    if (scalar(@filenames) == 0) {
      print STDERR "Could not find $filespec.  Please specify --proc-stats1.\n";
      exit(1);
    }
    $procStatsFile1 = $filenames[0];
  } else {
    print STDERR "Unexpected filename format: $procStatsFile2.  Please specify --proc-stats1.\n";
    exit(1);
  }
}

assertFileExists($procStatsFile1);

if ($useSysCpu) {
  $columnNumber = 15;
}

print("Reading CPU usage from column $columnNumber in $procStatsFile1 and $procStatsFile2.\n");

# Read proc-stats files.
my $lastcmd = "awk '{print \$1, \$$columnNumber}' $procStatsFile2";
my $firstcmd = "awk '{print \$1, \$$columnNumber}' $procStatsFile1";
my @lastarray = qx($lastcmd);
my @firstarray = qx($firstcmd);

sub trim($)
  {
    my $string = shift;
    $string =~ s/^\s+//;
    $string =~ s/\n+$//;
    return $string;
  }

for my $i (@lastarray) {
  $i =  trim($i);
  my @kv = split(" ", $i);
  $last{$kv[0]} = $kv[1];
}

for my $i (@firstarray) {
  $i =  trim($i);
  my @kv = split(" ", $i);
  $first{$kv[0]} = $kv[1]; 
}

my $v;
my $delta;  

while ( my ($key, $value) = each(%last) ) {  
  if ( exists $first{$key}) {
    $v = $first{$key} + 0;      
  } else {
    $v = 0; 
  }  
    
  $delta = $value + 0 - $v;
  $last{$key} = $delta;    
  #print "$key $delta\n";  
}

sub hashValueDescendingNum {
  $last{$b} <=> $last{$a};
}

my @ticks;
my @threadid;
my $count = 0;
foreach my $key (sort hashValueDescendingNum (keys(%last))) {
  if ($count == $numThreads) {
    last;
  }
  push(@ticks, $last{$key});
  $key = sprintf("%x", $key);
  push(@threadid, "0x"."$key" );
  $count ++;
}

$count = 0;
my $start = 0;
my @finalResult; 
my $currentPos;

open(DUMP, $threadDumpFile) or die "Cannot open $threadDumpFile, $!";
while (<DUMP>) {	
  if ( $start) {
    if ( $_ =~ /^\n$/) {
      $start = 0;				 		
    } elsif ($_ =~ /prio=/) {			
      goto CK;			
    } else {
      if ($stackTrace) {
	$finalResult[$currentPos][0] = $finalResult[$currentPos][0]."$_"; 
      }
    }
  } else {
  CK:
    for ( my $i = 0; $i < scalar(@threadid); $i++) {
      if ( $threadid[$i] && $_ =~ /prio.*$threadid[$i]/ ) {
	$currentPos = $i;
	my $j = $i + 1;
	my $line = "$ticks[$currentPos] ticks:\n".$_;
	$finalResult[$currentPos][0] = $line;
	$threadid[$i] = 0;
	$start = 1; 
	next;
      }        
    }
  }
}

for my $i ( 0 .. $#finalResult ) {
  print $finalResult[$i][0]."\n";        
}
