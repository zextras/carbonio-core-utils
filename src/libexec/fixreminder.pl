#!/usr/bin/perl -w
# 
# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only
# 

use strict;
use Getopt::Long;
use Cwd;
use File::Path;

my $ZMLOCALCONFIG = 'zmlocalconfig';
my $ZMPROV = 'zmprov';
my $ZMMAILBOX = 'zmmailbox';
my $DEFAULT_REMINDER_MINUTES = 5;
my $OUTDIR;

sub getETA($) {
    my $totalSeconds = shift;
    my $hours = int($totalSeconds / 3600);
    my $minutes = int($totalSeconds / 60) - $hours * 60;
    my $seconds = $totalSeconds - $hours * 3600 - $minutes * 60;
    my $str = '';
    my ($hasHour, $hasMinute) = (0, 0);
    if ($hours > 0) {
	if ($hours > 1) {
	    $str .= "$hours hours ";
	} else {
	    $str .= "$hours hour ";
	}
	$hasHour = 1;
    }
    if ($hasHour || $minutes > 0) {
	if ($minutes > 1) {
	    $str .= "$minutes minutes ";
	} else {
	    $str .= "$minutes minute ";
	}
	$hasMinute = 1;
    }
    if (!$hasHour && !$hasMinute) {
	$seconds = int($seconds);
	$str .= "$seconds seconds";
    }
    return $str;
}

sub getOutdir() {
    my $outdir = "$OUTDIR/reminder_fixup_temp";
    if (-d $outdir && -w $outdir) {
	return $outdir;
    }
    mkpath($outdir);
    if (! -d $outdir || ! -w $outdir) {
	print STDERR "Can't create temp directory.  Try running this script from a directory where you have write permission.";
	exit(1);
    }
    return $outdir;
}

sub getLocalServerName() {
    my $server = qx($ZMLOCALCONFIG -m nokey zimbra_server_hostname);
    chomp($server);
    return $server;
}

sub getTriggerTimeMinutes($) {
    my $email = shift;
    my @output = qx($ZMPROV -l ga $email);
    my %prefs;
    foreach my $line (@output) {
	chomp($line);
	my ($key, $val) = split(/:\s*/, $line);
        if (defined($key) && defined($val) &&
	    $key eq 'zimbraPrefCalendarApptReminderWarningTime') {
	    return $val;
	}
    }
    return $DEFAULT_REMINDER_MINUTES;
}

sub getDtstamp() {
    my $now = time();
    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = gmtime($now);
    my $stamp = sprintf("%04d%02d%02dT%02d%02d%02dZ",
			$year + 1900, $mon + 1, $mday,
			$hour, $min, $sec);
    return $stamp;
}

# Process an ics file.  Input file $icsFile is scanned, and any VEVENTs
# that don't have a VALARM are copied to $outIcsFile with an alarm inserted.
# Inserted alarm specified reminder at $triggerMinutes before meeting start
# time.  Importing the output ics file will update those VEVENTs.  The
# events/todos that got filtered out aren't touched.
#
# This sub returns the number of VEVENTs that needed to have alarm added.
sub fixupIcsFile($$$) {
    my ($icsFile, $outIcsFile, $triggerMinutes) = @_;
    my $dtstamp = getDtstamp();
    my $numFixed = 0;  # number of VEVENTs and VTODOs that had reminders added
    my %fixedUids;
    open(ICS_OUT_FH, "> $outIcsFile") or die ("Can't open $outIcsFile: $!");
    open(ICS_FH, "< $icsFile") or die ("Can't open $icsFile: $!");
    my $line;
    my ($inComp, $currCompName, $isEvent, $isSeries) = (0, undef, 0, 0);
    my ($uid, $alreadyHasAlarm, $isCancel) = (undef, 0, 0);
    my @currCompLines;
    while (defined($line = <ICS_FH>)) {
	chomp($line);
	$line =~ s/[\r\n]+$//;  # remove CRs and LFs at line end
	if (!$inComp) {
	    if ($line =~ /^BEGIN:(VEVENT|VTODO|VJOURNAL)/i) {
		$inComp = 1;
		$currCompName = $1;
		$isEvent = uc($currCompName) eq 'VEVENT' ? 1 : 0;
		$isSeries = 0;
		$uid = undef;
		$alreadyHasAlarm = 0;
		$isCancel = 0;
		@currCompLines = ($line);
	    } else {
		print ICS_OUT_FH "$line\r\n";
	    }
	} else {
	    # We're inside a VEVENT/VTODO/VJOURNAL.
	    if ($line =~ /^END:$currCompName/i) {
		# Add a VALARM if the VEVENT doesn't have one already.
		# No need to add alarm for a CANCELLED VEVENT though.
		if (!$alreadyHasAlarm && !$isCancel) {
		    $numFixed++;
		    # Do our fixup.  Add a simple display alarm.
		    push(@currCompLines, "BEGIN:VALARM");
		    push(@currCompLines, "ACTION:DISPLAY");
		    push(@currCompLines, "TRIGGER:-PT${triggerMinutes}M");
		    push(@currCompLines, "DESCRIPTION:Reminder");
		    push(@currCompLines, "END:VALARM");
		}
		push(@currCompLines, "$line");

		# Only write VEVENTs.  VTODOs and VJOURNALs are not written
		# to the output file and thus won't be updated.
		if ($isEvent) {
		    # Write the VEVENT to the output file if we added a VALARM
		    # to it.  Even if we didn't add one (because it was a
		    # CANCELLED event or it had an alarm already), we need to
		    # write it out if it is an exception instance and the
		    # VEVENT with RRULE (the recurrence series) had to be
		    # written out.  This is because updating the series can
		    # blow away exceptions.  Writing the exceptions out ensures
		    # they are recreated.
		    if (!$alreadyHasAlarm && $isSeries && !$isCancel) {
			$fixedUids{$uid} = 1;
		    }
		    if (exists($fixedUids{$uid}) || (!$alreadyHasAlarm && !$isCancel)) {
			foreach my $outLine (@currCompLines) {
			    if ($outLine =~ /^DTSTAMP:/i) {
				# update DTSTAMP to now
				$outLine = "DTSTAMP:$dtstamp";
			    }
			    print ICS_OUT_FH "$outLine\r\n";
			}
		    }
		}

		$inComp = 0;
	    } elsif ($isEvent) {
		if ($line =~ /^BEGIN:VALARM/i) {
		    $alreadyHasAlarm = 1;
		} elsif ($line =~ /^UID:(.+)$/i) {
		    $uid = $1;
		} elsif ($line =~ /^STATUS:CANCELLED/i) {
		    $isCancel = 1;
		} elsif ($line =~ /^RRULE/i) {
		    $isSeries = 1;
		}
		push(@currCompLines, "$line");
	    }
	}
    }
    close(ICS_FH);
    close(ICS_OUT_FH);

    if ($numFixed < 1) {
	unlink($outIcsFile);
    }
    return $numFixed;
}

# Run fixup for a single user.
sub fixupOneUser($) {
    my $email = shift;

    # Get user's reminder preference.  (one zmprov call)
    my $triggerMinutes = getTriggerTimeMinutes($email);
    print "Account: $email\n";
    if ($triggerMinutes == 0) {
	print "    Reminder preference set to Never.  Nothing to do for this account.\n";
	return 0;
    }
    print "    Reminder preference: $triggerMinutes minutes before\n";

    # Create temp directory to save exported ics files.
    my $username = $email;
    $username =~ s/\@.*//;
    my $pwd = getcwd();
    my $outdirBase = getOutdir();
    my $outdir = "$outdirBase/$username";
    mkpath($outdir);
    if (! -d $outdir) {
        print STDERR "Can't create temp directory $outdir\n";
	exit(1);
    }

    # Get the list of calendar folders.  (one zmmailbox call)
    my %calendars;  # key = id, value = REST path
    my @foldersOutput = qx($ZMMAILBOX -z -m $email gaf);
    foreach my $lineFolders (@foldersOutput) {
	chomp($lineFolders);
	$lineFolders =~ s/^\s+//;
	my @fields = split(/\s+/, $lineFolders, 5);
	if (scalar(@fields) == 5) {
	    my $view = $fields[1];
	    if ($view eq 'appo') {
		my $folderId = $fields[0];
		my $path = $fields[4];
		#print "Found Calendar $path\n";
		# Filter out remote folders.  Only fix up calendars owned by
		# the user.
		if ($path =~ /(\s\([^:\(]+:\d+\))$/) {
		    # Don't worry about remote calendars.  Only fix up
		    # calendars owned by the user's mailbox.
		    next;
		}
		if ($path =~ /\s\(([^\(]+)\)$/) {
		    my $base = $`;
		    my $desc = $1;
		    if ($desc =~ /^(http|https|webcal):\/\//) {
			# If description inside parens starts with http://,
			# https:// or webcal://, assume it's a subscribed
			# calendar.  Path is only what came before the parens.
			$path = $base;
		    }
		}
		if ($path =~ /^\/Trash\//i) {
		    # Skip deleted calendars.
		    next;
		}
		$calendars{$folderId} = $path;
	    }
	}
    }

    # Export all calendar folders.  Only appointments that have instances
    # now or later are exported.  (one zmmailbox call to export all calendars)
    my $nowLong = time() . '000';
    my $exportCmd = '';
    foreach my $calId (keys %calendars) {
	my $path = $calendars{$calId};
	my $icsFile = "$outdir/$calId.ics";
	$exportCmd .=
	    "getRestURL --output $icsFile --startTime $nowLong \"$path\"\n";
    }
    $exportCmd .= "exit\n";
    open(EXPORT_FH, "| $ZMMAILBOX -z -m $email > /dev/null")
	or die "Can't run zmmailbox to export calendars";
    print EXPORT_FH $exportCmd;
    close(EXPORT_FH);

    my $numFixedTotal = 0;
    # Scan all exported ics files and figure out appointments that need
    # reminder inserted.  Those that need fixup are saved to new ics files.
    # (one file per calendar folder)
    my $fixupCmd = '';
    foreach my $calId (keys %calendars) {
	my $path = $calendars{$calId};
	my $icsFile = "$outdir/$calId.ics";

	if (! -e $icsFile) {
	    print "    Skipping calendar $path because export file $icsFile was not found\n";
	    next;
	}

	my $outIcsFile = "$outdir/$calId-fixed.ics";
	my $numFixed = fixupIcsFile($icsFile, $outIcsFile, $triggerMinutes);
	if ($numFixed > 0) {
	    $fixupCmd .=
		"postRestURL --ignore -c text/calendar \"$path\" $outIcsFile\n";
	    print "    Calendar $path has $numFixed VEVENTs needing update\n";
	} else {
	    print "    Calendar $path needs no update\n";
	}
	$numFixedTotal += $numFixed;
    }
    print "    VEVENTs updated: $numFixedTotal\n";

    # Import the fixed-up ics files.  (one zmmailbox call for all folders)
    if ($fixupCmd ne '') {
	$fixupCmd .= "exit\n";
	open(FIXUP_FH, "| $ZMMAILBOX -z -m $email > /dev/null")
	    or die "Can't run zmmailbox to import fixed calendars";
	print FIXUP_FH $fixupCmd;
	close(FIXUP_FH);
    }

    # Comment out this line if you need to debug.
    rmtree($outdir);

    return $numFixedTotal;
}

sub fixupAllLocalUsers() {
    print "Fetching account list...\n";
    my $listFile = getOutdir() . "/accounts.list";
    my $server = getLocalServerName();
    # Get all accounts and calendar resources on this host.
    system("$ZMPROV -l gaa -s $server > $listFile");
    system("$ZMPROV -l gacr -s $server >> $listFile");
    my $numTotalAccounts = qx(grep \@ $listFile | wc -l);
    chomp($numTotalAccounts);
    $numTotalAccounts =~ s/^\s+//;
    $numTotalAccounts =~ s/\s+$//;
    print "Total $numTotalAccounts accounts to examine\n";

    print "\n";

    my $startTime = time();
    my $segmentStartTime = $startTime;
    my $segmentSize = 10;

    my $numProcessedAccounts = 0;
    my $numFixedEvents = 0;
    my $numFixedAccounts = 0;
    my $line;
    open(ACCOUNTS_FH, "< $listFile")
	or die("Can't open account list file: $!");
    while (defined($line = <ACCOUNTS_FH>)) {
	chomp($line);
	my $numFixed = fixupOneUser($line);
	$numFixedEvents += $numFixed;
	if ($numFixed > 0) {
	    $numFixedAccounts++;
	}
	$numProcessedAccounts++;
	print "\n";
	if ($numProcessedAccounts % $segmentSize == 0) {
	    printf("[PROGRESS: %d out of %d accounts; Updated %d VEVENTs in %d accounts]\n",
		   $numProcessedAccounts, $numTotalAccounts, $numFixedEvents, $numFixedAccounts);
	    my $now = time();
	    my $segmentElapsedTime = $now - $segmentStartTime;
	    $segmentStartTime = $now;

	    my $numAccountsLeft = $numTotalAccounts - $numProcessedAccounts;
	    if ($numAccountsLeft > 0) {
		my $eta = $segmentElapsedTime * $numAccountsLeft / $segmentSize;
		my $etaStr = getETA($eta);
		print "[ETA: $etaStr (based on last $segmentSize accounts)]\n";
	    }
	    print "\n";
	}
    }
    close(ACCOUNTS_FH);
    printf("FINISHED: %d accounts; Updated %d VEVENTs in %d accounts\n",
	   $numProcessedAccounts, $numFixedEvents, $numFixedAccounts);

    unlink($listFile);
}


sub usage() {
    my $script = $0;
    print <<_USAGE_;
Purpose: Fix up appointments without reminders by adding reminders based on user preference.
Usage: $0 <options>
    -a <email> - fix the named account
    -a all     - fix all accounts on this server
    -o <output directory> - where temp files are created;
                            default is current working directory
_USAGE_
    exit(1);
}

#
# main
#

my $account;
my $outdir;
my $opts_good = GetOptions(
    'account=s' => \$account,
    'outdir=s'  => \$outdir
    );
if (!$opts_good || !$account) {
    usage();
}

$OUTDIR = defined($outdir) ? $outdir : getcwd();
if (! -d $OUTDIR) {
    print STDERR "ERROR: Output directory $OUTDIR does not exist\n\n";
    usage();
}
if (! -w $OUTDIR) {
    print STDERR "ERROR: No write permission on output directory $OUTDIR\n\n";
    usage();
}

if (lc($account) eq 'all') {
    fixupAllLocalUsers();
} else {
    fixupOneUser($account);
}
