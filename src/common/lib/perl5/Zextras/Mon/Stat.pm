# 
# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only
# 

package Zextras::Mon::Stat;

use Exporter;
@ISA = qw(Exporter);
@EXPORT = qw(
    zmstatInit getZextrasUser getZimbraServerHostname
    getZmstatRoot getZmstatInterval
    percent getTstamp getDate waitUntilNiceRoundSecond
    getPidFileDir readPidFile createPidFile
    getLogFilePath openLogFile rotateLogFile
    readLine
);

use strict;
use File::Basename;
use FileHandle;

our %LC;

sub getLocalConfig(;@) {
    my @vars = @_;
    my $dir = dirname($0);
    my $cmd = "/opt/zextras/bin/zmlocalconfig -q -x";
    if (scalar(@vars) > 0) {
        $cmd .= ' ' . join(' ', @vars);
    }
    open(LCH, "$cmd |") or die "Unable to invoke $cmd: $!";
    my $line;
    while (defined($line = <LCH>)) {
        $line =~ s/[\r\n]*$//;  # Remove trailing CR/LFs.
        my @fields = split(/\s*=\s*/, $line, 2);
        $LC{$fields[0]} = $fields[1];
    }
    close(LCH);
}

sub userCheck() {
    my $loggedIn = `id -un`;
    chomp($loggedIn) if (defined($loggedIn));
    my $expected = $LC{zimbra_user};
    if ($loggedIn ne $expected) {
        print STDERR "Must be user $expected to run this command\n";
        exit(1);
    }
}

sub zmstatInit() {
    getLocalConfig('zimbra_user', 'zimbra_server_hostname',
                   'zmstat_interval', 'zmstat_disk_interval');
    userCheck();
}

sub getZextrasUser() {
    return $LC{'zimbra_user'};
}

sub getZimbraServerHostname() {
    return $LC{'zimbra_server_hostname'};
}

sub getZmstatRoot() {
        return "/opt/zextras/zmstat";
}

sub getZmstatInterval() {
    my $n = $LC{'zmstat_interval'};
    if (!defined($n) || $n + 0 < 1) {
        $n = 30;
    }
    return $n;
}

sub percent($$) {
    my ($val, $total) = @_;
    return sprintf("%.1f", $total > 0 ? $val * 100 / $total : 0);
}

sub getTstamp() {
    my ($sec, $min, $hour, $mday, $mon, $year) =
        localtime();
    return sprintf("%02d/%02d/%04d %02d:%02d:%02d",
                   $mon + 1, $mday, $year + 1900,
                   $hour, $min, $sec);
}

sub getDate() {
    my ($sec, $min, $hour, $mday, $mon, $year) = localtime();
    return sprintf("%04d-%02d-%02d", $year + 1900, $mon + 1, $mday);
}

sub waitUntilNiceRoundSecond($) {
    # Maximum interval allowed is 1 day (24 * 60 * 60 seconds)
    my $maxInterval = 24 * 60 * 60;
    my $interval = shift;
    $interval %= $maxInterval;
    $interval = $interval ? $interval : $maxInterval;
    while (1) {
        my ($sec, $min, $hour) = localtime();
        my $t = $hour * 60 * 60 + $min * 60 + $sec;
        my $howlong = $t % $interval;
        last if ($howlong == 0);
        select(undef, undef, undef, 0.05);
    }
    return time;
}

sub getPidFileDir() {
    return "/run/carbonio/stats";
}

sub readPidFile($) {
    my $file = shift;
    my $pid = undef;
    if (open(PID, "< $file")) {
        $pid = <PID>;
        close(PID);
        chomp($pid) if (defined($pid));
    }
    return $pid;
}

# Check pid file to see if this process is a duplicate.
# If not, create the pid file.
sub createPidFile($) {
    my $name = shift;
    my $zmstatDir = getZmstatRoot();
    my $pidDir = getPidFileDir();
    my $pidFile = "$pidDir/$name";
    if (-e $pidFile) {
        my $pid = readPidFile($pidFile);
        if ($pid) {
            if (kill(0, $pid)) {
                # Already running.
                print STDERR "$name: Already running as pid $pid\n";
                exit(0);
            }
            unlink($pidFile);
        }
    }
    if (! -e $zmstatDir) {
        die "$zmstatDir does not exist";
    }
    if (! -e $pidDir) {
        mkdir($pidDir, 0755);
    }
    open(PID, "> $pidFile") || die "Unable to create pid file $pidFile: $!";
    print PID "$$\n";
    close(PID);
}

sub getLogFilePath($) {
    my $fname = shift;
    return getZmstatRoot() . "/$fname";
}

sub openLogFile($;$) {
    my ($logfile, $heading) = @_;
    my $fh = new FileHandle;
    if (defined($logfile) && $logfile ne '' && $logfile ne '-') {
        my $dir = File::Basename::dirname($logfile);
        if (! -e $dir) {
            mkdir($dir, 0755) || die "Unable to create log directory $dir: $!";
            my (undef,undef,$uid,$gid) = getpwnam('zextras');
            chown $uid,$gid,$dir;
        }
        if (-f $logfile) { # check for stale data
        	my $stale = 0;
        	my $date = "";
        	my $today = getDate();
        	$fh->open("<$logfile") || die "Unable to read existing logfile: $!";
        	while (<$fh>) {
        		if (/^(\d{2})\/(\d{2})\/(\d{4})/o) {
        			$date = "$3-$1-$2";
        		}
        	}
        	$stale = 1 if $date ne $today;
        	if ($stale) {
        		print STDERR "$logfile was stale ($date) pre-rotating\n";
        		return rotateLogFile($fh, $logfile, $heading, $date);
        	}
        	$fh->close();
        }
        $fh->open(">> $logfile") || die "Unable to open log file $logfile: $!";
    } else {
        $fh = *STDOUT;
    }
    if ($heading) {
        $fh->print($heading);
        $fh->print("\n");
        $fh->flush();
    }
    return $fh;
}

sub rotateLogFile($$;$$) {
    my ($fh, $logfile, $heading, $date) = @_;
    my ($name, $path) = File::Basename::fileparse($logfile);
    if (!defined($date)) {
        $date = getDate();
    }
    my $rotatedir = "$path/$date";
    mkdir($rotatedir, 0755);
    if (! -d $rotatedir) {
        die "Unable to create log rotation directory $rotatedir";
    }
    my (undef,undef,$uid,$gid) = getpwnam('zextras');
    chown $uid,$gid,$rotatedir;
    $fh->close() if defined $fh;

    my $rotatefile = "$rotatedir/$name";

    # If previous .gz is there, unzip it.
    my $rotateGz = "$rotatefile.gz";
    if (-e $rotateGz) {
    	if (-e $rotatefile) {
    	    unlink($rotatefile);
    	}
    	system("gzip -d $rotateGz");
    }

    # Rename or concatenate, with gzip.
    if (! -e $rotatefile) {
        my $rc = system("cat $logfile | gzip -c > $rotateGz");
        $rc >>= 8;
        if ($rc) {
        	die "Unable to move $logfile to $rotateGz";
        }
        unlink($logfile);
    } else {
        my $rc = system("cat $rotatefile $logfile | gzip -c > $rotateGz");
        $rc >>= 8;
        if ($rc) {
            die "Unable to concatenate $logfile and $rotatefile to $rotateGz";
        }
        unlink($rotatefile, $logfile);
    }

    return openLogFile($logfile, $heading);
}

sub readLine($$) {
    my ($rh, $skip_empty) = @_;
    my $line = '';
    while ($line eq '') {
        $line = <$rh>;
        return if (!defined($line));  # EOF
        chomp($line);
        last if (!$skip_empty);
    }
    return $line;
}

1;
