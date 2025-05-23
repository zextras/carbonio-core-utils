#!/usr/bin/perl -w

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

use strict;
use lib "/opt/zextras/common/lib/perl5";
use File::Basename;
use Zextras::Mon::Stat;
use Zextras::Util::Systemd;
use POSIX qw(setsid);

my @TOOL_ALL        = ( 'zmstat-proc', 'zmstat-cpu', 'zmstat-vm', 'zmstat-io -x', 'zmstat-df', 'zmstat-io', 'zmstat-fd', 'zmstat-allprocs', );

my $TOOL_MYSQL    = 'zmstat-mysql';
my $TOOL_NGINX    = 'zmstat-nginx';
my $TOOL_MTAQUEUE = 'zmstat-mtaqueue';
my $TOOL_LDAP     = 'zmstat-ldap';

setsid;

zmstatInit();

sub arrayContains($$) {
    my ( $arrayRef, $val ) = @_;
    foreach my $elem (@$arrayRef) {
        chomp($elem);
        if ( $elem eq $val ) {
            return 1;
        }
    }
    return 0;
}

sub getProcList() {
    my @procs;
    my @services;
    my $all    = 0;
    my $server = getZimbraServerHostname();
    if ( -f "/opt/zextras/conf/stats.conf" ) {
        open F, "/opt/zextras/conf/stats.conf";
        @services = <F>;
        close F;
        chomp @services;
        map { s/service // } @services;
    }
    else {
        if ($server) {
            eval { @services = qx(zmprov -l gs $server zimbraServiceEnabled | grep -i zimbraServiceEnabled | sed -e 's/^zimbraServiceEnabled: //'); };
        }
    }
    if ( scalar(@services) < 1 ) {
        print STDERR "Unable to determine service list on this host. Assuming all.\n";
        $all = 1;
    }

    if ( $all || arrayContains( \@services, 'mailbox' ) ) {
        push( @procs, 'mailbox', 'mysql' );
    }
    if ( $all || arrayContains( \@services, 'proxy' ) ) {
        push( @procs, 'nginx' );
    }
    if ( $all || arrayContains( \@services, 'ldap' ) ) {
        push( @procs, 'ldap' );
    }
    if ( $all || arrayContains( \@services, 'mta' ) ) {
        push( @procs, 'mta' );
    }
    if ( $all || arrayContains( \@services, 'antispam' ) ) {
        push( @procs, 'amavisd' );
    }
    if ( $all || arrayContains( \@services, 'antivirus' ) ) {
        push( @procs, 'clam' );
    }
    return join( ' ', @procs );
}

sub getPidFiles() {
    my @pids;
    my $piddir = getPidFileDir();
    if ( -e $piddir ) {
        opendir( DIR, $piddir ) || die "Unable to opendir $piddir: $!";
        my @pidfiles = readdir(DIR);
        foreach my $file (@pidfiles) {
            next
              if ( $file =~ /fd-real/ );    # can't kill/test: running as root
            if ( $file =~ /\.pid$/ ) {
                push( @pids, "$piddir/$file" );
            }
        }
        closedir(DIR);
    }
    return @pids;
}

sub startRestart() {
    my $procs   = getProcList();
    my $doNginx = $procs =~ /\bnginx\b/;
    my $doMysql =
      ( -x "/opt/zextras/common/sbin/mysqld" && -l "/opt/zextras/mailboxd" )
      ? 1
      : 0;
    my $doMtaQueue =
      ( -x "/opt/zextras/common/sbin/postqueue" && $procs =~ /\bmta\b/ )
      ? 1
      : 0;
    my $doLdap    = -x "/opt/zextras/common/libexec/slapd" ? 1 : 0;
    my $outfile   = getZmstatRoot() . "/zmstat.out";
    my $scriptDir = dirname($0);
    my $parentDir = dirname($scriptDir);
    my $toolpath  = "$parentDir/libexec";
    my @pids      = getPidFiles();

    if ( scalar(@pids) == 0 ) {
        foreach my $tool (@TOOL_ALL) {
            my $cmd = "$toolpath/$tool";
            print "Invoking: $cmd\n";
            system("$cmd >> $outfile 2>&1 &");
        }
        if ($doMysql) {
            my $cmd = "$toolpath/$TOOL_MYSQL";
            print "Invoking: $cmd\n";
            system("$cmd >> $outfile 2>&1 &");
        }
        if ($doMtaQueue) {
            my $cmd = "$toolpath/$TOOL_MTAQUEUE";
            print "Invoking: $cmd\n";
            system("$cmd >> $outfile 2>&1 &");
        }
        if ($doNginx) {
            my $cmd = "$toolpath/$TOOL_NGINX";
            print "Invoking: $cmd\n";
            system("$cmd >> $outfile 2>&1 &");
        }
        if ($doLdap) {
            my $cmd = "$toolpath/$TOOL_LDAP";
            print "Invoking: $cmd\n";
            system("$cmd >> $outfile 2>&1 &");
        }
    }
    else {
        my %procs;
        foreach my $pidFile (@pids) {
            my $pid  = readPidFile($pidFile);
            my $proc = $pidFile;
            $proc =~ s/\.pid//;
            $proc =~ s/.*pid\///;
            if ( kill( 0, $pid ) ) {
                print "$proc already running, skipping.\n";
                if (   $proc eq "zmstat-mysql"
                    || $proc eq "zmstat-mtaqueue"
                    || $proc eq "zmstat-nginx"
                    || $proc eq "zmstat-ldap" )
                {
                    $procs{$proc} = 1;
                }
                else {
                    if ( $proc eq "zmstat-io-x" ) {
                        $proc = "zmstat-io -x";
                    }
                    @TOOL_ALL = grep !/^($proc)$/, @TOOL_ALL;
                }
            }
        }
        foreach my $tool (@TOOL_ALL) {
            my $cmd = "$toolpath/$tool";
            print "Invoking: $cmd\n";
            system("$cmd >> $outfile 2>&1 &");
        }
        if ( $doMysql && !$procs{"zmstat-mysql"} ) {
            my $cmd = "$toolpath/$TOOL_MYSQL";
            print "Invoking: $cmd\n";
            system("$cmd >> $outfile 2>&1 &");
        }
        if ( $doMtaQueue && !$procs{"zmstat-mtaqueue"} ) {
            my $cmd = "$toolpath/$TOOL_MTAQUEUE";
            print "Invoking: $cmd\n";
            system("$cmd >> $outfile 2>&1 &");
        }
        if ( $doNginx && !$procs{"zmstat-nginx"} ) {
            my $cmd = "$toolpath/$TOOL_NGINX";
            print "Invoking: $cmd\n";
            system("$cmd >> $outfile 2>&1 &");
        }
        if ( $doLdap && !$procs{"zmstat-ldap"} ) {
            my $cmd = "$toolpath/$TOOL_LDAP";
            print "Invoking: $cmd\n";
            system("$cmd >> $outfile 2>&1 &");
        }
    }
}

sub stopRestart() {
    my @pids = getPidFiles();
    foreach my $pidFile (@pids) {
        my $pid = readPidFile($pidFile);
        if ($pid) {
            print "Terminating process $pid\n";
            if ( !kill( 0, $pid ) ) {
                unlink($pidFile);
            }
            elsif ( kill( 15, $pid ) == 1 ) {    # SIGTERM
                unlink($pidFile);
            }
        }
    }
}

sub usage() {
    print STDERR <<_USAGE_;
Usage: zmstatctl start|stop|restart|status|rotate
Starts/stops/restarts monitoring processes, checks status, or rotates logs.
_USAGE_
    exit(1);
}

#
# main
#

my $cmd = $ARGV[0];
if ( defined($cmd) ) {
    if ( $cmd eq 'stop' || $cmd eq 'restart' ) {
        if ( isSystemd() ) {
            systemdPrint();
        }
        if ( $cmd eq 'stop' ) {
            if ( isSystemd() ) {
                systemdPrint();
            }
            exit(0);
        }
    }
    if ( $cmd eq 'stop-systemd' || $cmd eq 'restart-systemd' ) {
        stopRestart();
        if ( $cmd eq 'stop-systemd' ) {
            exit(0);
        }
    }
    if ( $cmd eq 'start' || $cmd eq 'restart' ) {
        if ( isSystemd() ) {
            systemdPrint();
        }
        startRestart();
    }
    if ( $cmd eq 'start-systemd' || $cmd eq 'restart-systemd' ) {
        startRestart();
    }
    elsif ( $cmd eq 'status' ) {
        my @pids = getPidFiles();
        if ( scalar(@pids) == 0 ) {

            # zmstat must not be running if there is no pid file
            # Must exit with code 1 in this case
            exit(1);
        }
        my $numDeadProcs = 0;
        foreach my $pidFile (@pids) {
            my $pid = readPidFile($pidFile);
            if ($pid) {
                if ( !kill( 0, $pid ) ) {
                    print STDERR "process $pid in $pidFile not running\n";
                    $numDeadProcs++;
                }
                else {
                    $pidFile =~ m#/.*/(.*?)\.pid#;
                    print STDERR "Running: $1\n";
                }
            }
        }
        exit( $numDeadProcs > 0 ? 1 : 0 );
    }
    elsif ( $cmd eq 'rotate' ) {
        my @pids = getPidFiles();
        exit 1 if ( @pids == 0 );
        foreach my $pidFile (@pids) {
            my $pid = readPidFile($pidFile);
            if ($pid) {
                print "Sending HUP to process $pid\n";
                my $rc = kill( 1, $pid );    # SIGHUP
                print "PID $pid was not running\n" if !$rc;
            }
        }
    }
}
else {
    usage();
}
