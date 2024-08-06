#!/usr/bin/perl

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

use strict;

use lib "/opt/zextras/common/lib/perl5";
use Zimbra::Util::Common;

use Getopt::Long;
use POSIX qw(strftime);
use File::Spec;
use File::Path;
use File::Copy qw/cp/;
use Zimbra::Mon::Zmstat;
use Digest::MD5;

use vars qw(
  $VERSION $PID_FILE $DEFAULT_DEST $DLOGDIR $JMAP $JAVA $JINFO $DEFAULT_TIMEOUT
  $HAVE_GCORE $HAVE_PSTACK $HAVE_LSOF $HAVE_DMESG $LOG_FILE $ZMSTAT_CONF
  $ZMDUMPENV $ZMLOCALCONFIG $ZMPROV $ZMHOSTNAME $SU $HAVE_NETSTAT $HAVE_MYSQL $ZMMYTOP $ZMINNOTOP $HAVE_NETWORK
);

chomp( $ZMHOSTNAME = qx(/opt/zextras/bin/zmhostname) );

my $zimbra_tmp_directory = "/opt/zextras/data/tmp";
if ( -f "/opt/zextras/bin/zmlocalconfig" ) {
    $zimbra_tmp_directory =
      qx(/opt/zextras/bin/zmlocalconfig -x -s -m nokey zimbra_tmp_directory);
    chomp($zimbra_tmp_directory);
}

if ( !-d $zimbra_tmp_directory ) {
    File::Path::mkpath("$zimbra_tmp_directory");
}

$DEFAULT_DEST = "$zimbra_tmp_directory";
$DLOGDIR = "zmdiaglog-$ZMHOSTNAME."
  . strftime( "%Y%m%d-%H%M%S", localtime() ) . "."
  . $$;
$DEFAULT_TIMEOUT                    = 120;
$JMAP                               = '/opt/zextras/common/bin/jmap';
$JAVA                               = '/opt/zextras/common/lib/jvm/java/bin/java';
$JINFO                              = '/opt/zextras/common/lib/jvm/java/bin/jinfo';
$Getopt::Std::STANDARD_HELP_VERSION = 1;
$VERSION                            = 0.1;
$HAVE_GCORE                         = has_cmd('gcore');
$HAVE_PSTACK                        = has_cmd('pstack');
$HAVE_LSOF                          = has_cmd('lsof');
$HAVE_DMESG                         = has_cmd('dmesg');
$HAVE_NETSTAT                       = has_cmd('netstat');
$HAVE_MYSQL                         = has_cmd('/opt/zextras/common/bin/mysql');
$LOG_FILE                           = 'zmdiag.log';
$ZMSTAT_CONF                        = '/opt/zextras/conf/zmstat-chart.xml';
$ZMDUMPENV                          = '/opt/zextras/bin/zmdumpenv';
$ZMLOCALCONFIG                      = '/opt/zextras/bin/zmlocalconfig';
$ZMPROV                             = '/opt/zextras/bin/zmprov -l';
$ZMMYTOP                            = '/opt/zextras/bin/zmmytop --nocolor -b';
$ZMINNOTOP = '/opt/zextras/bin/zminnotop --nocolor --nonint';
$SU        = "su - zextras -c ";
$HAVE_NETWORK                       = has_cmd('/opt/zextras/bin/zxsuite');

sub logmsg($) {
    my $msg = shift;
    open( LOGFILE, ">>$LOG_FILE" );
    my $logstamp = strftime( "%F %T", localtime() );
    print LOGFILE "$logstamp $msg";
    close(LOGFILE);
    print $msg;
}

sub get_java_version() {
    open( JAVA, "$JAVA -version 2>&1 |" )
      || die "Cannot determine java version: $!";
    my $version = <JAVA>;
    close(JAVA);
    $version;
}

sub save_heap_info($$$$) {
    my ( $version, $destination, $pid, $timeout ) = @_;
    my $histo_cmd;
    my $dump_cmd;
    my $dump_file;

    $histo_cmd = "$JMAP -histo:live $pid";
    $dump_file = "$destination/heapdump-live.hprof";
    $dump_cmd  = " '$JMAP -dump:live,file=$dump_file $pid'";
    logmsg "Retrieving JVM $version heap histogram\n";
    exec_with_timeout( " '$histo_cmd' > heap.histo 2>&1", $timeout );
    logmsg "Saving JVM $version heapdump\n";
    my $success =  system("bash -c $dump_cmd "); 
    my $dumped = -f "$dump_file";
    $dumped && $success;
}

sub save_jvm_core($$) {
    my ( $JAVA_VERSION, $mailboxd_pid ) = @_;
    if ($HAVE_GCORE) {
        logmsg "Live heap dump could not be collected. Collecting JVM coredump\n";

        # longer timeout for gcore because it can take a lot longer
        my $got_core = exec_with_timeout( "gcore $mailboxd_pid", 300 );
        logmsg "Converting coredump to heap snapshot\n";
        if ($got_core) {
            qx($JMAP -dump:file=heapdump.snapshot $JAVA core.$mailboxd_pid);
        }
        unlink("core.$mailboxd_pid");
    }
    elsif ( !$HAVE_GCORE ) {
        logmsg "'gcore' (gdb) is not installed, will not collect JVM coredump\n";
    }
}

sub save_jinfo($) {
    my ($pid) = @_;
    my $jinfo_cmd;
    my $out_file = "jinfo.out";

    $jinfo_cmd = "$JINFO $pid";
    logmsg "Saving Java configuration info for process $pid to $out_file\n";
    qx($jinfo_cmd > $out_file 2>&1);
}

sub has_cmd($) {
    my $cmd = shift;
    my $r   = system("bash -c 'type -P $cmd' > /dev/null");
    ( $r >> 8 ) == 0;
}

sub get_pid() {
    my $pid = 0;
    if ( !$pid ) {
        eval {
            $pid = qx(pgrep -f '/opt/zextras/.*/java.*mailboxd');
            chomp($pid);
        };
        if ( !$pid ) {
            logmsg "Unable to determine mailboxd pid\n";
        }
    }
    return $pid;
}

sub invoke_thread_dump($$) {
    my ( $i, $ts ) = @_;
    system("bash -c 'cd /opt/zextras/bin/; ./zmthrdump -i' > threaddump.$i.$ts 2>&1");
}

sub collect_thread_stats($) {
    my $pid = shift;
    return undef unless ( -d "/proc" );
    open( STATS, "cat /proc/$pid/task/*/stat |" );
    my @stats = <STATS>;
    close STATS;
    return join( "", @stats );
}

sub exec_with_timeout($$) {
    my $cmd     = shift;
    my $timeout = shift;
    my $result  = 1;

    my $r = fork();
    if ($r) {    # parent
        my $reaped = 0;
        local $SIG{'CHLD'} = sub {
            waitpid( $r, 0 );    # reap
            $reaped = 1;
        };
        sleep($timeout);
        if ( !$reaped ) {
            logmsg "Timeout exceeded executing: '$cmd', killing\n";
            kill( 'SIGKILL', $r );
            $result = 0;
        }
    }
    else {                       # child
        my @cmdary = ( '/bin/sh', '-c', $cmd );
        close(STDOUT);
        close(STDERR);
        open( STDOUT, ">>$LOG_FILE" );
        open( STDERR, ">>$LOG_FILE" );
        exec(@cmdary);
        die "Unable to exec command: $!";
    }
    $result;
}

sub usage {
    my $fd = shift;
    print $fd <<"EOF";
Usage:
zmdiaglog [-h]
zmdiaglog [-a | -c] [-d DESTINATION] [-t TIMEOUT] [-j] [-z | -Z]

    -a    - Do everything: plus collect live JVM heap dump
    -c    - Use instead of -a to parse heap dump from JVM core dump
    -d    - Log destination (Default $DEFAULT_DEST)
    -t    - Timeout in seconds for hanging commands (Default $DEFAULT_TIMEOUT)
    -j    - Also include the output of /opt/zextras/libexec/zmjavawatch
    -z    - Archive data collected by zmdiaglog to a bzip2 tar archive and leave data
            collection directory intact.
    -Z    - Archive data collected by zmdiaglog to a bzip2 tar archive AND remove
            data collection directory.
    -h    - Display this help message.
EOF
}

sub get_mysql_data() {
    if ($HAVE_MYSQL) {
        my $mysql_cmd = "/opt/zextras/bin/mysql";
        logmsg "Collecting MySQL data ";
        logmsg ".";
        system("echo \"show engine innodb status\\G;\" | $SU $mysql_cmd > mysql-innodb-status.txt");
        logmsg ".";
        system("echo \"show global status;\" | $SU $mysql_cmd > mysql-show-global-status.txt");
        logmsg ".";
        system("echo \"select * from information_schema.processlist;\" | $SU $mysql_cmd > mysql-information_schema.processlist.txt");
        logmsg " done.";
    }
}

sub remove_data_dir($) {
    my $dir = shift;
    logmsg "Removing data collection directory\n";
    chdir('..');
    File::Path::remove_tree($dir);
    print "$dir removed\n";
    print "$0 run complete\n";
}

# "main"
sub run() {
    Getopt::Long::Configure ("bundling");
    my %options = ('t' => $DEFAULT_TIMEOUT);
    my $opt_result =
        GetOptions (\%options,
                    't=i',
                    'd:s',
                    'h' => sub{ usage( \*STDERR ); exit 0; },
                    'j', 'a', 'c', 'z', 'Z',
                    '' => sub{ print "Error: '-' must be followed by a valid option.\n";
                               usage( \*STDERR );
                               exit 1; },
                    '<>' => sub{ warn("Error: unexpected argument(s): @_\n");
                                 usage( \*STDERR );
                                 exit 1; }
                   );

    die "Error: Timeout must be greater than 0.\n" unless $options{t} > 0;
    $options{d} = $DEFAULT_DEST if ( $options{d} eq "" );

    if (! $opt_result) {
        usage( \*STDERR );
        exit();
    }

    if ( $< != 0 ) {
        print STDERR "zmdiaglog needs to be run as root\n";
        exit 1;
    }

    if ( $options{a} && $options{c} ) {
        print STDERR "ERROR: Specify only one of -a or -c.\n";
        usage( \*STDERR );
        exit 1;
    }

    my $destination = "$options{d}/$DLOGDIR";
    $destination = File::Spec->rel2abs($destination);
    my $timeout = $options{t};

    if ( !-d $destination ) {
        File::Path::mkpath("$destination");
    }
    my ( undef, undef, $uid, $gid ) = getpwnam('zextras');

    chown $uid, $gid, $destination;

    {
        local $> = $uid;
        print STDERR "$destination is not writable by user zextras\n" and exit 1
          if !-w $destination;
    }

    chdir($destination);

    my $mailboxd_pid = get_pid();
    logmsg "No '-a' argument, skipping heap/coredump collection.\n"
      if ( !$options{a} );
    logmsg "Saving diagnostic logging output to: $destination\n";

    my $JAVA_VERSION = get_java_version();
    logmsg "Java version: $JAVA_VERSION\n";
    if ($mailboxd_pid) {
        logmsg "mailboxd pid: $mailboxd_pid\n";
        save_jinfo($mailboxd_pid);

        for ( my $i = 1 ; $i <= 10 ; $i++ ) {
            logmsg "Collecting thread stats/stacks: $i of 10\n";
            my $TS = strftime( "%H-%M-%S", localtime() );

            invoke_thread_dump( $i, $TS );
            my $top_cmd = "top -bc -n1 > top.$i.$TS 2>&1";
            system($top_cmd);
            system("ps -auxw > ps.$i.$TS 2>&1");
            my $netstat = "netstat -anp > netstat.$i.$TS 2>&1";
            system($netstat);

            my $stats = collect_thread_stats($mailboxd_pid);
            open( STATS, ">proc-stats.$i.$TS" ) || warn $i;
            print STATS $stats;
            close(STATS);

            sleep(5);
        }

        if ($HAVE_PSTACK) {
            for ( my $i = 1 ; $i <= 3 ; $i++ ) {
                logmsg "Collecting process stack: $i of 3\n";
                my $TS = strftime( "%H-%M-%S", localtime() );
                exec_with_timeout( "pstack $mailboxd_pid > pstack.$i.$TS 2>&1",
                    $timeout );
                sleep(5);
            }
        }
        else {
            logmsg "'pstack' is not installed, will not collect process stacks\n";
        }

        mkdir("$destination/db");
        logmsg "Collecting database server statistics...\n";

        for ( my $i = 1 ; $i <= 10 ; $i++ ) {
            logmsg "\tDB Stats: zmmytop $i of 10\n";
            my $TS = strftime( "%H-%M-%S", localtime() );
            my $zmmytop = qq($SU "$ZMMYTOP" > db/zmmytop.$i.$TS 2>&1);
            system($zmmytop);
        }

        my @INNOTOP = (
            {
                mode        => "A",
                description => "Health Dashboard",
                count       => "5",
                filename    => "health_dashboard",
            },
            {
                mode        => "B",
                description => "InnoDB Buffers",
                count       => "5",
                filename    => "innodb_buffers",
            },
            {
                mode        => "C",
                description => "Command Summary",
                count       => "1",
                filename    => "command_summary",
            },
            {
                mode        => "D",
                description => "InnoDB Deadlocks",
                count       => "5",
                filename    => "innodb_deadlocks",
            },
            {
                mode        => "F",
                description => "InnoDB Foreign Key Errors",
                count       => "5",
                filename    => "innodb_fk_errors",
            },
            {
                mode        => "I",
                description => "InnoDB I/O Info",
                count       => "5",
                filename    => "innodb_io_info",
            },
            {
                mode        => "K",
                description => "InnoDB Lock Waits",
                count       => "5",
                filename    => "innodb_lock_waits",
            },
            {
                mode        => "L",
                description => "Locks",
                count       => "5",
                filename    => "locks",
            },
            {
                mode        => "O",
                description => "Open Tables",
                count       => "5",
                filename    => "open_tables",
            },
            {
                mode        => "U",
                description => "User Statistics",
                count       => "5",
                filename    => "user_stats",
            },
            {
                mode        => "Q",
                description => "Query List ",
                count       => "5",
                filename    => "query_list",
            },
            {
                mode        => "R",
                description => "InnoDB Row Operations and Semaphores ",
                count       => "5",
                filename    => "innodb_row_ops_semephores",
            },
            {
                mode        => "S",
                description => "Variables & Status",
                count       => "5",
                filename    => "variables",
            },
            {
                mode        => "T",
                description => "InnoDB Transactions ",
                count       => "5",
                filename    => "innodb_transactions",
            },
        );

        logmsg "Collecting database InnodDB statistics...\n";

        for my $href (@INNOTOP) {
            my $mode        = $href->{mode};
            my $count       = $href->{count};
            my $filename    = $href->{filename};
            my $description = $href->{description};
            logmsg "\tInnoDB Stats: zminnotop $description\n";
            my $headlen    = length($description) + 6;
            my $headtopbot = "=" x $headlen;
            open( ITOPFILE, ">>db/zminnotop.$filename" );
            print ITOPFILE "$headtopbot\n** $description **\n$headtopbot\n";
            close(ITOPFILE);
            my $zminnotop = qq($SU "$ZMINNOTOP --mode $mode --count $count -d 1" >> db/zminnotop.$filename 2>&1);
            system($zminnotop);
        }

        if ( $options{j} ) {
            system("/opt/zextras/libexec/zmjavawatch > zmjavawatch.log 2>&1");
        }
        my $dumped =
          save_heap_info( $JAVA_VERSION, $destination, $mailboxd_pid, $timeout )
          if ( $options{a} );

        save_jvm_core( $JAVA_VERSION, $mailboxd_pid )
          if ( $options{c} || ( !$dumped && $options{a} ) );

        logmsg "Heap dump processing complete. It is now safe to restart mailboxd.\n";
    }
    else {
        logmsg "Not a mailboxd node or mailboxd not running. Not performing threaddump and pstack collection activities.\n";
        for ( my $i = 1 ; $i <= 10 ; $i++ ) {
            logmsg "Collecting top/ps/netstat: $i of 10\n";
            my $TS = strftime( "%H-%M-%S", localtime() );
            my $top_cmd = "top -bc -n1 > top.$i.$TS 2>&1";
            system($top_cmd);
            system("ps -auxw > ps.$i.$TS 2>&1");
            my $netstat = "netstat -anp > netstat.$i.$TS 2>&1";
            system($netstat);
            sleep(5);
        }
    }

    if ($HAVE_LSOF) {
        logmsg "Saving output of LSOF\n";
        qx(lsof -n > lsof.out 2>&1);
    }
    else {
        logmsg "'lsof' is not installed, will not check fd status\n";
    }

    if ($HAVE_DMESG) {
        logmsg "Saving output of DMESG\n";
        qx(dmesg > dmesg.out 2>&1);
    }
    else {
        logmsg "'dmesg' is not installed, skipping check.\n";
    }

    if ( has_cmd('dmidecode') ) {
        logmsg "Saving output of dmidecode\n";
        qx(dmidecode > dmidecode.out 2>&1);
    }
    else {
        logmsg "'dmidecode' is not installed, skipping check.\n";
    }

    if ( has_cmd('vgs') ) {
        logmsg "Capturing LVM information\n";
        qx(vgs -v > vgs.out 2>&1);
        qx(lvs -v > lvs.out 2>&1);
        qx(pvs -v > pvs.out 2>&1);
    }
    else {
        logmsg "LVM not found, not capturing LVM information.\n";
    }

    if ($HAVE_NETSTAT) {
        logmsg "Saving netstat statistics\n";
        qx(netstat -s > netstat-s.out 2>&1);
    }
    else {
        logmsg "'netstat' is not installed, skipping check.\n";
    }

    logmsg "Capturing System Information\n";
    qx(iostat -x > iostat.out 2>&1);
    qx(lspci > lspci.out 2>&1);
    qx(lsscsi > lsscsi.out 2>&1);
    qx(lscpu > lscpu.out 2>&1);
    qx(lsblk > lsblk.out 2>&1);
    qx(lsusb > lsusb.out 2>&1);

    logmsg "Saving output of zmdumpenv\n";
    exec_with_timeout( "$SU '$ZMDUMPENV' > zmdumpenv.txt 2>&1", $timeout );
    logmsg "Saving server configuration\n";
    exec_with_timeout( "$SU '$ZMPROV gs $ZMHOSTNAME' > zmprov-gs.txt 2>&1",
        $timeout );
    exec_with_timeout( "$SU '$ZMPROV gacf' > zmprov-gacf.txt 2>&1", $timeout );
    exec_with_timeout(
        "$SU '$ZMLOCALCONFIG -x -s' > zmlocalconfig-x-s.txt 2>&1", $timeout );
    exec_with_timeout( "$SU '$ZMLOCALCONFIG -n' > zmlocalconfig-n.txt 2>&1",
        $timeout );
    exec_with_timeout( "$SU '/opt/zextras/bin/zmvolume -l' > zmvolume.txt 2>&1",
        $timeout );
    exec_with_timeout( "/usr/bin/crontab -l > crontab-root.txt 2>&1",
        $timeout );
    exec_with_timeout(
        "/usr/bin/crontab -u zextras -l > crontab-zimbra.txt 2>&1", $timeout );
    exec_with_timeout( "du -sh /opt/zextras/redolog > du-redolog.txt 2>&1",
        $timeout );
    exec_with_timeout( "df -hT > df-hT.txt 2>&1", $timeout );

    mkdir("$destination/confs");
    my @conf_files = (
        "/opt/zextras/conf/cbpolicyd.conf",
        "/opt/zextras/conf/localconfig.xml",
        "/opt/zextras/conf/my.cnf",
        "/opt/zextras/common/conf/main.cf",
        "/opt/zextras/common/conf/master.cf",
        "/opt/zextras/conf/zmconfigd.cf"
    );
    cp $_, "$destination/confs" for @conf_files;

    if ($HAVE_NETWORK) {
        mkdir("$destination/confs/network");
        my @network_conf_files = (
            "/opt/zextras/conf/zextras/config",
            "/opt/zextras/conf/zextras/oplog",
            "/opt/zextras/conf/zextras/cluster_config/zextras.json",
            glob("/opt/zextras/conf/zextras/zxadmin/*")
        );
        cp $_, "$destination/confs/network" for @network_conf_files;
    }

    mkdir("$destination/logs");
    mkdir("$destination/stats");
    mkdir("$destination/confs/ld.so.conf");

    if ( !-f $ZMSTAT_CONF ) {
        logmsg "Saving statistics chart config\n";
        open( CONF,     "$SU '/opt/zextras/bin/zmstat-chart-config' |" );
        open( CONF_OUT, ">stats/zmstat-chart.xml" );
        while (<CONF>) {
            print CONF_OUT;
        }
        close(CONF);
        close(CONF_OUT);
    }
    else {
        logmsg "Copying statistics chart config\n";
        cp $ZMSTAT_CONF, "$destination/stats";
    }
    my $today   = strftime( "%Y-%m-%d", localtime( time() ) );
    my $t_today = strftime( "%Y_%m_%d", localtime( time() ) );

    logmsg "Copying current logs\n";
    my @log_files = (
        "/opt/zextras/log/access_log.$today",
        "/opt/zextras/log/audit.log",
        "/opt/zextras/log/cbpolicyd.log",
        "/opt/zextras/log/gc.log",
        "/opt/zextras/log/mailbox.log",
        "/opt/zextras/log/sync.log",
        "/opt/zextras/log/$t_today.trace.log",
        "/opt/zextras/log/zmconfigd.log",
        "/opt/zextras/log/zmmailboxd.out",
        "/var/log/carbonio.log",
        glob("/opt/zextras/db/data/*.err"),
        glob("/opt/zextras/log/hs_err_pid*"),
        glob("/opt/zextras/log/my*.log"),
        glob("/opt/zextras/log/zmsetup*.txt"),
        glob("/tmp/install.log.*"),
        "/opt/zextras/log/mysql-mailboxd.log"
    );
    cp $_, "$destination/logs" for @log_files;

    if ($HAVE_NETWORK) {
        mkdir("$destination/logs/network");
        my @network_log_files = (
            glob("/opt/zextras/log/op_*"),
        );
        cp $_, "$destination/logs/network" for @network_log_files;
    }

    logmsg "Copying file system info and mounts\n";
    my @static_info = ( "/etc/fstab", "/proc/mounts", );

    cp $_, "$destination" for @static_info;

    logmsg "Copying today's statistics\n";
    cp $_, "$destination/stats" for glob("/opt/zextras/zmstat/*.csv");

    my $yesterday = time() - ( 24 * 60 * 60 );
    my $yesterday_stats_dir = strftime( "%Y-%m-%d", localtime($yesterday) );
    if ( -d "/opt/zextras/zmstat/$yesterday_stats_dir" ) {
        logmsg "Copying yesterday's statistics\n";
        mkdir("$destination/stats/$yesterday_stats_dir");
        my $zuser = $Zimbra::Mon::Zmstat::LC{zimbra_user};
        my ( $zuid, $zgid ) = ( getpwnam($zuser) )[ 2, 3 ];
        chown $zuid, $zgid, "$destination/stats/$yesterday_stats_dir";
        cp $_, "$destination/stats/$yesterday_stats_dir"
          for glob("/opt/zextras/zmstat/$yesterday_stats_dir/*");
    }

    my $systemlogfile = "/var/log/messages";
    if ( -f $systemlogfile ) {
        logmsg "Copying system log $systemlogfile\n";
        cp $systemlogfile, "$destination/logs";
    }

    if ( -f "/opt/zextras/log/nginx.log" ) {
        logmsg "Copying nginx log /opt/zextras/log/nginx.log\n";
        cp "/opt/zextras/log/nginx.log", "$destination/logs";
    }

    if ( -f "/opt/zextras/log/nginx.access.log" ) {
        logmsg "Copying nginx access log /opt/zextras/log/nginx.access.log\n";
        cp "/opt/zextras/log/nginx.access.log", "$destination/logs/";
    }

    if ( -f "/etc/ld.so.conf" ) {
        logmsg "Copying ld.so configuration\n";
        my @ld_files = ( "/etc/ld.so.conf", glob("/etc/ld.so.conf.d/*") );
        cp $_, "$destination/confs/ld.so.conf" for @ld_files;
    }
    else {
        logmsg "ld.so.conf not present...skipping copy.\n";
    }

    logmsg "Collecting server list from LDAP\n";
    exec_with_timeout( "$SU '$ZMPROV gas' > zmprov-gas.txt 2>&1",
        $timeout );

    logmsg
      "\n *** Diagnostics collection done. Data stored in $destination/.\n\n";

    chomp( my $dirname = qx(pwd) );
    chomp( $dirname = qx(basename $dirname) );
    if ( $options{z} || $options{Z} ) {
        my $ext = "tar.bz2";
        logmsg "Saving contents of $destination to bzip2 archive $destination.$ext\n";
        $LOG_FILE = "$destination/$LOG_FILE";
        chdir('..');
        my $rc = 0xffff &
          system("nice -n 19 /bin/tar jcf $destination.$ext $dirname >> $LOG_FILE 2>&1");
        if ( ( $rc == 0 ) && ( -e "$destination.$ext" ) ) {
            logmsg "bzip2 archive created\n";
            logmsg "Computing MD5 digest\n";
            open(my $fh, "<", "$destination.$ext")
              or die "cannot open file for reading";
            my $ctx = Digest::MD5->new;
            $ctx->addfile($fh);
            my $md5 = $ctx->hexdigest;
            close $fh;
            logmsg "MD5 digest: $md5\n";
            rename "$destination.$ext", "$destination-$md5.$ext";
            logmsg "\n***Archive $destination-$md5.$ext complete.\n";
            remove_data_dir($destination) if ( $options{Z} );
        }
        else {
            logmsg
"An error occurred creating $destination.$ext. Leaving data collection directory intact.\n";
            logmsg "$0 run complete\n";
        }
    }
    else {
        logmsg "Skipping bzip2 archive creation.\n";
        logmsg "$0 run complete\n";
    }
}

run();