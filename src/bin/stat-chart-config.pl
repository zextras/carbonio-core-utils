#!/usr/bin/perl -w
#
# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only
#

use strict;
use Zextras::Mon::Stat;

zmstatInit();

my $mtaqstatCsv = 'mtaqueue.csv';
my $cpustatCsv  = 'cpu.csv';
my $fdstatCsv   = 'fd.csv';
my $dfstatCsv   = 'df.csv';
my $pstatCsv    = 'proc.csv';
my $allpstatCsv = "allprocs.csv";
my $vmstatCsv   = 'vm.csv';
my $iostatxCsv  = 'io-x.csv';
my $iostatCsv   = 'io.csv';
my $mailboxdCsv = 'mailboxd.csv';
my $nginxCsv    = 'nginx.csv';
my $mysqlCsv    = 'mysql.csv';
my $soapCsv     = 'soap.csv';
my $ldapCsv     = 'ldap.csv';
my $sqlstatsCsv = 'sql.csv';

my @DEVICE_LIST;         # list of device names (e.g. "sda", "sdb")
my %DEVICE_PARTITIONS;   # $DEVICE_PARTITIONS{device} = arrayref of partitions
my %DEVICE_MOUNTPOINTS;  # $DEVICE_MOUNTPOINTS{device} = arrayref of mountpoints
my %MOUNTS;              # $MOUNTS{partition} = mountpoint

my $ZIMBRA_HOSTNAME;
my @ENABLED_PROCS;
my $HAS_MTA     = 0;
my $HAS_MAILBOX = 0;

sub filenameSafe($) {

    # Some device/partitions look like cciss/c0d0p1 and can't be used
    # as prefix of the file name.  Replace '/' with '_'.
    my $dev = shift;
    $dev =~ s/\//_/g;
    return $dev;
}

sub memPoolCsvName($) {
    my $name = shift;    # name of JVM memory pool, e.g. "PS Perm Gen"
    $name = lc($name);
    $name =~ s/ /_/g;
    return "mpool_$name";
}

sub getDiskInfo() {

    # Get device list.

    my $iostat = '/usr/bin/iostat';
    if ( !-e $iostat ) {
        $iostat = '/usr/sbin/iostat';
        if ( !-e $iostat ) {
            print STDERR
              "No iostat installed on this host; Skipping IO charts\n";
            return;
        }
    }
    my $cmd = "$iostat -d -x";
    if ( !open( IOSTAT, "$cmd |" ) ) {
        print STDERR "Unable to execute $cmd; Skipping IO charts\n";
        return;
    }
    my $line = '';
    while ( $line !~ /^Device/ ) {
        $line = readLine( *IOSTAT, 1 );
    }
    while ( defined( $line = readLine( *IOSTAT, 1 ) ) ) {
        if ( $line =~ /^\s*([^\s]+)\s+/ ) {
            my $dev = $1;
            push( @DEVICE_LIST, $dev );
        }
    }
    close(IOSTAT);

    # make sure there are no duplicate items in DEVICE_LIST
    # see bug 32973
    my %devices_tmp;
    for (@DEVICE_LIST) {
        $devices_tmp{$_} = 1;
    }
    @DEVICE_LIST = keys %devices_tmp;

    if ( scalar(@DEVICE_LIST) < 1 ) {
        print STDERR "Unable to find any disk device; Skipping IO charts\n";
        return;
    }

    # Get partition and mountpoint list.

    if ( open( MOUNT, "mount |" ) ) {
        my $line;
        while ( defined( $line = readLine( *MOUNT, 1 ) ) ) {
            if ( $line =~ /^\/dev\/([^\s+]+) on ([^\s+]+)/ ) {
                my ( $partition, $mountpoint ) = ( $1, $2 );
                my %partitions_seen;
                foreach my $dev (@DEVICE_LIST) {
                    if ( $partition =~ /^$dev/ ) {

                        # make sure to avoid duplicates
                        # see bug 32973
                        next if ( exists $partitions_seen{$partition} );

                        $MOUNTS{$partition} = $mountpoint;
                        my $partitionList = $DEVICE_PARTITIONS{$dev};
                        if ( !defined($partitionList) ) {
                            $partitionList = [];
                            $DEVICE_PARTITIONS{$dev} = $partitionList;
                        }
                        push( @$partitionList, $partition );
                        my $mountpointList = $DEVICE_MOUNTPOINTS{$dev};
                        if ( !defined($mountpointList) ) {
                            $mountpointList = [];
                            $DEVICE_MOUNTPOINTS{$dev} = $mountpointList;
                        }
                        push( @$mountpointList, $mountpoint );
                        $partitions_seen{$partition} = 1;
                    }
                }
            }
        }
        close(MOUNT);
    }
    else {
        print STDERR
          "Unable to get list of mounted volumes; Skipping IO charts\n";
        return;
    }
}

sub getHostAndProcsInfo() {
    $ZIMBRA_HOSTNAME = getZimbraServerHostname();

    my $svc;
    my @enabledServices =
      qx(zmprov -l gs $ZIMBRA_HOSTNAME | grep zimbraServiceEnabled);
    foreach $svc (@enabledServices) {
        if ( $svc =~ /mailbox/ ) {
            push( @ENABLED_PROCS, 'mailbox' );
            push( @ENABLED_PROCS, 'mysql' );
            $HAS_MAILBOX = 1;
            last;
        }
    }

    foreach $svc (@enabledServices) {
        if ( $svc =~ /ldap/ ) {
            push( @ENABLED_PROCS, 'ldap' );
            last;
        }
    }

    foreach $svc (@enabledServices) {
        if ( $svc =~ /mta/ ) {
            push( @ENABLED_PROCS, 'postfix' );
            $HAS_MTA = 1;
            last;
        }
    }

    foreach $svc (@enabledServices) {
        if ( $svc =~ /antispam/ || $svc =~ /antivirus/ ) {
            push( @ENABLED_PROCS, 'amavis' );
            push( @ENABLED_PROCS, 'clam' );
            last;
        }
    }

    push( @ENABLED_PROCS, 'stats' );
}

sub mtaConfig() {
    print <<_HERE_;
  <!-- Postfix Stats -->

  <chart title="Host $ZIMBRA_HOSTNAME: Postfix Queue Size"
         category="MTA"
         infile="$mtaqstatCsv"
         outfile="${ZIMBRA_HOSTNAME}_postfix_queue.png"
         yAxis="msgs"
         showRaw="false"
         showMovingAvg="true">
    <plot data="requests" legend="queue size" aggregateFunction="max"/>
  </chart>

_HERE_
}

sub getFDstatConfig() {
    print <<_HERE_;
  <chart title="Host $ZIMBRA_HOSTNAME: Open file descriptor count"
      category="IO"
      infile="$fdstatCsv"
      outfile="${ZIMBRA_HOSTNAME}_fd_stat.png"
      yAxis="fd"
      showRaw="false"
      showMovingAvg="true">
    <plot data="fd_count" legend="total system file descriptors open"/>
    <plot data="mailboxd_fd_count" legend="mailboxd file descriptors open"/>
  </chart>
_HERE_
}

sub cpuPstatConfig() {
    print <<_HERE_;
  <!-- CPU Stats -->

  <chart title="Host $ZIMBRA_HOSTNAME: Total CPU"
         category="CPU"
         infile="$cpustatCsv"
         outfile="${ZIMBRA_HOSTNAME}_cpu.png"
         yAxis="% cpu"
         allowLogScale="false"
         showRaw="false"
         showMovingAvg="true">
    <plot data="cpu:user" legend="user"/>
    <plot data="cpu:sys" legend="sys"/>
    <plot data="cpu:idle" legend="idle"/>
    <plot data="cpu:iowait" legend="iowait" optional="true"/>
    <plot data="cpu:nice" legend="nice" optional="true"/>
    <plot data="cpu:irq" legend="irq" optional="true"/>
    <plot data="cpu:softirq" legend="softirq" optional="true"/>
  </chart>

_HERE_

    my $numCPUs = qx(egrep '^cpu[0-9]+' /proc/stat 2> /dev/null | wc -l);
    chomp($numCPUs);
    if ( $numCPUs > 1 ) {
        my @categories =
          ( 'user', 'nice', 'sys', 'idle', 'iowait', 'irq', 'softirq' );
        foreach my $category (@categories) {
            my $i;
            print <<_HERE_;
  <chart title="Host $ZIMBRA_HOSTNAME: Individual CPU $category time"
         category="CPU"
         infile="$cpustatCsv"
         outfile="${ZIMBRA_HOSTNAME}_cpus_$category.png"
         yAxis="% cpu"
         allowLogScale="false"
         showRaw="false"
         showMovingAvg="true">
_HERE_
            for ( $i = 0 ; $i < $numCPUs ; $i++ ) {
                print qq[    <plot data="cpu$i:$category" legend="cpu$i"/>\n];
            }
            print "  </chart>\n\n";
        }
    }

    print <<_HERE_;
  <chart title="Host $ZIMBRA_HOSTNAME: Process CPU"
         category="CPU"
         infile="$pstatCsv"
         outfile="${ZIMBRA_HOSTNAME}_proc_cpu.png"
         yAxis="% cpu"
         allowLogScale="false"
         showRaw="false"
         showMovingAvg="true">
_HERE_
    my $proc;
    foreach $proc (@ENABLED_PROCS) {
        print qq[    <plot data="$proc-total-cpu" legend="$proc"/>\n];
    }
    print "  </chart>\n\n";

    print <<_HERE_;
  <!-- Process Stats -->

  <chart title="Host $ZIMBRA_HOSTNAME: Process Total Memory"
         category="Memory"
         infile="$pstatCsv"
         outfile="${ZIMBRA_HOSTNAME}_proc_total_mem.png"
         yAxis="MB"
         allowLogScale="false"
         showRaw="false"
         showMovingAvg="true">
_HERE_
    foreach $proc (@ENABLED_PROCS) {
        print qq[    <plot data="$proc-totalMB" legend="$proc"/>\n];
    }
    print "  </chart>\n\n";

    print <<_HERE_;
  <chart title="Host $ZIMBRA_HOSTNAME: Process Resident Memory"
         category="Memory"
         infile="$pstatCsv"
         outfile="${ZIMBRA_HOSTNAME}_proc_res_mem.png"
         yAxis="MB"
         allowLogScale="false"
         showRaw="false"
         showMovingAvg="true">
_HERE_
    foreach $proc (@ENABLED_PROCS) {
        print qq[    <plot data="$proc-rssMB" legend="$proc"/>\n];
    }
    print "  </chart>\n\n";
}

sub vmstatConfig() {
    my ( $colFree, $colPageIn, $colPageOut, $colActive, $colInactive );
    ( $colFree, $colPageIn, $colPageOut, $colActive, $colInactive ) =
      ( 'free', 'si', 'so', 'Active', 'Inactive' );

    print <<_HERE_;
  <!-- vmstat -->

  <chart title="Host $ZIMBRA_HOSTNAME: Swap Activity"
         category="Memory"
         infile="$vmstatCsv"
         outfile="${ZIMBRA_HOSTNAME}_vm_swap.png"
         yAxis="KB/s"
         showRaw="false"
         showMovingAvg="true">
    <plot data="$colPageIn" legend="swap in"/>
    <plot data="$colPageOut" legend="swap out"/>
  </chart>

  <chart title="Host $ZIMBRA_HOSTNAME: Virtual Memory"
         category="Memory"
         infile="$vmstatCsv"
         outfile="${ZIMBRA_HOSTNAME}_vm_mem.png"
         yAxis="MB"
         divisor="1024"
         showRaw="false"
         showMovingAvg="true">
    <plot data="swpd" legend="swapped" optional="true"/>
    <plot data="$colFree" legend="free"/>
    <plot data="$colActive" legend="active"/>
    <plot data="$colInactive" legend="inactive"/>
    <plot data="cache" legend="page cache" optional="true"/>
  </chart>

_HERE_

    print <<_HERE_;
  <chart title="Host $ZIMBRA_HOSTNAME: Context Switches"
         category="CPU"
         infile="$vmstatCsv"
         outfile="${ZIMBRA_HOSTNAME}_vm_cs.png"
         yAxis="cs/s"
         showRaw="false"
         showMovingAvg="true">
    <plot data="cs" legend="context switches"/>
  </chart>

  <chart title="Host $ZIMBRA_HOSTNAME: Run/Blocked Process Queue Size, Load Average"
         category="CPU"
         infile="$vmstatCsv"
         outfile="${ZIMBRA_HOSTNAME}_vm_runqueue.png"
         yAxis="procs"
         showRaw="false"
         showMovingAvg="true">
    <plot data="r" legend="processes waiting for run time"/>
    <plot data="b" legend="processes waiting for io time"/>
    <plot data="loadavg" legend="load average (1 min)"/>
  </chart>

_HERE_

}

sub iostatConfig() {
    my $dev;

    print <<_HERE_;
  <!-- IO stats -->

_HERE_
    print <<_HERE_;
  <chart title="Host $ZIMBRA_HOSTNAME: Disk Utilization (Top 10 avg)"
         category="IO"
         infile="$iostatxCsv"
         outfile="${ZIMBRA_HOSTNAME}_disk_util.png"
         yAxis="% util"
         allowLogScale="false"
         height="400"
         topPlots="10"
         topPlotsType="avg"
         showRaw="false"
         showMovingAvg="true">
_HERE_

    foreach $dev (@DEVICE_LIST) {
        print qq[    <plot data="$dev:%util" legend="$dev"/>\n];
    }
    print "  </chart>\n\n";

    foreach $dev (@DEVICE_LIST) {
        my $devFile = filenameSafe($dev);
        print <<_HERE_;
  <chart title="Host $ZIMBRA_HOSTNAME: Disk Throughput: /dev/$dev"
         category="IO"
         infile="$iostatxCsv"
         outfile="${ZIMBRA_HOSTNAME}_${devFile}_dev_thruput.png"
         yAxis="KB/s"
         showRaw="false"
         showMovingAvg="true">
_HERE_
        print <<_HERE_;
    <plot data="$dev:rkB/s" legend="$dev read"/>
    <plot data="$dev:wkB/s" legend="$dev write"/>
_HERE_

        print "  </chart>\n\n";
    }

    foreach $dev (@DEVICE_LIST) {
        my $devFile = filenameSafe($dev);
        print <<_HERE_;
  <chart title="Host $ZIMBRA_HOSTNAME: Disk IOPs: /dev/$dev"
         category="IO"
         infile="$iostatxCsv"
         outfile="${ZIMBRA_HOSTNAME}_${devFile}_dev_iops.png"
         yAxis="reqs/s"
         showRaw="false"
         showMovingAvg="true">
_HERE_
        print <<_HERE_;
    <plot data="$dev:r/s" legend="$dev read"/>
    <plot data="$dev:w/s" legend="$dev write"/>
_HERE_

        print "  </chart>\n\n";
    }

    foreach $dev (@DEVICE_LIST) {
        my $partitionList = $DEVICE_PARTITIONS{$dev};
        foreach my $partition (@$partitionList) {
            my $mountpoint = $MOUNTS{$partition};
            my $partFile   = filenameSafe($partition);
            print <<_HERE_;
  <chart title="Host $ZIMBRA_HOSTNAME: Disk Partition Throughput: /dev/$partition mounted on $mountpoint"
         category="IO"
         infile="$iostatCsv"
         outfile="${ZIMBRA_HOSTNAME}_${partFile}_part_thruput.png"
         yAxis="KB/s"
         showRaw="false"
         showMovingAvg="true">
    <plot data="$partition:kB_read/s" legend="$partition read"/>
    <plot data="$partition:kB_wrtn/s" legend="$partition write"/>
  </chart>

_HERE_
        }
    }
    foreach $dev (@DEVICE_LIST) {
        my $partitionList = $DEVICE_PARTITIONS{$dev};
        foreach my $partition (@$partitionList) {
            my $mountpoint = $MOUNTS{$partition};
            my $partFile   = filenameSafe($partition);
            print <<_HERE_;
  <chart title="Host $ZIMBRA_HOSTNAME: Disk Partition IOPs: /dev/$partition mounted on $mountpoint"
         category="IO"
         infile="$iostatCsv"
         outfile="${ZIMBRA_HOSTNAME}_${partFile}_part_iops.png"
         yAxis="tps"
         showRaw="false"
         showMovingAvg="true">
    <plot data="$partition:tps" legend="$partition tps"/>
  </chart>
_HERE_

        }
    }
    print <<_HERE_;
  <chart title="Host $ZIMBRA_HOSTNAME: Disk Usage"
         category="IO"
         height="400"
         infile="$dfstatCsv"
         outfile="${ZIMBRA_HOSTNAME}_disk_usage.png"
         yAxis="% used">
    <groupplot data="disk_pct_used" groupBy="path" />
  </chart>
_HERE_

}

sub mailboxdConfig() {
    print <<_HERE_;
  <!-- SOAP Stats -->
  <chart title="Host $ZIMBRA_HOSTNAME: SOAP: Invocation Count: Summary (Top 10 max)"
         category="soap"
         height="400"
         topPlots="10"
         topPlotsType="max"
         infile="$soapCsv"
         outfile="${ZIMBRA_HOSTNAME}_soap_call_count.png"
         yAxis="calls/min">
    <groupplot data="exec_count" ignore="BackupRequest" groupBy="command" aggregateFunction="max"/>
  </chart>
  
  <chart title="Host $ZIMBRA_HOSTNAME: SOAP: Average Call Duration: Summary (Top 10 avg)"
         category="soap"
         height="400"
         topPlots="10"
         topPlotsType="avg"
         infile="$soapCsv"
         outfile="${ZIMBRA_HOSTNAME}_soap_avg_duration.png"
         yAxis="ms avg">
    <groupplot data="exec_ms_avg" ignore="BackupRequest" groupBy="command"/>
  </chart>
  <chart title="Host $ZIMBRA_HOSTNAME: SOAP: Invocation Count: %s"
         category="soap"
         outDocument="soap.html"
         infile="$soapCsv"
         outfile="${ZIMBRA_HOSTNAME}_soap_call_count_%s.png"
         yAxis="calls/min">
    <groupplot data="exec_count" groupBy="command" aggregateFunction="max"/>
  </chart>
  
  <chart title="Host $ZIMBRA_HOSTNAME: SOAP: Average Call Duration: %s"
         category="soap"
         outDocument="soap.html"
         infile="$soapCsv"
         outfile="${ZIMBRA_HOSTNAME}_soap_avg_duration_%s.png"
         yAxis="ms avg">
    <groupplot data="exec_ms_avg" groupBy="command"/>
  </chart>
  
  <!-- MySQL Stats -->

  <chart title="Host $ZIMBRA_HOSTNAME: MySQL: InnoDB Buffer Pool Pages"
         category="database"
         infile="$mysqlCsv"
         outfile="${ZIMBRA_HOSTNAME}_mysql-bufpool-pages.png"
         yAxis="pages">
    <plot data="Innodb_pages_read" legend="pages read"/>
    <plot data="Innodb_pages_written" legend="pages written"/>
  </chart>

  <chart title="Host $ZIMBRA_HOSTNAME: MySQL: InnoDB Buffer Pool Hit Rate"
         category="database"
         infile="$mailboxdCsv"
         outfile="${ZIMBRA_HOSTNAME}_mysql-bufpool-hit-rate.png"
         yAxis="rate">
    <plot data="innodb_bp_hit_rate" legend="buffer pool hit rate"/>
  </chart>

  <chart title="Host $ZIMBRA_HOSTNAME: MySQL: Database Connections In Use"
         category="database"
         infile="$mailboxdCsv"
         outfile="${ZIMBRA_HOSTNAME}_mysql-conns.png"
         yAxis="conns">
    <plot data="db_pool_size" legend="connections in use"/>
  </chart>

  <chart title="Host $ZIMBRA_HOSTNAME: MySQL: Tables Open/Opened"
         category="database"
         infile="$mysqlCsv"
         outfile="${ZIMBRA_HOSTNAME}_mysql-open-tables.png"
         yAxis="tables">
    <plot data="Open_tables" legend="open_tables"/>
    <plot data="Opened_tables" legend="opened_tables (cumulative)"/>
  </chart>

  <chart title="Host $ZIMBRA_HOSTNAME: MySQL: Total Slow Queries Count"
         category="database"
         infile="$mysqlCsv"
         outfile="${ZIMBRA_HOSTNAME}_mysql-slow-queries.png"
         yAxis="queries">
    <plot data="Slow_queries" legend="slow queries (cumulative)"/>
  </chart>

  <!-- Mailboxd Stats -->

  <chart title="Host $ZIMBRA_HOSTNAME: Mailboxd: Connection Pool Get Latency"
         category="mailboxd"
         infile="$mailboxdCsv"
         outfile="${ZIMBRA_HOSTNAME}_mboxd-cpool-get-latency.png"
         yAxis="msec">
    <plot data="db_conn_ms_avg" legend="mysql"/>
    <plot data="ldap_dc_ms_avg" legend="ldap"/>
  </chart>

  <chart title="Host $ZIMBRA_HOSTNAME: Mailboxd: Dirty Lucene Index Writers"
         category="mailboxd"
         infile="$mailboxdCsv"
         outfile="${ZIMBRA_HOSTNAME}_mboxd-dirty-index-writers.png"
         yAxis="writers">
    <plot data="idx_wrt_avg" legend="dirty index writers"/>
  </chart>

  <chart title="Host $ZIMBRA_HOSTNAME: Mailboxd: Lucene IndexWriterCache Hitrate"
         category="mailboxd"
         infile="$mailboxdCsv"
         outfile="${ZIMBRA_HOSTNAME}_mboxd-idxwrtrcache-hitrate.png"
         yAxis="hitrate %">
    <plot ratioTop="idx_wrt_opened_cache_hit"
          ratioBottom="idx_wrt_opened+idx_wrt_opened_cache_hit"
          legend="cache hitrate" multiplier="100"/>
  </chart>
  
  <chart title="Host $ZIMBRA_HOSTNAME: Mailboxd: Lucene IO"
      category="mailboxd"
      infile="$mailboxdCsv"
      outfile="${ZIMBRA_HOSTNAME}_mboxd-lucene-io.png"
      yAxis="KB/s"
      showRaw="false"
      showMovingAvg="true">
    <plot data="idx_bytes_written" legend="Index writes" divisor="61440"/>
    <plot data="idx_bytes_read" legend="Index reads" divisor="61440"/>
  </chart>

  <chart title="Host $ZIMBRA_HOSTNAME: Mailboxd: LMTP Delivery Throughput"
         category="mailboxd"
         infile="$mailboxdCsv"
         outfile="${ZIMBRA_HOSTNAME}_mboxd-lmtp-thruput.png"
         yAxis="KB/s"
         showRaw="false"         
         showMovingAvg="true">
    <plot data="lmtp_rcvd_bytes" legend="received" divisor="61440"/>
    <plot data="lmtp_dlvd_bytes" legend="delivered" divisor="61440"/>
  </chart>
  
  <chart title="Host $ZIMBRA_HOSTNAME: Mailboxd: LMTP Delivery Rate"
         category="mailboxd"
         infile="$mailboxdCsv"
         outfile="${ZIMBRA_HOSTNAME}_mboxd-mbox-deliv-rate.png"         
         yAxis="msgs/s">
      <plot data="lmtp_rcvd_msgs" legend="received msgs" divisor="60"/>
      <plot data="lmtp_dlvd_msgs" legend="delivered msgs" divisor="60" />
      <plot data="lmtp_rcvd_rcpt" legend="received x rcpts" divisor="60" />
  </chart>

  <chart title="Host $ZIMBRA_HOSTNAME: Mailboxd: Mailbox Add Rate (Delivery Rate)"
         category="mailboxd"
         infile="$mailboxdCsv"
         outfile="${ZIMBRA_HOSTNAME}_mboxd-mbox-add-rate.png"
         yAxis="adds/s">
    <plot data="mbox_add_msg_count" legend="mailbox add rate" divisor="60"/>
  </chart>

  <chart title="Host $ZIMBRA_HOSTNAME: Mailboxd: Mailbox Add Latency (Delivery Speed)"
         category="mailboxd"
         infile="$mailboxdCsv"
         outfile="${ZIMBRA_HOSTNAME}_mboxd-mbox-add-latency.png"
         yAxis="msec">
    <plot data="mbox_add_msg_ms_avg" legend="mailbox add latency"/>
  </chart>

  <chart title="Host $ZIMBRA_HOSTNAME: Mailboxd: Request Rate by Client Protocol"
         category="mailboxd"
         infile="$mailboxdCsv"
         outfile="${ZIMBRA_HOSTNAME}_mboxd-proto-req-rate.png"
         yAxis="reqs/s">
    <plot data="soap_count" legend="SOAP" divisor="60"/>
    <plot data="imap_count" legend="IMAP" divisor="60"/>
    <plot data="pop_count" legend="POP" divisor="60"/>
  </chart>

  <chart title="Host $ZIMBRA_HOSTNAME: Mailboxd: Response Time by Client Protocol"
         category="mailboxd"
         infile="$mailboxdCsv"
         outfile="${ZIMBRA_HOSTNAME}_mboxd-proto-resp-time.png"
         yAxis="msec"
         showRaw="false"
         showMovingAvg="true">
    <plot data="soap_ms_avg" legend="SOAP"/>
    <plot data="imap_ms_avg" legend="IMAP"/>
    <plot data="pop_ms_avg" legend="POP"/>
  </chart>

  <chart title="Host $ZIMBRA_HOSTNAME: Mailboxd: Active Connections by Client Protocol"
         category="mailboxd"
         infile="$mailboxdCsv"
         outfile="${ZIMBRA_HOSTNAME}_mboxd-proto-active-conns.png"
         yAxis="conns">
    <plot data="imap_conn" legend="IMAP"/>
    <plot data="imap_ssl_conn" legend="IMAP SSL"/>
    <plot data="pop_conn" legend="POP"/>
    <plot data="pop_ssl_conn" legend="POP SSL"/>
    <plot data="soap_sessions" legend="SOAP sessions"/>
  </chart>

  <chart title="Host $ZIMBRA_HOSTNAME: Mailboxd: Mailbox Get Count"
         category="mailboxd"
         infile="$mailboxdCsv"
          outfile="${ZIMBRA_HOSTNAME}_mboxd-mbox-get-count.png"
          yAxis="count">
      <plot data="mbox_get_count" legend="mailbox get count"/>
  </chart>

  <chart title="Host $ZIMBRA_HOSTNAME: Mailboxd: Mailbox Get Latency"
         category="mailboxd"
         infile="$mailboxdCsv"
         outfile="${ZIMBRA_HOSTNAME}_mboxd-mbox-get-latency.png"
         yAxis="msec">
      <plot data="mbox_get_ms_avg" legend="mailbox get latency"/>
  </chart>

  <chart title="Host $ZIMBRA_HOSTNAME: Mailboxd: Mailbox Cache Hit Rate"
         category="mailboxd"
         infile="$mailboxdCsv"
         outfile="${ZIMBRA_HOSTNAME}_mboxd-mbox-cache-hit.png"
         yAxis="rate (%)">
    <plot data="mbox_cache" legend="mailbox cache hit rate"/>
  </chart>

  <chart title="Host $ZIMBRA_HOSTNAME: Mailboxd: Mailbox Item/Blob Cache Hit Rate"
         category="mailboxd"
         infile="$mailboxdCsv"
         outfile="${ZIMBRA_HOSTNAME}_mboxd-item-blob-cache-hit.png"
         yAxis="rate (%)"
         showRaw="false"
         showMovingAvg="true">
    <plot data="mbox_msg_cache" legend="msg blob cache"/>
    <plot data="mbox_item_cache" legend="item metadata cache"/>
  </chart>

_HERE_
}

sub allpstatsConfig() {
    print <<_HERE_;
  <!-- allprocs Stats -->
  <chart title="Host $ZIMBRA_HOSTNAME: Process CPU Time (Top 10 avg)"
         category="CPU"
         infile="$allpstatCsv"
         outfile="${ZIMBRA_HOSTNAME}_allpstats_cputime.png"
         yAxis="cputime (seconds)"
         allowLogScale="false"
         height="400"
         topPlots="10"
         topPlotsType="avg"
         showRaw="false"
         showMovingAvg="true">
    <groupplot data="cputime" groupBy="process"/>
  </chart>
_HERE_
}

sub nginxConfig() {
    print <<_HERE_;
  <!-- Nginx Stats -->
  <chart title="Host $ZIMBRA_HOSTNAME: nginx: CPU time used"
         category="nginx"
         infile="$nginxCsv"
         outfile="${ZIMBRA_HOSTNAME}_nginx_cputime.png"
         yAxis="cputime (seconds)"
         showRaw="false"
         showMovingAvg="true">
    <plot data="cputime" legend="total cputime" divisor="100"/>
    <plot data="utime" legend="user time" divisor="100"/>
    <plot data="stime" legend="system time" divisor="100"/>
  </chart>
  
  <chart title="Host $ZIMBRA_HOSTNAME: nginx: Resident Memory"
         category="nginx"
         infile="$nginxCsv"
         outfile="${ZIMBRA_HOSTNAME}_nginx_rss.png"
         yAxis="MB"
         showRaw="false"
         showMovingAvg="true">
    <plot data="rss" legend="nginx rss" divisor="1024"/>
  </chart>
  
  <chart title="Host $ZIMBRA_HOSTNAME: nginx: Processes and Threads"
         category="nginx"
         infile="$nginxCsv"
         outfile="${ZIMBRA_HOSTNAME}_nginx_procs_threads.png"
         yAxis="count"
         showRaw="false"
         showMovingAvg="true">
    <plot data="processes" legend="processes"/>
    <plot data="threads" legend="threads"/>
  </chart>

_HERE_
}

sub gcConfig() {
    print <<_HERE_;
  <!-- Garbage Collection Stats -->

  <chart title="Host $ZIMBRA_HOSTNAME: Mailboxd: Minor Garbage Collection Time"
         category="mailboxd"
         infile="$mailboxdCsv"
         outfile="${ZIMBRA_HOSTNAME}_mboxd-min-gc-time.png"
         plotZero="true"
         yAxis="% time">
    <plot data="gc_minor_ms" legend="minor GC time"
          dataFunction="diff" percentTime="true"/>
  </chart>
  <chart title="Host $ZIMBRA_HOSTNAME: Mailboxd: Major Garbage Collection Time"
         category="mailboxd"
         infile="$mailboxdCsv"
         outfile="${ZIMBRA_HOSTNAME}_mboxd-maj-gc-time.png"
         plotZero="true"
         yAxis="% time">
    <plot data="gc_major_ms" legend="major GC time"
          dataFunction="diff" percentTime="true"/>
  </chart>

  <chart title="Host $ZIMBRA_HOSTNAME: Mailboxd: Minor Garbage Collection Count"
         category="mailboxd"
         infile="$mailboxdCsv"
         outfile="${ZIMBRA_HOSTNAME}_mboxd-min-gc-count.png"
         plotZero="true"
         yAxis="times">
    <plot data="gc_minor_count" legend="minor GC count"
          dataFunction="diff" nonNegative="true"/>
  </chart>
  <chart title="Host $ZIMBRA_HOSTNAME: Mailboxd: Major Garbage Collection Count"
         category="mailboxd"
         infile="$mailboxdCsv"
         outfile="${ZIMBRA_HOSTNAME}_mboxd-maj-gc-count.png"
         plotZero="true"
         yAxis="times">
    <plot data="gc_major_count" legend="major GC count"
          dataFunction="diff" nonNegative="true"/>
  </chart>

_HERE_
}

sub heapConfig() {
    print <<_HERE_;
  <!-- Heap Stats -->

_HERE_

    my %JVM_MEMPOOLS = (
        'YOUNGGEN' => [
            'PS Eden Space',
            'PS Survivor Space',
            'Par Eden Space',
            'Par Survivor Space',
            'Eden Space',
            'Survivor Space'
        ],
        'OLDGEN' => [
            'PS Old Gen', 'CMS Old Gen', 'Tenured Gen', 'Train Gen'

              # Train Gen is gone in JDK 1.6
        ],
        'PERMGEN' => [
            'PS Perm Gen',
            'Perm Gen',
            'CMS Perm Gen',
            'Code Cache'
            ,    # throw this in here too even though it's not a perm gen
            'Perm Gen [shared-ro]', 'Perm Gen [shared-rw]'
        ]
    );

    my $genname;
    my $pool;

    print <<_HERE_;
  <chart title="Host $ZIMBRA_HOSTNAME: Mailboxd: JVM Heap Used"
         category="mailboxd"
         infile="$mailboxdCsv"
         outfile="${ZIMBRA_HOSTNAME}_mboxd-heap-used.png"
         yAxis="MB">
    <plot data="heap_used" legend="total" divisor="1m"/>
_HERE_
    foreach $genname ( 'OLDGEN', 'YOUNGGEN' ) {
        my $pools = $JVM_MEMPOOLS{$genname};
        foreach $pool (@$pools) {
            my $csvname = memPoolCsvName($pool);
            print <<_HERE_;
    <plot data="${csvname}_used" legend="$pool" divisor="1m"
          optional="true"/>
_HERE_
        }
    }
    print "  </chart>\n\n";

    print <<_HERE_;
  <chart title="Host $ZIMBRA_HOSTNAME: Mailboxd: JVM Heap Free"
         category="mailboxd"
         infile="$mailboxdCsv"
         outfile="${ZIMBRA_HOSTNAME}_mboxd-heap-free.png"
         yAxis="MB">
    <plot data="heap_free" legend="total free" divisor="1m"/>
_HERE_
    foreach $genname ( 'OLDGEN', 'YOUNGGEN' ) {
        my $pools = $JVM_MEMPOOLS{$genname};
        foreach $pool (@$pools) {
            my $csvname = memPoolCsvName($pool);
            print <<_HERE_;
    <plot data="${csvname}_free" legend="$pool free" divisor="1m"
          optional="true"/>
_HERE_
        }
    }
    print "  </chart>\n\n";

    print <<_HERE_;
  <chart title="Host $ZIMBRA_HOSTNAME: Mailboxd: JVM Permanent Generation and Code Cache"
         category="mailboxd"
         infile="$mailboxdCsv"
         outfile="${ZIMBRA_HOSTNAME}_mboxd-permgen.png"
         yAxis="MB">
_HERE_
    my $pgpools = $JVM_MEMPOOLS{'PERMGEN'};
    foreach $pool (@$pgpools) {
        my $csvname = memPoolCsvName($pool);
        print <<_HERE_;
    <plot data="${csvname}_used" legend="$pool" divisor="1m"
          optional="true"/>
_HERE_
    }
    foreach $pool (@$pgpools) {
        my $csvname = memPoolCsvName($pool);
        print <<_HERE_;
    <plot data="${csvname}_free" legend="$pool free" divisor="1m"
          optional="true"/>
_HERE_
    }
    print "  </chart>\n\n";
}

sub ldapConfig() {
    print <<_HERE_;
  <!-- LDAP Stats -->

  <chart title="Host $ZIMBRA_HOSTNAME: LDAP: Invocation Count: Summary (Top 10 max)"
         category="ldap"
         height="400"
         topPlots="10"
         topPlotsType="max"
         infile="ldap.csv"
         outfile="${ZIMBRA_HOSTNAME}_ldap_call_count.png"
         yAxis="calls/min">
    <groupplot data="exec_count"  groupBy="command" aggregateFunction="max"/>
  </chart>
  
  <chart title="Host $ZIMBRA_HOSTNAME: LDAP: Average Call Duration: Summary (Top 10 avg)"
         category="ldap"
         height="1200"
         topPlots="10"
         topPlotsType="avg"
         infile="ldap.csv"
         outfile="${ZIMBRA_HOSTNAME}_ldap_avg_duration.png"
         yAxis="ms avg">
    <groupplot data="exec_ms_avg"  groupBy="command"/>
  </chart>
  <chart title="Host $ZIMBRA_HOSTNAME: LDAP: Invocation Count: %s"
         category="ldap"
         outDocument="ldap.html"
         infile="ldap.csv"
         outfile="${ZIMBRA_HOSTNAME}_ldap_call_count_%s.png"
         yAxis="calls/min">
    <groupplot data="exec_count" groupBy="command" aggregateFunction="max"/>
  </chart>
  
  <chart title="Host $ZIMBRA_HOSTNAME: LDAP: Average Call Duration: %s"
         category="ldap"
         outDocument="ldap.html"
         infile="ldap.csv"
         outfile="${ZIMBRA_HOSTNAME}_ldap_avg_duration_%s.png"
         yAxis="ms avg">
    <groupplot data="exec_ms_avg" groupBy="command"/>
  </chart>

  


_HERE_
}

sub mobileSyncConfig() {
    print <<_HERE_;
  <!-- mobile sync stats -->
  <chart title="Host $ZIMBRA_HOSTNAME: MobileSync: SyncState cache Hit Rate"
         category="mobile"
         infile="$mailboxdCsv"
         outfile="${ZIMBRA_HOSTNAME}_mobile-syncstate-cache.png"
         yAxis="rate">
    <plot data="mobile_syncstate_cache_hit_rate" legend="SyncState cache hit rate"/>
  </chart>

  <chart title="Host $ZIMBRA_HOSTNAME: MobileSync: Ping cache Hit Rate"
         category="mobile"
         infile="$mailboxdCsv"
         outfile="${ZIMBRA_HOSTNAME}_mobile-ping-cache.png"
         yAxis="rate">
    <plot data="mobile_ping_cache_hit_rate" legend="Ping cache hit rate"/>
  </chart>
_HERE_
}

sub sqlstatsConfig() {
    print <<_HERE_;
  <!-- SQL Performance Stats -->
  <chart title="Host $ZIMBRA_HOSTNAME: SQL: Invocation Count: Summary (Top 10 max)"
         category="sqlstats"
         height="400"
         topPlots="10"
         topPlotsType="max"
         infile="$sqlstatsCsv"
         outfile="${ZIMBRA_HOSTNAME}_sql_call_count.png"
         yAxis="calls/min">
    <groupplot data="exec_count" groupBy="command" aggregateFunction="max"/>
  </chart>
  
  <chart title="Host $ZIMBRA_HOSTNAME: SQL: Average Call Duration: Summary (Top 10 avg)"
         category="sqlstats"
         height="400"
         topPlots="10"
         topPlotsType="avg"
         infile="$sqlstatsCsv"
         outfile="${ZIMBRA_HOSTNAME}_sql_avg_duration.png"
         yAxis="ms avg">
    <groupplot data="exec_ms_avg" groupBy="command"/>
  </chart>
  <chart title="Host $ZIMBRA_HOSTNAME: SQL: Invocation Count: %s"
         category="sqlstats"
         outDocument="sqlstats.html"
         infile="$sqlstatsCsv"
         outfile="${ZIMBRA_HOSTNAME}_sql_call_count_%s.png"
         yAxis="calls/min">
    <groupplot data="exec_count" groupBy="command" aggregateFunction="max"/>
  </chart>
  
  <chart title="Host $ZIMBRA_HOSTNAME: SQL: Average Call Duration: %s"
         category="sqlstats"
         outDocument="sqlstats.html"
         infile="$sqlstatsCsv"
         outfile="${ZIMBRA_HOSTNAME}_sql_avg_duration_%s.png"
         yAxis="ms avg">
    <groupplot data="exec_ms_avg" groupBy="command"/>
  </chart>
  

_HERE_
}

#
# main
#

getHostAndProcsInfo();
getDiskInfo();

print "<charts>\n\n";
if ($HAS_MTA) {
    mtaConfig();
}
cpuPstatConfig();
vmstatConfig();
iostatConfig();
getFDstatConfig();
allpstatsConfig();

if ($HAS_MAILBOX) {
    mailboxdConfig();
    gcConfig();
    heapConfig();
    nginxConfig();
    ldapConfig();
    mobileSyncConfig();
    sqlstatsConfig();
}
print "</charts>\n";
