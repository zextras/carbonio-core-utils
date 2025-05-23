#!/usr/bin/perl

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

use strict;

my $id = qx(id -u -n);
chomp $id;
if ( $id ne "zextras" ) { die "Run as the zextras user!\n"; }

use lib "/opt/zextras/common/lib/perl5";
use Zextras::Util::Common;
use Zextras::Util::Systemd;
use Zextras::Mon::Logger;
use Net::LDAP;

use Getopt::Std;
use File::Temp qw/ tempfile /;
use File::Path;

my $zimbra_tmp_directory = getLocalConfig("zimbra_tmp_directory");

if ( !-d $zimbra_tmp_directory ) {
    File::Path::mkpath("$zimbra_tmp_directory");
}

my ( undef, $zmcontrolLogfile ) = tempfile( "zmcontrol.out.XXXXX", DIR => "$zimbra_tmp_directory", OPEN => 0 );

my $timeout = 180;
$SIG{ALRM} = sub { print "Timeout after $timeout seconds\n"; exit(1) };
my $now           = time();
my $cache_file    = "/opt/zextras/log/.zmcontrol.cache";
my $localHostName = getHostName();
my $ldapHere      = isLdapLocal();
my $services;
my %devicesChecked;
my %serviceStatusList;

# This will break a lot of legacy codebase. Sorry not sorry
my %serviceNames = ( "zmconfigd" => "config service" );
my %startorder   = (
    "directory-server" => 0,
    "zmconfigd"        => 10,
    "mailbox"          => 50,
    "memcached"        => 60,
    "proxy"            => 70,
    "amavis"           => 75,
    "antispam"         => 80,
    "antivirus"        => 90,
    "opendkim"         => 100,
    "cbpolicyd"        => 120,
    "mta"              => 150,
    "stats"            => 160,
    "service"          => 170,
);

my %stoporder = (
    "directory-server" => 0,
    "mailbox"          => 40,
    "memcached"        => 50,
    "proxy"            => 60,
    "antispam"         => 70,
    "antivirus"        => 80,
    "amavis"           => 85,
    "opendkim"         => 90,
    "cbpolicyd"        => 110,
    "mta"              => 140,
    "stats"            => 150,
    "service"          => 160,
    "zmconfigd"        => 210,
);

my %allservices = (
    "amavis"           => "/opt/zextras/bin/zmamavisdctl",
    "antivirus"        => "/opt/zextras/bin/zmantivirusctl",
    "antispam"         => "/opt/zextras/bin/zmantispamctl",
    "opendkim"         => "/opt/zextras/bin/zmopendkimctl",
    "mta"              => "/opt/zextras/bin/zmmtactl",
    "mailbox"          => "/opt/zextras/bin/zmstorectl",
    "service"          => "/opt/zextras/bin/zmstorectl",
    "directory-server" => "/opt/zextras/bin/ldap",
    "memcached"        => "/opt/zextras/bin/zmmemcachedctl",
    "proxy"            => "/opt/zextras/bin/zmproxyctl",
    "stats"            => "/opt/zextras/bin/zmstatctl",
    "zmconfigd"        => "/opt/zextras/bin/zmconfigdctl",
    "cbpolicyd"        => "/opt/zextras/bin/zmcbpolicydctl",
);

my %rewrites = (
    "antivirus" => "antivirus amavis",
    "antispam"  => "antispam amavis",
    "opendkim"  => "opendkim",
    "mta"       => "amavis antispam antivirus opendkim mta sasl",
    "mailbox"   => "webxml mailbox",
    "proxy"     => "proxy",
);

my %GlobalOpts = ();

my %DESC = (
    "start"    => "Start services",
    "startup"  => "Start services",
    "stop"     => "Stop services",
    "shutdown" => "Stop services",
    "restart"  => "Restart services",

    #"maintenance" => "Toggle maintenance mode",
    "status" => "Display service status",
);

my %COMMANDS = (
    "start"    => \&doStartup,
    "startup"  => \&doStartup,
    "stop"     => \&doShutdown,
    "shutdown" => \&doShutdown,
    "restart"  => \&doRestart,

    #"maintenance" => \&setMaintenanceMode,
    "status" => \&doStatus,
);

my %REMOTECOMMANDS = (
    "start"    => "startup",
    "startup"  => "startup",
    "stop"     => "shutdown",
    "shutdown" => "shutdown",
    "restart"  => "restart",

    #"maintenance" => "maintenance",
    "status" => "status",
);

my $zal_path     = "/opt/zextras/lib/ext/carbonio/zal.jar";
my $zextras_path = "/opt/zextras/lib/ext/carbonio/carbonio.jar";

# Commands: start, stop, restart and status
my $command = $ARGV[0];

systemdPrint() if isSystemd() && $command !~ /^-[vVhH]$/;

$| = 1;

unless ( getopts( 'VvhH:', \%GlobalOpts ) ) { usage(); }

if ( !$GlobalOpts{H} ) {
    $GlobalOpts{H} = $localHostName;
    chomp $GlobalOpts{H};
}

if ( $GlobalOpts{h} ) { usage(); }
if ( $GlobalOpts{v} ) { displayVersion(); exit 0; }
if ( $GlobalOpts{V} ) { displayPackagesVersion(); exit 0; }

unless ( defined( $COMMANDS{$command} ) ) { usage(); }

if ( $GlobalOpts{H} ne $localHostName ) {
    exit( runRemoteCommand($command) );
}

exit( &{ $COMMANDS{$command} }( $ARGV[1] ) );

#
# Functions
#
sub runRemoteCommand {
    my $cmd  = shift;
    my $cstr = "HOST:$GlobalOpts{H} $REMOTECOMMANDS{$cmd}";

    open( REMOTE, "echo $cstr | /opt/zextras/libexec/zmrc $GlobalOpts{H} |" )
      or die "Can't contact $GlobalOpts{H}";

    while (<REMOTE>) {
        if (/^STARTCMD: (\S+) .*/) {

            #print "Host $1 starting\n";
        }
        elsif (/^ENDCMD: (\S+) .*/) {
            print "Host $1 complete\n";
            exit;    # Since the pipe doesn't always like to close...
        }
        else {
            print "$_";
        }
    }
    close REMOTE;
}

sub doStatus {
    $services = getEnabledServices();
    getServiceStatusList();
    alarm($timeout);
    my ( undef, $statusfile ) = tempfile(
        "zmcontrol.status.XXXXX",
        DIR  => "$zimbra_tmp_directory",
        OPEN => 0
    );
    my ( undef, $errfile ) = tempfile(
        "zmcontrol.error.XXXXX",
        DIR  => "$zimbra_tmp_directory",
        OPEN => 0
    );
    if ( scalar( keys %$services ) == 0 ) {
        print "Cannot determine services - exiting\n";
        return 1;
    }
    my $status = 0;
    print "Host $localHostName\n";
    foreach ( sort keys %{$services} ) {
        if ( $_ eq "zimlet" || $_ eq "zimbraAdmin" || $_ eq "zimbra" ) { next; }
        my $rc = 0xffff & system("$allservices{$_} status > $statusfile 2> $errfile");
        $rc = $rc >> 8;
        if ($rc) {

            # this is an any ugly hack for 11266
            $status = 1 if ( $serviceStatusList{$_} );
        }
        my $stat;
        if ( $_ eq "service" ) {
            my $bit = "$_ webapp";
            $stat = sprintf "\t%-20s %10s\n", $bit, ($rc) ? "Stopped" : "Running";
        }
        elsif ( $_ eq "service-discover" ) {
            $rc   = system("systemctl is-active service-discover.service >/dev/null 2>&1");
            $stat = sprintf "\t%-20s %10s\n", $_, ($rc) ? "Stopped" : "Running";
        }
        else {
            my $service_name = renameServices($_);
            $stat = sprintf "\t%-20s %10s\n", $service_name, ($rc) ? "Stopped" : "Running";
            if ( $_ eq "mailbox" ) {
                my $res = `/opt/zextras/bin/advanced_status 0`;
                foreach my $line ( split /\n/, $res ) {
                    $stat = $stat . "\t --" . $line . "\n";
                }
            }
        }
        print "$stat";
        if ($rc) {
            open( ST, "$statusfile" ) or next;
            foreach my $s (<ST>) {
                print "\t\t$s";
            }
            close ST;
        }
    }
    unlink($statusfile);
    unlink($errfile);
    alarm(0);
    return $status;
}

sub startLdap {
    print "\tStarting directory server...";
    my $rc = 0xffff & system("/opt/zextras/bin/ldap start > $zmcontrolLogfile 2>&1");
    $rc = $rc >> 8;
    print "Done.\n";
    return $rc;
}

sub doRewrite {
    my $rew = "";
    foreach (@_) {
        $rew .= " $rewrites{$_}";
    }
    Zextras::Mon::Logger::Log( "info", "Rewriting configs $rew" );
    my $rc = 0xffff & system("/opt/zextras/libexec/configrewrite $rew > $zmcontrolLogfile 2>&1");
    $rc = $rc >> 8;
    return $rc;
}

sub doRestart {
    &doShutdown;
    &doStartup;
}

sub doStartup {
    Zextras::Mon::Logger::Log( "info", "Starting services initiated by zmcontrol" );
    print "Host $localHostName\n";
    my $rc  = 0;
    my $rrc = 0;
    if ($ldapHere) {
        my $ldapStopped = 0xffff & system("/opt/zextras/bin/ldap status > /dev/null 2>&1");
        if ($ldapStopped) {
            $rrc = startLdap();
        }
    }
    if ($rrc) {
        $rc = 1;
        my $out = qx(cat $zmcontrolLogfile);
        print "Failed.\n";
        print "$out\n\n";
        exit(1);
    }
    unlink($zmcontrolLogfile);
    $services = getEnabledServices();
    if ( scalar( keys %$services ) == 0 ) {
        return 1;
    }
    if ( defined( $$services{"directory-server"} ) ) {
        my $ldapStopped = 0xffff & system("/opt/zextras/bin/ldap status > /dev/null 2>&1");
        if ($ldapStopped) {
            $rrc = startLdap();
            sleep 3;
        }
    }
    if ($rrc) {
        $rc = 1;
        my $out = qx(cat $zmcontrolLogfile);
        print "Failed.\n";
        print "$out\n\n";
        exit(1);
    }

    checkAvailableSpace();
    foreach ( sort { $startorder{$a} <=> $startorder{$b} } keys %{$services} ) {
        if ( $_ eq "directory-server" || $_ eq "zimlet" || $_ eq "zimbraAdmin" || $_ eq "zimbra" ) { next; }
        if ( $_ eq "proxy" ) {
            $rrc = 0xffff & system("/opt/zextras/bin/zmresolverctl");
            $rrc = $rrc >> 8;
            if ($rrc) {
                print "resolvers.conf file generation failed.\n";
            }
        }
        checkAvailableServiceSpace($_);
        Zextras::Mon::Logger::Log( "info", "Starting $_ via zmcontrol" );
        if ( $_ eq "service" ) {
            print "\tStarting $_ webapp...";
        }
        elsif ( $_ eq "service-discover" ) { next; }
        else {
            my $service_name = renameServices($_);
            print "\tStarting $service_name...";
        }
        unless ( -x "$allservices{$_}" ) {
            print "skipped.\n\t\t$allservices{$_} missing or not executable.\n";
            next;
        }
        $rrc = 0xffff & system("$allservices{$_} start norewrite > $zmcontrolLogfile 2>&1");
        $rrc = $rrc >> 8;
        if ($rrc) {
            $rc = 1;
            my $out = qx(cat $zmcontrolLogfile);
            print "Failed.\n";
            print "$out\n\n";
        }
        else {
            print "Done.\n";
            if ( $_ eq "mailbox" ) {
                my $res = `/opt/zextras/bin/advanced_status 2`;
                foreach my $line ( split /\n/, $res ) {
                    print "\t --" . $line . "\n";
                }
            }
        }
        unlink($zmcontrolLogfile);
    }
    return $rc;
}

sub doShutdown {
    Zextras::Mon::Logger::Log( "info", "Stopping services initiated by zmcontrol" );
    print "Host $localHostName\n";
    my $rc  = 0;
    my $rrc = 0;
    foreach ( sort { $stoporder{$b} <=> $stoporder{$a} } keys %allservices ) {
        Zextras::Mon::Logger::Log( "info", "Stopping $_ via zmcontrol" );
        if ( $_ eq "zimlet" || $_ eq "zimbraAdmin" || $_ eq "zimbra" ) { next; }
        if ( $_ eq "directory-server"
            && !( -x "/opt/zextras/common/libexec/slapd" ) )
        {
            next;
        }
        if ( $_ eq "mta" && !( -x "/opt/zextras/common/sbin/postfix" ) ) {
            next;
        }
        if ( $_ eq "mailbox" && !( -d "/opt/zextras/db/data" ) ) { next; }
        if ( $_ eq "service" ) {
            print "\tStopping $_ webapp...";
        }
        else {
            my $service_name = renameServices($_);
            print "\tStopping $service_name...";
        }
        unless ( -x "$allservices{$_}" ) {
            print "skipped.\n\t\t$allservices{$_} missing or not executable.\n";
            next;
        }
        $rrc = 0xffff & system("$allservices{$_} stop > $zmcontrolLogfile 2>&1");
        $rrc = $rrc >> 8;
        if ($rrc) {
            $rc = 1;
            my $out = qx(cat $zmcontrolLogfile);
            print "Failed.\n";
            print "$out\n\n";
        }
        else {
            print "Done.\n";
        }
        unlink($zmcontrolLogfile);
    }
    return $rc;
}

sub setMaintenanceMode {
    my $mode = shift;
}

sub getServiceStatusList {
    my @services =
      split( /\s+/, getLocalConfig("zmcontrol_service_status_list") );
    @services = grep( !/stats|logger/, keys %allservices )
      if ( scalar @services < 1 );
    if ( scalar @services > 1 ) {
        foreach my $service (@services) {
            $serviceStatusList{$service} = 1
              if ( defined( $allservices{$service} ) );
        }
    }
}

sub getLocalConfig {
    my $key = shift;
    if ( defined( $ENV{zmsetvars} ) ) {
        return $ENV{$key};
    }
    open CONF, "/opt/zextras/bin/zmlocalconfig -x -s -q -m shell |"
      or die "Can't open zmlocalconfig: $!";
    my @conf = <CONF>;
    close CONF;

    chomp @conf;

    foreach (@conf) {
        my ( $key, $val ) = split '=', $_, 2;
        $val =~ s/;$//;
        $val =~ s/'$//;
        $val =~ s/^'//;
        $ENV{$key} = $val;
    }
    $ENV{zmsetvars} = 'true';
    return $ENV{$key};
}

sub getCachedServices {
    my %s = ();
    $s{"zmconfigd"} = "zmconfigd";
    if ( -f $cache_file && -M $cache_file <= 1 ) {
        open( CACHE, "<$cache_file" );
        my @lines = <CACHE>;
        close CACHE;
        foreach (@lines) {
            chomp;
            $s{$_} = $_;
        }
    }
    else {
        print "Unable to determine enabled services. Cache is out of date or doesn't exist.\n";
        exit 1;
    }
    warn "Enabled services read from cache. Service list may be inaccurate.\n"
      if ( scalar keys %s > 0 );
    return \%s;
}

sub getEnabledServices {
    my $ldap_master_url         = getLocalConfig("ldap_master_url");
    my $ldap_dn                 = getLocalConfig("zimbra_ldap_userdn");
    my $ldap_pass               = getLocalConfig("zimbra_ldap_password");
    my $require_tls             = getLocalConfig("zimbra_require_interprocess_security");
    my $ldap_starttls_supported = getLocalConfig("ldap_starttls_supported");

    my %s = ();
    $s{"zmconfigd"} = "zmconfigd";

    my @ldap_masters = split( / /, $ldap_master_url );
    my $master_ref   = \@ldap_masters;
    my ( $ldap, $result );
    unless ( $ldap = Net::LDAP->new( $master_ref, timeout => 30 ) ) {
        warn "Connect: Unable to determine enabled services from ldap.\n";
        return getCachedServices();
    }
    if ($ldap_starttls_supported) {
        my $type = "none";
        if ($require_tls) {
            $type = "require";
        }
        my $result = $ldap->start_tls(
            verify => "$type",
            capath => "/opt/zextras/conf/ca",
        );
        if ( $result->code ) {
            warn "Unable to start TLS: " . $result->error . " when connecting to master directory server.\n";
            return ();
        }
    }
    unless ( $result = $ldap->bind( $ldap_dn, password => $ldap_pass ) ) {
        warn "Bind: Unable to determine enabled services from directory server.\n";
        return getCachedServices();
    }
    $result = $ldap->search(
        base   => "cn=servers,cn=zimbra",
        filter => "cn=$localHostName",
        attrs  => ['zimbraServiceEnabled']
    );
    if ( $result->code ) {
        warn "Search error: Unable to determine enabled services from directory server.\n";
        return getCachedServices();
    }
    my $size = $result->count;
    if ( $size != 1 ) {
        warn "Size error: Unable to determine enabled services from directory server.\n";
        return getCachedServices();
    }
    my $entry = $result->entry(0);
    foreach my $value ( $entry->get_value('zimbraServiceEnabled') ) {

        # Need to exclude legacy services. See CO-496
        if ( $value ne "zimlet" && $value ne "zimbraAdmin" && $value ne "zimbra" ) {
            $s{$value} = $value;
        }
    }
    $result = $ldap->unbind;

    if ( scalar keys %s > 0 ) {
        open( CACHE, ">$cache_file" );
        foreach my $service ( keys %s ) {
            print CACHE "$service\n";
        }
        close(CACHE);
    }
    return \%s;
}

sub isLdapLocal {
    return ( ( index( getLocalConfig("ldap_url"), "/" . getLocalConfig("zimbra_server_hostname") ) != -1 ) ? 1 : 0 );
}

sub getHostName {
    return ( getLocalConfig("zimbra_server_hostname") );
}

sub displayVersion {
    my $additional_zal_version = "";
    if ( -e $zal_path and -e $zextras_path ) {
        $additional_zal_version = `/opt/zextras/bin/carbonio core getVersion`;
        chomp $additional_zal_version;
    }

    my $release = qx(cat /opt/zextras/.version);
    chomp $release;

    my $output = "Carbonio Release $release";
    if ( !( $additional_zal_version eq "" ) ) {
        $output .= "\nAdvanced module version:\n" . $additional_zal_version;
    }
    print "$output\n";
}

sub displayPackagesVersion {
    my $release = qx(cat /opt/zextras/.version);
    chomp $release;
    my $distro = `grep -oP '(?<=^ID=).+' /etc/os-release`;
    chomp $distro;

    my $packages = "";
    if ( $distro eq "ubuntu" ) {
        $packages = qx'dpkg-query -W -f\'${Package} ${Version}\n\' carbonio\*';
    }
    else {
        $packages = qx'dnf list installed 2>/dev/null | grep carbonio* | awk -F\' \' \'{{ print $1 " " $2 }}\'';
    }

    my $output = "Carbonio Release $release\n";
    if ( -e $zal_path and -e $zextras_path ) {
        $output .= "Advanced version installed";
    }
    if ( !( $packages eq "" ) ) {
        $output .= "\nInstalled packages:\n" . "$packages";
    }
    else {
        $output .= "\n";
    }

    print "$output";
}

sub checkAvailableSpace {
    my ($service) = @_;

    my @dirs = ("/opt/zextras");
    foreach my $dir (@dirs) {
        if ( -e "$dir" ) {
            print "\tWARNING: Disk space below threshold for $dir.\n"
              unless hasAvailableSpace($dir);
        }
    }
}

sub checkAvailableServiceSpace {
    my ($service) = @_;

    my %serviceDirs = (
        mailbox => [ "/opt/zextras/store", "/opt/zextras/db", "/opt/zextras/index", "/opt/zextras/redolog" ],
        mta     => ["/opt/zextras/data/postfix/spool"]
    );
    my @dirs = ();
    @dirs = ( @dirs, @{ $serviceDirs{$service} } )
      if ( defined $serviceDirs{$service} );
    foreach my $dir (@dirs) {
        if ( -e "$dir" ) {
            print "\tWARNING: Disk space below threshold for $dir.\n"
              unless hasAvailableSpace($dir);
        }
    }
}

sub hasAvailableSpace() {
    my ( $dir, $freeMbytes ) = @_;
    return undef unless ( -e "$dir" );
    $freeMbytes = getLocalConfig("zimbra_disk_threshold") || 100
      unless $freeMbytes;

    my $DFCMD = "df -mlP ";

    open DF, "$DFCMD $dir | tail -1 |" or die "Can't open $DFCMD: $!";
    my @df = <DF>;
    close DF;
    my ( $device, $total, undef, $avail ) = split( /\s+/, $df[0] );
    return 1 if ( defined( $devicesChecked{$device} ) );
    $devicesChecked{$device} = $avail;
    if ( $avail < $freeMbytes ) {
        Zextras::Mon::Logger::Log( "info", "Availble disk space on $dir is below threshold of $freeMbytes.  $avail Mbytes available." );
    }

    return ( $avail > $freeMbytes ) ? 1 : undef;
}

sub renameServices {
    my ($service_id) = @_;

    my $service_name = $serviceNames{$service_id};
    if ( $service_name eq "" ) {
        $service_name = $service_id;
    }

    return $service_name;
}

sub usage {
    displayVersion();
    print "$0 [-v -h -H <host>] command [args]\n";
    print "\n";
    print "\t-v:	display version\n";
    print "\t-V:	display advanced version information\n";
    print "\t-h:	print usage statement\n";
    print "\t-H:	Host name (localhost)\n";
    print "\n";
    print "\tCommand in:\n";

    foreach ( sort keys %COMMANDS ) {
        print "\t\t" . sprintf( "%-20s%30s", $_, $DESC{$_} ) . "\n";
    }

    print "\n";
    exit 1;
}
