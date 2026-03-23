#!/usr/bin/perl
#
# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only
#

use strict;

use lib "/opt/zextras/libexec";
use lib "/opt/zextras/common/lib/perl5";
use Zextras::Util::Common;
use Zextras::Util::Timezone;
use Zextras::Util::Systemd;
use Zextras::Setup::DNS;
use Zextras::Setup::SSL;
use Zextras::Setup::LDAP;
use Zextras::Setup::Menu;
use FileHandle;
use Net::LDAP;
use IPC::Open3;
use Cwd;
use Time::localtime qw(ctime);

$| = 1;    # don't buffer stdout

our $platform = qx(grep -oP '(?<=^ID=).+' /etc/os-release);
chomp $platform;
my $logFileName = "zmsetup." . getDateStamp() . ".log";
my $logfile     = "/tmp/" . $logFileName;
open LOGFILE, ">$logfile" or die "Can't open $logfile: $!\n";
unlink("/tmp/zmsetup.log") if ( -e "/tmp/zmsetup.log" );
symlink( $logfile, "/tmp/zmsetup.log" );

my $ol = select(LOGFILE);
$| = 1;
select($ol);

progress("Operations logged to $logfile\n");

our $ZMPROV = "/opt/zextras/bin/zmprov -r -m -l";
our $SU     = "su - zextras -c ";

my $filename = "/opt/zextras/conf/localconfig.xml";
my $uid      = ( stat $filename )[4];
my $user     = ( getpwuid $uid )[0];

if ( $user ne "zextras" ) {
    progress("\n\nERROR\n\n");
    progress("/opt/zextras/conf/localconfig.xml is not owned by zextras\n");
    progress("This will cause installation failure.\n");
    exit(1);
}

use ldapinit;
use Getopt::Std;

our %options = ();
our %config  = ();
our %loaded  = ();
our %saved   = ();

our @packageList = (
    "carbonio-core",
    "carbonio-clamav",
    "carbonio-directory-server",
    "carbonio-mta",
    "carbonio-appserver",
    "carbonio-memcached",
    "carbonio-proxy",
);

my %packageServiceMap = (
    amavis             => "carbonio-mta",
    antivirus          => "carbonio-clamav",
    antispam           => "carbonio-mta",
    opendkim           => "carbonio-mta",
    cbpolicyd          => "carbonio-mta",
    mta                => "carbonio-mta",
    mailbox            => "carbonio-appserver",
    'directory-server' => "carbonio-directory-server",
    'service-discover' => "carbonio-core",
    stats              => "carbonio-core",
    memcached          => "carbonio-memcached",
    proxy              => "carbonio-proxy",
    service            => "carbonio-appserver",
);

our $serviceWebApp = "service";

our %installedPackages     = ();
our %installedWebapps      = ();
our %prevInstalledPackages = ();
our %prevEnabledServices   = ();
our %enabledPackages       = ();
our %enabledServices       = ();

my %installStatus = ();
our %configStatus = ();

our $newinstall = 1;
chomp(
    our $ldapSchemaVersion = do {
        local $/ = undef;
        open my $fh, "<", "/opt/zextras/conf/attrs-schema"
          or die "could not open /opt/zextras/conf/attrs-schema: $!";
        <$fh>;
    }
);

our $ldapConfigured           = 0;
our $haveSetLdapSchemaVersion = 0;
our $ldapRunning              = 0;
my $sqlConfigured             = 0;
my $sqlRunning                = 0;
our @installedServiceList     = ();
our @enabledServiceList       = ();

our $ldapRootPassChanged                   = 0;
our $ldapAdminPassChanged                  = 0;
our $ldapRepChanged                        = 0;
our $ldapPostChanged                       = 0;
our $ldapAmavisChanged                     = 0;
our $ldapNginxChanged                      = 0;
our $ldapReplica                           = 0;
our $starttls                              = 0;
our $needNewCert                           = "";
our $ssl_cert_type                         = "self";
our $publicServiceHostnameAlreadySet = 0;

our @ssl_digests = ( "ripemd160", "sha", "sha1", "sha224", "sha256", "sha384", "sha512" );
our @interfaces  = ();

($>) and usage();

getopts( "c:hd", \%options ) or usage();

my $debug = $options{d};

usage() if ( $options{h} );

isSystemd();
getInstallStatus();
my $bootStrapMode = ($newinstall) ? "new install" : "existing install";

progress("\nBootstrap mode: $bootStrapMode\n");

if ( isInstalled("carbonio-directory-server") ) {
    if ( $newinstall || !-f "/opt/zextras/data/ldap/config/cn\=config.ldif" ) {
        installLdapConfig();
    }
}

if ( isInstalled("carbonio-directory-server") ) {
    installLdapSchema();
}

if ( !$newinstall ) {
    if ( -f "/opt/zextras/conf/ca/ca.pem" ) {
        progress("Adding /opt/zextras/conf/ca/ca.pem to cacerts...");
        my $ec = runAsZextras("/opt/zextras/bin/zmcertmgr addcacert /opt/zextras/conf/ca/ca.pem");
        if ( $ec != 0 ) {
            progress("failed.\n");
        }
        else {
            progress("done.\n");
        }
    }
}

getInstalledPackages();

unless ( isEnabled("carbonio-core") ) {
    progress("carbonio-core must be enabled.");
    exit 1;
}

getInstalledWebapps();

if ( $options{d} ) {
    foreach my $pkg ( keys %installedPackages ) {
        detail("Package $pkg is installed.");
    }
    foreach my $pkg ( keys %enabledPackages ) {
        detail("Package $pkg is $enabledPackages{$pkg}.");
    }
}

setDefaults();

setDefaultsFromLocalConfig() if ( !$newinstall );

setEnabledDependencies();

checkPortConflicts();

if ( !$newinstall ) {
    my $rc = system("/opt/zextras/libexec/zmldapupdateldif");
}

if ( $options{c} ) {
    loadConfig( $options{c} );
}

if ( $ldapConfigured || ( ( $config{LDAPHOST} ne $config{HOSTNAME} ) && ldapIsAvailable() ) ) {
    setLdapDefaults();
    getAvailableComponents();
}

if ( $options{c} ) {
    applyConfig();
}
else {
    if (   $configStatus{BEGIN} eq "CONFIGURED"
        && $configStatus{END} ne "CONFIGURED" )
    {
        resumeConfiguration();
    }
    mainMenu();
}

close LOGFILE;
moveLogToZextras();

################################################################
# End Main
################################################################

################################################################
# Subroutines
################################################################

sub usage {
    ($>) and print STDERR "Warning: $0 must be run as root!\n\n";
    print STDERR "Usage: $0 [-h] [-c <config file>]\n";
    print STDERR "\t-h: display this help message\n";
    print STDERR "\t-c: configure with values in <config file>\n\n";
    exit 1;
}

sub progress {
    my $msg = shift;
    print "$msg";
    my ( $sub, $line ) = ( caller(1) )[ 3, 2 ];
    $msg = "$sub:$line $msg" if $options{d};
    detail($msg);
}

sub detail {
    my $msg = shift;
    my ( $sub, $line ) = ( caller(1) )[ 3, 2 ];
    my $date = ctime();
    $msg =~ s/\n$//;
    $msg = "$sub:$line $msg" if $options{d};
    print LOGFILE "$date $msg\n";
}

# Helper function to print done/failed based on return code
# Usage: progressResult($rc) or progressResult($rc, 1) to exit on failure
sub progressResult {
    my ( $rc, $exitOnFail ) = @_;
    if ( $rc != 0 ) {
        progress("failed.\n");
        exit 1 if $exitOnFail;
        return 0;
    }
    progress("done.\n");
    return 1;
}


# Track if log has been moved to avoid duplication
my $logFileMoved = 0;

sub moveLogToZextras {
    return if $logFileMoved;
    chmod 0600, $logfile;
    if ( -d "/opt/zextras/log" ) {
        progress("Moving $logfile to /opt/zextras/log\n");
        system("cp -f $logfile /opt/zextras/log/");
        system("chown zextras:zextras /opt/zextras/log/$logFileName");
    }
    else {
        progress("Operations logged to $logfile\n");
    }
    $logFileMoved = 1;
}




sub defineInstallWebapps {
    if ( !defined $config{INSTALL_WEBAPPS} ) {
        if ( $config{SERVICEWEBAPP} eq "yes" ) {
            $config{INSTALL_WEBAPPS} = "service $config{INSTALL_WEBAPPS}";
        }
    }
}

sub saveConfig {
    my $fname = "/opt/zextras/config.$$";

    if ( open CONF, ">$fname" ) {
        progress("Saving config in $fname...");
        foreach ( sort keys %config ) {

            # Don't write passwords or previous INSTALL_PACKAGES
            if (/PASS|INSTALL_PACKAGES/) { next; }
            print CONF qq($_="$config{$_}"\n);
        }
        print CONF qq(INSTALL_PACKAGES=");
        foreach (@packageList) {
            my $el = $_;
            if ( grep( /$el/, keys %installedPackages ) ) {
                print CONF "$_ ";
            }
        }
        print CONF qq("\n);
        close CONF;
        chmod 0600, $fname;
        progress("done.\n");
    }
    else {
        progress("Cannot open $fname: $!\n");
    }
}

sub loadConfig {
    my $filename = shift;
    open( CONF, $filename ) or die "Can't open $filename: $!";
    my @lines = <CONF>;
    close CONF;
    foreach (@lines) {
        chomp;
        my ( $k, $v ) = split( '=', $_, 2 );
        $v =~ s/"//g;
        $config{$k} = $v;
    }

    $config{ALLOWSELFSIGNED} = "true";
}

sub checkPortConflicts {
    progress("Checking for port conflicts...\n");
    my %needed = (
        25    => 'carbonio-mta',
        80    => 'carbonio-appserver',
        110   => 'carbonio-appserver',
        143   => 'carbonio-appserver',
        389   => 'carbonio-directory-server',
        443   => 'carbonio-appserver',
        636   => 'carbonio-directory-server',
        993   => 'carbonio-appserver',
        995   => 'carbonio-appserver',
        7025  => 'carbonio-appserver',
        7071  => 'carbonio-appserver',
        7072  => 'carbonio-appserver',
        7306  => 'carbonio-appserver',
        7307  => 'carbonio-appserver',
        8465  => 'carbonio-mta',
        10024 => 'carbonio-mta',
        10025 => 'carbonio-mta',
        10026 => 'carbonio-mta',
        10027 => 'carbonio-mta',
        10028 => 'carbonio-mta',
        10029 => 'carbonio-mta',
        10030 => 'carbonio-mta',
    );

    open PORTS, "netstat -an | egrep '^tcp' | grep LISTEN | awk '{print \$4}' | sed -e 's/.*://' |";
    my @ports = <PORTS>;
    close PORTS;
    chomp @ports;

    my $any = 0;
    foreach (@ports) {
        if ( defined( $needed{$_} ) && isEnabled( $needed{$_} ) ) {
            unless ( $needed{$_} eq "carbonio-directory-server" && $newinstall == 0 ) {
                $any = 1;
                progress("Port conflict detected: $_ ($needed{$_})\n");
            }
        }
    }

    if ( !$options{c} ) {
        if ($any) { ask( "Port conflicts detected! - Press Enter/Return key to continue", "" ); }
    }

}

sub isComponentAvailable {
    my $component = shift;
    detail("Checking isComponentAvailable $component...");

    # if its already defined return;
    if ( exists $main::loaded{components}{$component} ) {
        return 1;
    }
    if ( $ldapConfigured
        || ( ( $config{LDAPHOST} ne $config{HOSTNAME} ) && ldapIsAvailable() ) )
    {
        getAvailableComponents();
    }
    if ( exists $main::loaded{components}{$component} ) {
        detail("Component $component is available.");
        return 1;
    }
    else {
        detail("Component $component is not available.");
        return 0;
    }

}

sub getAvailableComponents {
    detail("Getting available components...");
    open( ZM, "$ZMPROV gcf zimbraComponentAvailable 2> /dev/null|" )
      or return undef;
    while (<ZM>) {
        chomp;
        if (/^zimbraComponentAvailable: (\S+)/) {
            $main::loaded{components}{$1} = "zimbraComponentAvailable";
        }
    }
    close(ZM) or return undef;
}

sub getDateStamp() {
    my ( $sec, $min, $hour, $mday, $mon, $year ) = localtime( time() );
    $year = 1900 + $year;
    $sec  = sprintf( "%02d", $sec );
    $min  = sprintf( "%02d", $min );
    $hour = sprintf( "%02d", $hour );
    $mday = sprintf( "%02d", $mday );
    $mon  = sprintf( "%02d", $mon + 1 );
    my $stamp = "$year$mon$mday-$hour$min$sec";
    return $stamp;
}


sub getInstalledPackages {
    detail("Getting installed packages...");
    foreach my $p (@packageList) {
        if ( isInstalled($p) ) {
            $installedPackages{$p} = $p;
        }
    }

    # get list of previously installed packages and enabled services on upgrade
    if ( $newinstall != 1 ) {
        return 1 if ensureLdapForServerQuery();

        detail("Getting installed and enabled services from LDAP...");
        $enabledPackages{"carbonio-core"} = "Enabled"
          if ( isInstalled("carbonio-core") );

        open( ZMPROV, "$ZMPROV gs $config{zimbra_server_hostname}|" );
        while (<ZMPROV>) {
            chomp;
            if (/zimbraServiceInstalled:\s(.*)/) {
                my $service = $1;
                if ( exists $packageServiceMap{$service} ) {
                    detail("Marking $service as previously installed.")
                      if ($debug);
                    $prevInstalledPackages{ $packageServiceMap{$service} } = "Installed";
                }
                else {
                    progress("WARNING: Unknown package installed for $service.\n");
                }
            }
            elsif (/zimbraServiceEnabled:\s(.*)/) {
                my $service = $1;
                if ( $service eq "imapproxy" ) {
                    $service = "proxy";
                }
                if ( exists $packageServiceMap{$service} ) {
                    detail("Marking $service as an enabled service.")
                      if ($debug);
                    $enabledPackages{ $packageServiceMap{$service} } = "Enabled";
                    $enabledServices{$service}                       = "Enabled";
                    $prevEnabledServices{$service}                   = "Enabled";
                }
                else {
                    progress("WARNING: Unknown package installed for $service.\n");
                }
            }
            else {
                detail("DEBUG: skipping => $_") if $debug;
            }
        }
        close(ZMPROV);

        foreach my $p (@packageList) {
            if ( isInstalled($p) and not defined $prevInstalledPackages{$p} ) {
                detail("Marking $p as installed. Services for $p will be enabled.");
                $enabledPackages{$p} = "Enabled";
            }
            elsif ( isInstalled($p) and not defined $enabledPackages{$p} ) {
                detail("Marking $p as disabled.");
                $enabledPackages{$p} = "Disabled";
            }
        }
    }

}

sub getInstalledWebapps {
    detail("Determining installed web applications...");

    # E.g.: installedWebapps = {"service": "Enabled"}
    if (   ( $newinstall && isEnabled("carbonio-appserver") )
        || ( !$newinstall && isServiceEnabled($serviceWebApp) ) )
    {
        $installedWebapps{$serviceWebApp} = "Enabled";
        detail("Web application $serviceWebApp is enabled.");
    }
    else {
        # to enable webapps on configured installation
        if ( $newinstall != 1 && $installedWebapps{$serviceWebApp} ne "Enabled" ) {
            $installedWebapps{$serviceWebApp} = "Enabled";
        }
    }

    # updates global config map putting the app if Enabled
    if ( !$newinstall && !defined( $config{INSTALL_WEBAPPS} ) ) {
        foreach my $app ( keys %installedWebapps ) {
            if ( $installedWebapps{$app} eq "Enabled" ) {
                $config{INSTALL_WEBAPPS} = "$app $config{INSTALL_WEBAPPS}";
            }
        }
    }
}

sub isServiceEnabled {
    my $service = shift;

    if ( defined( $enabledServices{$service} ) ) {
        if ( $enabledServices{$service} eq "Enabled" ) {
            detail("Service $service is enabled.");
            return 1;
        }
        else {
            detail("Service $service is not enabled.");
            return undef;
        }
    }
    else {
        detail("Service $service not in enabled cache.");
    }

    return undef;
}

sub isEnabled {
    my $package = shift;

    # if its already defined return without logging (reduces log noise)
    if ( defined $enabledPackages{$package} ) {
        return ( $enabledPackages{$package} eq "Enabled" ) ? 1 : undef;
    }

    # Only log on cache miss
    detail("Checking isEnabled $package (cache miss).");
    my $packages = join( " ", keys %enabledPackages );
    detail("Enabled packages: $packages.");

    # On new install, enable all installed packages (LDAP data loaded by getInstalledPackages on upgrade)
    if ($newinstall) {
        detail("New install, enabling all installed packages...");
        foreach my $p (@packageList) {
            if ( isInstalled($p) ) {
                unless ( $enabledPackages{$p} eq "Disabled" ) {
                    detail("Enabling $p.");
                    $enabledPackages{$p} = "Enabled";
                }
            }
        }
    }

    $enabledPackages{$package} = "Disabled"
      if ( $enabledPackages{$package} ne "Enabled" );

    return ( $enabledPackages{$package} eq "Enabled" ? 1 : 0 );
}

my %isInstalledCache;

sub isInstalled {
    my $pkg = shift;

    return $isInstalledCache{$pkg} if exists $isInstalledCache{$pkg};

    my $pkgQuery;

    my $good = 0;
    if ( $platform =~ /ubuntu/ ) {
        $pkgQuery = "dpkg -s $pkg";
    }
    else {
        $pkgQuery = "rpm -q $pkg";
    }

    my $rc = 0xffff & system("$pkgQuery > /dev/null 2>&1");
    $rc >>= 8;
    my $result;
    if ( ( $platform =~ /ubuntu/ ) && $rc == 0 ) {
        $good     = 1;
        $pkgQuery = "dpkg -s $pkg | egrep '^Status: ' | grep 'not-installed'";
        $rc       = 0xffff & system("$pkgQuery > /dev/null 2>&1");
        $rc >>= 8;
        $result = ( $rc == $good );
    }
    else {
        $result = ( $rc == $good );
    }

    $isInstalledCache{$pkg} = $result;
    return $result;
}

sub genRandomPass {
    open RP, "/opt/zextras/bin/zmjava com.zimbra.common.util.RandomPassword -l 8 10|"
      or die "Can't generate random password: $!\n";
    my $rp = <RP>;
    close RP;
    chomp $rp;
    return $rp;
}

sub getSystemStatus {
    if ( isEnabled("carbonio-directory-server") ) {
        if ( -f "/opt/zextras/data/ldap/mdb/db/data.mdb" ) {
            $ldapConfigured = 1;
            $ldapRunning    = isLdapRunning();
        }
        else {
            $config{DOCREATEDOMAIN} = "yes";
        }
    }

    if ( isEnabled("carbonio-appserver") ) {
        if ( -d "/opt/zextras/db/data/zimbra" ) {
            $sqlConfigured = 1;
            $sqlRunning    = 0xffff & system("/opt/zextras/bin/mysqladmin status > /dev/null 2>&1");
            $sqlRunning    = ($sqlRunning) ? 0 : 1;
        }
        if ($newinstall) {
            $config{DOCREATEADMIN} = "yes";
            $config{DOTRAINSA}     = "yes";
        }
    }

    if ( isEnabled("carbonio-mta") ) {
        $config{SMTPHOST} = $config{HOSTNAME} if ( $config{SMTPHOST} eq "" );
    }
}


sub installLdapConfig {
    my $config_src  = "/opt/zextras/common/etc/openldap/zimbra/config";
    my $config_dest = "/opt/zextras/data/ldap/config";
    if ( -d "/opt/zextras/data/ldap/config" ) {
        progress("Installing LDAP configuration database...");
        # Copy config structure with single tar pipe (instead of 10 individual cp calls)
        qx(mkdir -p $config_dest/cn\=config/olcDatabase\=\{2\}mdb);
        system("cd $config_src && tar cf - cn=config.ldif cn=config | tar xf - -C $config_dest");
        # Set permissions: chown everything, chmod all ldif files to 600
        qx(chown -R zextras:zextras $config_dest && find $config_dest -name '*.ldif' -exec chmod 600 {} +);
        progress("done.\n");
    }
}

sub installLdapSchema {
    runAsZextras("/opt/zextras/libexec/zmldapschema 2>/dev/null");
}

sub setDefaults {
    progress("Setting defaults...") unless $options{d};

    # Get the interfaces.
    # Do this in perl, since it's the same on all platforms.
    my $ipv4found = 0;
    my $ipv6found = 0;

    open INTS, "/sbin/ifconfig | grep ' addr' |";
    foreach (<INTS>) {
        chomp;
        if ( $_ =~ /inet6/ ) {
            next if ( $_ =~ /Link/ );
            s/.*inet6 //;
            s/.*addr: //;
            s/\/.*//;
            if ( $_ ne "::1" ) {
                $ipv6found = 1;
            }
        }
        else {
            s/.*inet //;
            s/\s.*//;
            s/[a-zA-Z:]//g;
            s/^\n//g;
            next if ( $_ eq "" );
            if ( $_ ne "127.0.0.1" ) {
                $ipv4found = 1;
            }
        }
        push @interfaces, $_;
    }
    close INTS;
    if ( -x "/sbin/ip" ) {
        open INTS, "/sbin/ip addr| grep ' scope ' |";
        foreach (<INTS>) {
            chomp;
            if ( $_ =~ /inet6/ ) {
                next if ( $_ =~ /link/ );
                s/.*inet6 //;
                s/.*addr: //;
                s/\/.*//;
                if ( $_ ne "::1" ) {
                    $ipv6found = 1;
                }
            }
            else {
                s/.*inet //;
                s/\/.*//;
                s/[a-zA-Z:]//g;
                s/^\n//g;
                next if ( $_ eq "" );
                if ( $_ ne "127.0.0.1" ) {
                    $ipv4found = 1;
                }
            }
            push @interfaces, $_;
        }
        close INTS;
    }

    my %seen = ();
    @interfaces = grep { !$seen{$_}++ } @interfaces;

    $config{EXPANDMENU} = "no";
    $config{REMOVE}     = "no";
    $config{UPGRADE}    = "yes";
    $config{LDAPPORT}   = 389;

    $config{IMAPPORT}           = 143;
    $config{IMAPSSLPORT}        = 993;
    $config{POPPORT}            = 110;
    $config{POPSSLPORT}         = 995;
    $config{HTTPPORT}           = 80;
    $config{HTTPSPORT}          = 443;
    $config{ssl_default_digest} = "sha256";

    if ( !$ipv4found && $ipv6found ) {
        $config{zimbraIPMode} = "ipv6";
    }
    else {
        $config{zimbraIPMode} = "ipv4";
    }

    $config{JAVAHOME} = "/opt/zextras/common/lib/jvm/java";
    setLocalConfig( "zimbra_java_home", "$config{JAVAHOME}" );
    $config{HOSTNAME} = lc(qx(hostname --fqdn));
    chomp $config{HOSTNAME};

    $config{ldap_dit_base_dn_config} = "cn=zimbra"
      if ( $config{ldap_dit_base_dn_config} eq "" );

    $config{mailboxd_directory} = "/opt/zextras/mailboxd";
    if ( -d "/opt/zextras/mailboxd" ) {
        $config{mailboxd_server}   = "jetty";
        $config{mailboxd_keystore} = "$config{mailboxd_directory}/etc/keystore";
    }
    else {
        $config{mailboxd_keystore} = "/opt/zextras/conf/keystore";
    }
    $config{mailboxd_truststore}          = "/opt/zextras/common/lib/jvm/java/lib/security/cacerts";
    $config{mailboxd_keystore_password}   = genRandomPass();
    $config{mailboxd_truststore_password} = "changeit";

    $config{SMTPHOST}       = "";
    $config{DOCREATEDOMAIN} = "no";
    my $sHostname = lc(qx(hostname -s));
    chomp $sHostname;
    $config{CREATEDOMAIN} = $config{HOSTNAME};
    $config{CREATEDOMAIN} =~ s/$sHostname\.//g;
    $config{DOCREATEADMIN} = "no";

    if ( isEnabled("carbonio-appserver") ) {
        progress "setting defaults for carbonio-appserver.\n" if $options{d};
        $config{DOCREATEADMIN}                  = "yes" if $newinstall;
        $config{DOTRAINSA}                      = "yes";
        $config{SERVICEWEBAPP}                  = "yes";    # since carbonio-appserver servers are valid upstreams and need to be
                                                            # included in the upstream config of the reverse proxy
        $config{zimbraReverseProxyLookupTarget} = "TRUE";
        $config{zimbraMailProxy}                = "TRUE" if $newinstall;
        $config{zimbraWebProxy}                 = "TRUE" if $newinstall;

        # default values for upgrades
        if ( $config{TRAINSASPAM} eq "" ) {
            $config{TRAINSASPAM} = "spam." . lc( genRandomPass() );
            $config{TRAINSASPAM} .= '@' . $config{CREATEDOMAIN};
        }
        if ( $config{TRAINSAHAM} eq "" ) {
            $config{TRAINSAHAM} = "ham." . lc( genRandomPass() );
            $config{TRAINSAHAM} .= '@' . $config{CREATEDOMAIN};
        }
        if ( $config{VIRUSQUARANTINE} eq "" ) {
            $config{VIRUSQUARANTINE} = "virus-quarantine." . lc( genRandomPass() );
            $config{VIRUSQUARANTINE} .= '@' . $config{CREATEDOMAIN};
        }
    }

    $config{zimbra_require_interprocess_security} = 0;
    $config{ZIMBRA_REQ_SECURITY}                  = "no";

    if ( isEnabled("carbonio-directory-server") ) {
        progress "setting defaults for carbonio-directory-server.\n"
            if $options{d};
        $config{DOCREATEDOMAIN}      = "yes" if $newinstall;
        $config{LDAPROOTPASS}        = genRandomPass();
        $config{LDAPADMINPASS}       = $config{LDAPROOTPASS};
        $config{LDAPREPPASS}         = $config{LDAPADMINPASS};
        $config{LDAPPOSTPASS}        = $config{LDAPADMINPASS};
        $config{LDAPAMAVISPASS}      = $config{LDAPADMINPASS};
        $config{ldap_nginx_password} = $config{LDAPADMINPASS};
        $config{LDAPREPLICATIONTYPE} = "master";                 # Values can be master, mmr, replica
        $config{LDAPSERVERID}        = 2;                        # Aleady enabled master should be 1, so default to next ID.
        $ldapRepChanged              = 1;
        $ldapPostChanged             = 1;
        $ldapAmavisChanged           = 1;
        $ldapNginxChanged            = 1;
    }

    if ( isInstalled("carbonio-proxy") && !isEnabled("carbonio-directory-server") ) {
        $config{ldap_nginx_password} = genRandomPass();
        $ldapNginxChanged = 1;
    }

    $config{CREATEADMIN} = "zextras\@$config{CREATEDOMAIN}";

    my $tzname = qx(/bin/date '+%Z');
    chomp($tzname);

    detail("Local timezone detected as $tzname.\n");
    my $tzdata = Zextras::Util::Timezone->parse;
    my $tz     = $tzdata->gettzbyname($tzname);
    $config{zimbraPrefTimeZoneId} = $tz->tzid if ( defined $tz );
    $config{zimbraPrefTimeZoneId} = 'America/Los_Angeles'
      if ( $config{zimbraPrefTimeZoneId} eq "" );
    detail("Default Olson timezone name: $config{zimbraPrefTimeZoneId}.\n");

    #progress("tzname=$tzname tzid=$config{zimbraPrefTimeZoneId}");

    $config{zimbra_ldap_userdn} = "uid=zimbra,cn=admins,$config{ldap_dit_base_dn_config}";

    $config{SMTPSOURCE}   = $config{CREATEADMIN};
    $config{SMTPDEST}     = $config{CREATEADMIN};
    $config{AVUSER}       = $config{CREATEADMIN};
    $config{AVDOMAIN}     = $config{CREATEDOMAIN};
    $config{STARTSERVERS} = "yes";

    if ( isEnabled("carbonio-mta") ) {
        progress "setting defaults for carbonio-mta.\n" if $options{d};
        my @tmpval = (qx(/opt/zextras/libexec/zmserverips -n));
        chomp(@tmpval);
        if (@tmpval) {
            $config{zimbraMtaMyNetworks} = "@tmpval";
        }
        else {
            $config{zimbraMtaMyNetworks} = "127.0.0.0/8 [::1]/128 @interfaces";
        }
        $config{postfix_mail_owner}   = "postfix";
        $config{postfix_setgid_group} = "postdrop";
    }

    $config{MODE}      = "https";
    $config{PROXYMODE} = "https";

    $config{SYSTEMMEMORY}       = getSystemMemory();
    $config{MYSQLMEMORYPERCENT} = mysqlMemoryPercent( $config{SYSTEMMEMORY} );
    $config{MAILBOXDMEMORY}     = mailboxdMemoryMB( $config{SYSTEMMEMORY} );

    $config{CREATEADMINPASS} = $config{LDAPROOTPASS};

    if ( !$options{c} && $newinstall ) {
        progress "no config file and bootstrap mode is newinstall, checking DNS resolution\n" if $options{d};
        if ( lookupHostName( $config{HOSTNAME}, 'A' ) ) {
            if ( lookupHostName( $config{HOSTNAME}, 'AAAA' ) ) {
                progress("\n\nDNS ERROR - resolving $config{HOSTNAME}\n");
                progress("It is suggested that the hostname be resolvable via DNS and the resolved IP address does not point to any loopback device.\n");
                if ( askYN( "Change hostname", "Yes" ) eq "yes" ) {
                    setHostName();
                }
            }
        }

        my $good = 0;

        if ( $config{DOCREATEDOMAIN} eq "yes" ) {

            my $ans = getDnsRecords( $config{CREATEDOMAIN}, 'MX' );
            if ( !defined($ans) ) {
                progress("\n\nDNS ERROR - resolving \"MX\" for $config{CREATEDOMAIN}\n");
                progress("It is suggested that the domain name have an \"MX\" record configured in DNS.\n");
                if ( askYN( "Change domain name?", "Yes" ) eq "yes" ) {
                    setCreateDomain();
                }
            }
            elsif ( isEnabled("carbonio-mta") ) {
                $good = validateMxRecords( $config{CREATEDOMAIN}, $ans, \@interfaces );
                if ( !$good ) {
                    progress("\n\nDNS ERROR - none of the \"MX\" records for $config{CREATEDOMAIN}\n");
                    progress("resolve to this host.\n");
                    if ( askYN( "Change domain name?", "Yes" ) eq "yes" ) {
                        setCreateDomain();
                    }
                }
            }
        }

    }
    if ( isInstalled("carbonio-proxy") ) {
        progress "setting defaults for carbonio-proxy.\n" if $options{d};
        $config{STRICTSERVERNAMEENABLED} = "TRUE";
        $config{IMAPPROXYPORT}           = 143;
        $config{IMAPSSLPROXYPORT}        = 993;
        $config{POPPROXYPORT}            = 110;
        $config{POPSSLPROXYPORT}         = 995;
        $config{IMAPPORT}                = 7143;
        $config{IMAPSSLPORT}             = 7993;
        $config{POPPORT}                 = 7110;
        $config{POPSSLPORT}              = 7995;
        $config{MAILPROXY}               = "TRUE";
        $config{HTTPPROXY}               = "TRUE";
        $config{HTTPPROXYPORT}           = 8080;
        $config{HTTPSPROXYPORT}          = 8443;
        $config{HTTPPORT}                = 80;
        $config{HTTPSPORT}               = 443;
    }
    else {
        $config{IMAPPROXYPORT}    = 7143;
        $config{IMAPSSLPROXYPORT} = 7993;
        $config{POPPROXYPORT}     = 7110;
        $config{POPSSLPROXYPORT}  = 7995;
        $config{HTTPPROXYPORT}    = 8080;
        $config{HTTPSPROXYPORT}   = 8443;
    }

    # set default value for zimbraPublicServiceHostname
    $config{PUBLICSERVICEHOSTNAME} = $config{HOSTNAME};
    if ( $config{PUBLICSERVICEHOSTNAME} eq "" ) {
        $config{PUBLICSERVICEHOSTNAME} = "UNSET";
    }

    if ( $options{d} ) {
        dumpConfig();
    }

    progress("done.\n");
}

sub getInstallStatus {
    progress "getting install status..." if $options{d};

    if ( open H, "/opt/zextras/.install_history" ) {

        my @history = <H>;
        close H;
        foreach my $h (@history) {
            if ( $h =~ /CONFIG SESSION COMPLETE/ ) {
                next;
            }
            if ( $h =~ /CONFIG SESSION START/ ) {
                %configStatus = ();
                next;
            }
            if ( $h =~ /INSTALL SESSION COMPLETE/ ) {
                next;
            }
            if ( $h =~ /INSTALL SESSION START/ ) {
                %installStatus = ();
                %configStatus  = ();
                next;
            }

            my ( $d, $op, $stage ) = split ' ', $h;
            if ( $stage eq "carbonio-core" && $op eq "INSTALLED" ) {
                $installStatus{$stage}{op}   = $op;
                $installStatus{$stage}{date} = $d;
            }
            elsif ( $op eq "CONFIGURED" ) {
                $configStatus{$stage} = $op;
            }
        }

        if (   ( $installStatus{"carbonio-core"}{op} eq "INSTALLED" )
            && ( $configStatus{"END"} ne "CONFIGURED" ) )
        {
            $newinstall = 1;
        }
        else {
            $newinstall = 0;
        }
    }
    else {
        $newinstall = 1;
    }
}

sub setDefaultsFromLocalConfig {
    progress("Setting defaults from existing config...");
    $config{HOSTNAME} = getLocalConfig("zimbra_server_hostname");
    $config{HOSTNAME} = lc( $config{HOSTNAME} );
    my $ldapUrl = getLocalConfig("ldap_master_url");
    my $ld      = ( split ' ', $ldapUrl )[0];
    my $p       = $ld;
    $p =~ s/ldaps?:\/\///;
    $p =~ s/.*:?//;

    if ( $p ne "" ) {
        $config{LDAPPORT} = $p;
    }
    else {
        $p = getLocalConfig("ldap_port");
        if ( $p ne "" ) {
            $config{LDAPPORT} = $p;
        }
    }
    my $h = $ld;
    chomp($h);
    $h =~ s/"//g;
    $h =~ s/ldaps?:\/\///g;
    $h =~ s/:\d+//g;
    if ( $h ne "" ) {
        $config{LDAPHOST} = $h;
    }
    else {
        $h = getLocalConfig("ldap_host");
        if ( $h ne "" ) {
            $config{LDAPHOST} = $h;
        }
    }
    $config{ldap_url}       = getLocalConfig("ldap_url");
    $config{LDAPROOTPASS}   = getLocalConfig("ldap_root_password");
    $config{LDAPADMINPASS}  = getLocalConfig("zimbra_ldap_password");
    $config{SQLROOTPASS}    = getLocalConfig("mysql_root_password");
    $config{ZIMBRASQLPASS}  = getLocalConfig("zimbra_mysql_password");
    $config{MAILBOXDMEMORY} = getLocalConfig("mailboxd_java_heap_size");

    $config{mailboxd_directory} = getLocalConfig("mailboxd_directory");

    # Only override config if local config value is non-empty
    for my $key (qw(mailboxd_keystore mailboxd_keystore_password mailboxd_truststore_password zimbra_ldap_userdn)) {
        my $val = getLocalConfig($key);
        $config{$key} = $val if $val ne "";
    }

    $config{zimbra_require_interprocess_security} = getLocalConfig("zimbra_require_interprocess_security");
    if ( $config{zimbra_require_interprocess_security} ) {
        $config{ZIMBRA_REQ_SECURITY} = "yes";
    }
    else {
        $config{ZIMBRA_REQ_SECURITY} = "no";
    }

    $config{ldap_dit_base_dn_config} = getLocalConfig("ldap_dit_base_dn_config");
    $config{ldap_dit_base_dn_config} = "cn=zimbra"
        if ( $config{ldap_dit_base_dn_config} eq "" );

    $config{SMTPSOURCE} = getLocalConfig("smtp_source");
    $config{SMTPSOURCE} = $config{CREATEADMIN}
      if ( $config{SMTPSOURCE} eq "" );

    $config{SMTPDEST} = getLocalConfig("smtp_destination");
    $config{SMTPDEST} = $config{CREATEADMIN}
      if ( $config{SMTPDEST} eq "" );

    $config{AVUSER} = getLocalConfig("av_notify_user");
    $config{AVUSER} = $config{CREATEADMIN}
      if ( $config{AVUSER} eq "" );

    $config{AVDOMAIN} = getLocalConfig("av_notify_domain");
    $config{AVDOMAIN} = $config{CREATEDOMAIN}
      if ( $config{AVDOMAIN} eq "" );

    if ( isEnabled("carbonio-mta") ) {
        $config{postfix_mail_owner} = getLocalConfig("postfix_mail_owner");
        if ( $config{postfix_mail_owner} eq "" ) {
            $config{postfix_mail_owner} = "postfix";
        }
        $config{postfix_setgid_group} = getLocalConfig("postfix_setgid_group");
        if ( $config{postfix_setgid_group} eq "" ) {
            $config{postfix_setgid_group} = "postdrop";
        }

    }

    if ( isEnabled("carbonio-directory-server") ) {
        $config{LDAPREPPASS} = getLocalConfig("ldap_replication_password");
        if ( $config{LDAPREPPASS} eq "" ) {
            $config{LDAPREPPASS} = $config{LDAPADMINPASS};
            $ldapRepChanged = 1;
        }
    }
    if ( isEnabled("carbonio-directory-server") || isEnabled("carbonio-mta") ) {
        $config{LDAPPOSTPASS} = getLocalConfig("ldap_postfix_password");
        if ( $config{LDAPPOSTPASS} eq "" ) {
            $config{LDAPPOSTPASS} = $config{LDAPADMINPASS};
            $ldapPostChanged = 1;
        }
        $config{LDAPAMAVISPASS} = getLocalConfig("ldap_amavis_password");
        if ( $config{LDAPAMAVISPASS} eq "" ) {
            $config{LDAPAMAVISPASS} = $config{LDAPADMINPASS};
            $ldapAmavisChanged = 1;
        }
    }
    if ( isEnabled("carbonio-directory-server") || isEnabled("carbonio-proxy") ) {
        $config{ldap_nginx_password} = getLocalConfig("ldap_nginx_password");
        if ( $config{ldap_nginx_password} eq "" ) {
            $config{ldap_nginx_password} = $config{LDAPADMINPASS};
            $ldapNginxChanged = 1;
        }
    }

    # we want these two entries to have the default configuration values
    if ( isEnabled("carbonio-appserver") ) {
        $config{mailboxd_server} = "jetty"
          if ( $config{mailboxd_server} eq "" );
        $config{mailboxd_keystore} = "$config{mailboxd_directory}/etc/keystore"
          if ( $config{mailboxd_keystore} eq "" || $config{mailboxd_keystore} == "/opt/zextras/conf/keystore" );
    }

    if ( $options{d} ) {
        foreach my $key ( sort keys %config ) {
            print "\tlc DEBUG: $key=$config{$key}\n";
        }
    }
    progress("done.\n");
}




# Helper to log command execution while suppressing sensitive data
sub logRunCommand {
    my ( $cmd, $user ) = @_;
    my $logCmd = ( $cmd =~ /ldappass|init|zmprov -r -m -l ca/ ) ? ( split ' ', $cmd )[0] : $cmd;
    detail("*** Running as $user user: $logCmd\n");
}

sub runAsRoot {
    my $cmd = shift;
    logRunCommand( $cmd, "root" );
    return 0xffff & system("$cmd >> $logfile 2>&1");
}

sub runAsZextras {
    my $cmd = shift;
    logRunCommand( $cmd, "zextras" );
    return 0xffff & system("$SU \"$cmd\" >> $logfile 2>&1");
}

sub runAsZextrasWithOutput {
    my $cmd = shift;
    logRunCommand( $cmd, "zextras" );
    system("$SU \"$cmd\"");
    my $exit_value = $? >> 8;
    detail("DEBUG: Exit status from command was $exit_value.") if $debug;
    return $exit_value;
}

sub getLocalConfig {
    my ( $key, $force, $raw ) = @_;

    return $main::loaded{lc}{$key}
      if ( exists $main::loaded{lc}{$key} && !$force );

    detail("Getting local config $key...");
    my $expand = $raw ? "" : "-x";
    my $val = qx(/opt/zextras/bin/zmlocalconfig $expand -s -m nokey ${key} 2> /dev/null);
    chomp $val;
    detail("DEBUG: Local config loaded $key=$val.") if $debug;
    $main::loaded{lc}{$key} = $val;
    return $val;
}

sub getLocalConfigRaw {
    my ( $key, $force ) = @_;
    return getLocalConfig( $key, $force, 1 );
}

sub deleteLocalConfig {
    my $key = shift;

    detail("Deleting local config $key...");
    my $rc = runAsZextras("/opt/zextras/bin/zmlocalconfig -u ${key} 2> /dev/null");
    if ( $rc == 0 ) {
        detail("DEBUG: Deleted local config key $key.") if $debug;
        delete( $main::loaded{lc}{$key} )             if ( exists $main::loaded{lc}{$key} );
        return 1;
    }
    else {
        detail("DEBUG: Failed to delete local config key $key.") if $debug;
        return undef;
    }
}

sub setLocalConfig {
    my $key = shift;
    my $val = shift;

    if ( exists $main::saved{lc}{$key} && $main::saved{lc}{$key} eq $val ) {
        detail("Skipping update of unchanged value for $key=$val.");
        return;
    }
    detail("Setting local config $key to $val.");
    $main::saved{lc}{$key}  = $val;
    $main::loaded{lc}{$key} = $val;
    $val =~ s/\$/\\\$/g;
    runAsZextras("/opt/zextras/bin/zmlocalconfig -f -e ${key}=\'${val}\' 2> /dev/null");
}

# Batch version of setLocalConfig - sets multiple values in a single call
# Usage: setLocalConfigBatch( key1 => val1, key2 => val2, ... )
sub setLocalConfigBatch {
    my %configs = @_;
    my @args;

    foreach my $key ( keys %configs ) {
        my $val = $configs{$key};
        next unless defined $val;

        if ( exists $main::saved{lc}{$key} && $main::saved{lc}{$key} eq $val ) {
            detail("Skipping update of unchanged value for $key=$val.");
            next;
        }
        detail("Setting local config $key to $val.");
        $main::saved{lc}{$key}  = $val;
        $main::loaded{lc}{$key} = $val;
        $val =~ s/\$/\\\$/g;
        push @args, "${key}=\'${val}\'";
    }

    if (@args) {
        runAsZextras( "/opt/zextras/bin/zmlocalconfig -f -e " . join( " ", @args ) . " 2> /dev/null" );
    }
}

sub configLCValues {

    # we want these two entries to have the default configuration values
    # rather than being loaded from previous installs.
    if ( isEnabled("carbonio-appserver") ) {
        setLocalConfigBatch(
            mailboxd_keystore => $config{mailboxd_keystore},
            mailboxd_server   => $config{mailboxd_server}
        );
    }

    if ( $configStatus{configLCValues} eq "CONFIGURED" ) {
        configLog("configLCValues");
        return 0;
    }

    progress("Setting local config values...");

    # Compute LDAP URL values
    my ( $ldap_master_url, $ldap_url, $ldap_starttls );
    if ($newinstall) {
        my $proto = ( $config{LDAPPORT} == 636 ) ? "ldaps" : "ldap";
        $ldap_master_url = "$proto://$config{LDAPHOST}:$config{LDAPPORT}";
        $ldap_url = ( $config{ldap_url} ne "" ) ? $config{ldap_url} : $ldap_master_url;
        $ldap_starttls = ( $proto eq "ldaps" || $ldap_url =~ /^ldaps/i || !$config{zimbra_require_interprocess_security} ) ? 0 : 1;
    }

    # Get uid/gid once
    my $uid = qx(id -u zextras);
    chomp $uid;
    my $gid = qx(id -g zextras);
    chomp $gid;

    # Batch all config values in one call
    my %lc_values = (
        zimbra_server_hostname               => lc( $config{HOSTNAME} ),
        zimbra_require_interprocess_security => $config{zimbra_require_interprocess_security},
        zimbra_zmprov_default_to_ldap        => ( isEnabled("carbonio-appserver") && isStoreServiceNode() ) ? "false" : "true",
        ldap_port                            => $config{LDAPPORT},
        ldap_host                            => $config{LDAPHOST},
        zimbra_uid                           => $uid,
        zimbra_gid                           => $gid,
        zimbra_user                          => "zextras",
        ssl_default_digest                   => $config{ssl_default_digest},
        mailboxd_java_heap_size              => $config{MAILBOXDMEMORY},
        mailboxd_directory                   => $config{mailboxd_directory},
        mailboxd_keystore                    => $config{mailboxd_keystore},
        mailboxd_server                      => $config{mailboxd_server},
        mailboxd_truststore                  => $config{mailboxd_truststore},
        mailboxd_truststore_password         => $config{mailboxd_truststore_password},
        mailboxd_keystore_password           => $config{mailboxd_keystore_password},
        zimbra_ldap_userdn                   => $config{zimbra_ldap_userdn},
    );

    # Add LDAP URL values for new installs
    if ($newinstall) {
        $lc_values{ldap_master_url}           = $ldap_master_url;
        $lc_values{ldap_url}                  = $ldap_url;
        $lc_values{ldap_starttls_supported}   = $ldap_starttls;
        $lc_values{ssl_allow_untrusted_certs} = "true";
        $lc_values{ssl_allow_mismatched_certs} = "true";
    }

    # Add optional values
    $lc_values{av_notify_user}       = $config{AVUSER}   if defined $config{AVUSER};
    $lc_values{av_notify_domain}     = $config{AVDOMAIN} if defined $config{AVDOMAIN};
    $lc_values{ldap_dit_base_dn_config} = $config{ldap_dit_base_dn_config}
        if $config{ldap_dit_base_dn_config} ne "cn=zimbra";

    setLocalConfigBatch(%lc_values);

    configLog("configLCValues");
    progress("done.\n");
}



sub isStoreServiceNode {
    if ( $installedWebapps{"service"} eq "Enabled" ) {
        return 1;
    }
    else {
        return 0;
    }
}

sub isZCS {
    return ( ( grep( /\b\w+-appserver\b/, @packageList ) ) ? 1 : 0 );
}



sub configInitSql {

    if ( $configStatus{configInitSql} eq "CONFIGURED" ) {
        configLog("configInitSql");
        return 0;
    }

    if ( !$sqlConfigured && isEnabled("carbonio-appserver") ) {
        progress("Initializing store sql database...");
        runAsRoot("/opt/zextras/libexec/zmmyinit --mysql_memory_percent $config{MYSQLMEMORYPERCENT}");
        progress("done.\n");
        configLog("configInitSql");
    }
}

sub configInitCore {

    if ( $configStatus{configInitCore} eq "CONFIGURED" ) {
        configLog("configInitCore");
        return 0;
    }
    configLog("configInitCore");
}

sub configInitMta {

    if ( $configStatus{configInitMta} eq "CONFIGURED" ) {
        configLog("configInitMta");
        return 0;
    }

    if ( isEnabled("carbonio-mta") ) {
        progress("Initializing MTA config...");

        setLocalConfigBatch(
            postfix_mail_owner   => $config{postfix_mail_owner},
            postfix_setgid_group => $config{postfix_setgid_group}
        );

        runAsZextras("/opt/zextras/libexec/zmmtainit $config{LDAPHOST} $config{LDAPPORT}");
        progress("done.\n");
        if ( isZCS() ) {
            push( @installedServiceList, ( 'zimbraServiceInstalled', 'amavis' ) );
            push( @installedServiceList, ( 'zimbraServiceInstalled', 'antivirus' ) );
            push( @installedServiceList, ( 'zimbraServiceInstalled', 'antispam' ) );
            push( @installedServiceList, ( 'zimbraServiceInstalled', 'opendkim' ) );
            push( @enabledServiceList,   ( 'zimbraServiceEnabled',   'amavis' ) );
            if ( $config{RUNAV} eq "yes" ) {
                push( @enabledServiceList, ( 'zimbraServiceEnabled', 'antivirus' ) );
            }
            if ( $config{RUNSA} eq "yes" ) {
                push( @enabledServiceList, ( 'zimbraServiceEnabled', 'antispam' ) );
            }
            if ( $config{RUNDKIM} eq "yes" ) {
                push( @enabledServiceList, ( 'zimbraServiceEnabled', 'opendkim' ) );
            }
            if ( $config{RUNCBPOLICYD} eq "yes" ) {
                push( @enabledServiceList, ( 'zimbraServiceEnabled', 'cbpolicyd' ) );
            }
        }
        setLdapServerConfig( "zimbraMtaMyNetworks", $config{zimbraMtaMyNetworks} )
          if ( $config{zimbraMtaMyNetworks} ne "" );

        configLog("configInitMta");
    }
}



sub failConfig {
    progress("\n\nERROR\n\n");
    progress("\n\nConfiguration failed\n\n");
    progress("Please address the error and re-run carbonio-bootstrap to\n");
    progress("complete the configuration.\n");
    progress("\nErrors have been logged to $logfile\n\n");
    exit 1;
}

sub applyConfig {
    defineInstallWebapps();
    saveConfig();

    if ($newinstall) {
        open( H, ">>/opt/zextras/.install_history" );
        print H time(), ": CONFIG SESSION START\n";

        # This is the postinstall config
        configLog("BEGIN");
    }

    # On split store node setups, the unused webapps need to be removed before
    # applying any other configuration in order to ensure the installedWebapps
    # variables are properly setup for later steps.
    if ( isEnabled("carbonio-appserver") ) {
        removeUnusedWebapps();
    }

    configLCValues();

    configInitCore();

    # About SSL
    #
    # On the master ldap server, create a ca and a cert
    # On store and MTA servers, just create a cert.
    #
    # Non-ldap masters use the master CA, which they get from ldap
    # but ldap won't start without a cert.
    #
    # so - ldap - create CA, create cert, init ldap, store CA in ldap
    #
    # non-ldap - fetch CA, create cert

    configCASetup();

    configCreateCert();

    configInstallCert();

    if ($ldapReplica) {
        configCreateServerEntry();
    }

    configSetupLdap();

    if ( !$ldapReplica ) {
        configCreateServerEntry();
    }

    configSaveCA();

    configSaveCert();

    # Generating dhparam key
    if ($newinstall) {
        progress("Generating dhparam key...");
        my $rc = runAsZextras("/opt/zextras/common/bin/openssl dhparam -out /opt/zextras/conf/dhparam.pem.crb 2048 > /dev/null 2>&1");
        if ( $rc != 0 ) {
            progress("\nfailed to generate dhparam key");
            progress("\nCarbonio bootstrap process exited because one of the subprocesses failed.\n");
            exit();
        }
        else {
            # Added the following for bug 103803. Could not just add the cert as a globalConfigValue
            # for zimbraSSldHParam.  See bug 104244.
            setLdapGlobalConfig( "zimbraSSLDHParam", "/opt/zextras/conf/dhparam.pem.crb" );
            progress("done.\n");
        }
    }

    if ( isEnabled("carbonio-appserver") ) {

        configSetServicePorts();

        configSetKeyboardShortcutsPref() if ( !$newinstall );

        configSetStoreDefaults();
    }

    configLDAPSchemaVersion();

    if ( isEnabled("carbonio-directory-server") ) {
        configSetTimeZonePref();
        setLdapGlobalConfig( "zimbraSkinLogoURL", "https://www.zextras.com" );
    }

    # if ($newinstall && isInstalled("carbonio-proxy")) {
    #     configSetProxyPrefs();
    # }

    if ( isInstalled("carbonio-proxy") ) {
        configSetProxyPrefs();
    }

    if ( ( !$newinstall ) && isInstalled("carbonio-directory-server") ) {
        setProxyBits();
    }

    configInitMta();

    configSetEnabledServices();

    if ( isEnabled("carbonio-appserver") ) {
        if ( isStoreServiceNode() ) {
            addServerToHostPool();
        }
    }

    if ( isEnabled("carbonio-mta") && $main::newinstall ) {
        my @mtalist = getAllServers("mta");
        if ( scalar(@mtalist) gt 1 ) {
            setLocalConfig( "zmtrainsa_cleanup_host", "false" );
        }
        else {
            setLocalConfig( "zmtrainsa_cleanup_host", "true" );
        }
    }

    configCreateDomain();

    configInitSql();

    configInitGALSyncAccts();

    setupSyslog();

    if ( $newinstall != 1 ) {
        startLdap() if ($ldapConfigured);
    }

    if ( $newinstall != 1 ) {
        if ( ( isInstalled("carbonio-proxy") && isEnabled("carbonio-proxy") ) && ( $config{HTTPPROXY} eq "TRUE" ) ) {
            setLdapServerConfig( $config{HOSTNAME}, 'zimbraMailProxyPort',    $config{HTTPPROXYPORT} );
            setLdapServerConfig( $config{HOSTNAME}, 'zimbraMailSSLProxyPort', $config{HTTPSPROXYPORT} );
        }
    }

    if ( $config{STARTSERVERS} eq "yes" ) {
        if ( isEnabled("carbonio-appserver") ) {
            qx(chown zextras:zextras /opt/zextras/redolog/redo.log)
              if ( ( $platform =~ m/ubuntu/ ) && !$newinstall );
        }
        progress("Starting servers...\n");
        if ( isSystemd() ) {
            stopAllSystemdTargets();
            startAllSystemdTargets();
        }
        else {
            runAsZextras("/opt/zextras/bin/zmcontrol stop");
            runAsZextras("/opt/zextras/bin/zmcontrol start");
            qx($SU "/opt/zextras/bin/zmcontrol status");
        }
        progress("done.\n");

        # Initialize application server specific items
        # only after the application server is running.
        if ( $newinstall && isStoreServiceNode() ) {
            configCreateDefaultDomainGALSyncAcct();
        }
        else {
            if ($newinstall) {
                progress("Skipping creation of default domain GAL sync account - not a service node.\n");
            }
            else {
                progress("Skipping creation of default domain GAL sync account - existing install detected.\n");
            }
        }
    }
    else {
        progress("WARNING: galsync account creation for default domain skipped because Application Server was not configured to start.\n")
          if ( isEnabled("carbonio-appserver") );
    }

    setupCrontab();

    if ($newinstall) {
        runAsZextras("/opt/zextras/bin/zmsshkeygen");
        runAsZextras("/opt/zextras/bin/zmupdateauthkeys");
    }
    else {
        runAsZextras("/opt/zextras/bin/zmupdateauthkeys");
    }

    configLog("END");

    print H time(), ": CONFIG SESSION COMPLETE\n";

    close H;

    getSystemStatus();

    progress("\n\n");
    moveLogToZextras();
    progress("\n\n");
    if ( !defined( $options{c} ) ) {
        ask( "Configuration complete - press return to exit", "" );
        print "\n\n";
        close LOGFILE;
        exit 0;
    }
}

sub configLog {
    my $stage = shift;
    my $msg   = time() . ": CONFIGURED $stage\n";
    print H $msg;

    #progress ($msg);
}

sub setupSyslog {
    progress("Setting up syslog.conf...");
    if ( -f "/opt/zextras/libexec/zmsyslogsetup" ) {
        my $rc = runAsRoot("/opt/zextras/libexec/zmsyslogsetup");
        if ($rc) {
            progress("Failed\n");
        }
        else {
            progress("done.\n");
        }
    }
    else {
        progress("Failed\n");
    }
    configLog("setupSyslog");
}

sub setupCrontab {
    progress("Setting up zextras crontab...");
    detail("Crontab: Taking a copy of zextras user crontab file.");
    qx(crontab -u zextras -l > /tmp/crontab.zextras.orig 2> /dev/null);
    detail("Crontab: Looking for ZEXTRAS-START in existing crontab entry.");
    my $rc = 0xffff & system("grep ZEXTRAS-START /tmp/crontab.zextras.orig > /dev/null 2>&1");
    if ($rc) {
        detail("Crontab: ZEXTRAS-START not found, starting fresh.");
        qx(cp -f /dev/null /tmp/crontab.zextras.orig 2>> $logfile);
    }
    detail("Crontab: Looking for ZEXTRAS-END in existing crontab entry.");
    $rc = 0xffff & system("grep ZEXTRAS-END /tmp/crontab.zextras.orig > /dev/null 2>&1");
    if ($rc) {
        detail("Crontab: ZEXTRAS-END not found, starting fresh.");
        qx(cp -f /dev/null /tmp/crontab.zextras.orig);
    }
    qx(cat /tmp/crontab.zextras.orig | sed -e '/# ZEXTRAS-START/,/# ZEXTRAS-END/d' > /tmp/crontab.zextras.proc);
    detail("Crontab: Adding carbonio-core specific entries.");
    qx(cp -f /opt/zextras/conf/crontabs/crontab /tmp/crontab.zextras);

    if ( isEnabled("carbonio-directory-server") ) {
        detail("Crontab: Adding carbonio-directory-server specific entries.");
        qx(cat /opt/zextras/conf/crontabs/crontab.ldap >> /tmp/crontab.zextras 2>> $logfile);
    }

    if ( isEnabled("carbonio-appserver") ) {
        detail("Crontab: Adding carbonio-appserver specific entries.");
        qx(cat /opt/zextras/conf/crontabs/crontab.store >> /tmp/crontab.zextras 2>> $logfile);
    }

    if ( isEnabled("carbonio-mta") ) {
        detail("Crontab: Adding carbonio-mta specific entries.");
        qx(cat /opt/zextras/conf/crontabs/crontab.mta >> /tmp/crontab.zextras 2>> $logfile);
    }

    qx(echo "# ZEXTRAS-END -- DO NOT EDIT ANYTHING BETWEEN THIS LINE AND ZEXTRAS-START" >> /tmp/crontab.zextras);
    qx(cat /tmp/crontab.zextras.proc >> /tmp/crontab.zextras);
    detail("Crontab: Installing new crontab.");
    qx(crontab -u zextras /tmp/crontab.zextras 2> /dev/null);
    progress("done.\n");
    configLog("setupCrontab");
}

sub getSystemMemory {
    my $os = lc qx(uname -s);
    chomp($os);
    return "unknown" unless $os;
    my $mem;
    if ( $os eq "linux" ) {
        $mem = qx(cat /proc/meminfo | grep ^MemTotal: | awk '{print \$2}');
        chomp($mem);
        $mem = sprintf "%0.1f", $mem / ( 1024 * 1024 );
    }
    elsif ( $os eq "darwin" ) {
        $mem = qx(sysctl hw.memsize | awk '{print \$NF}');
        chomp($mem);
        $mem = sprintf "%0.1f", $mem / ( 1024 * 1024 * 1024 );
    }
    return $mem;
}

sub mysqlMemoryPercent {
    my $system_mem = shift;
    my $os         = lc qx(uname -s);
    chomp($os);
    my $percent = 30;
    return $percent;
}

sub mailboxdMemoryMB {
    my $system_mem = shift;
    my $memory;
    if ( $system_mem > 16 ) {
        $memory = 0.2 * $system_mem;
    }
    else {
        $memory = 0.25 * $system_mem;
    }
    return int( $memory * 1024 );
}


sub resumeConfiguration {
    progress("\n\nNote\n\n");
    progress("The previous configuration appears to have failed to complete\n\n");
    if ( askYN( "Attempt to complete configuration now?", "yes" ) eq "yes" ) {
        applyConfig();
    }
    else {
        %configStatus = ();
    }
}

### end subs

__END__
