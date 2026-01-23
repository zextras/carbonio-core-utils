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
select($ol);
$| = 1;

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
use Net::DNS::Resolver;
use NetAddr::IP;

our %options = ();
our %config  = ();
our %loaded  = ();
our %saved   = ();

my @packageList = (
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

my $serviceWebApp = "service";

my %installedPackages = ();
our %installedWebapps = ();
my %prevInstalledPackages = ();
my %prevEnabledServices   = ();
my %enabledPackages       = ();
my %enabledServices       = ();

my %installStatus = ();
our %configStatus = ();

our $newinstall = 1;
chomp(
    my $ldapSchemaVersion = do {
        local $/ = undef;
        open my $fh, "<", "/opt/zextras/conf/attrs-schema"
          or die "could not open /opt/zextras/conf/attrs-schema: $!";
        <$fh>;
    }
);

my $ldapConfigured           = 0;
my $haveSetLdapSchemaVersion = 0;
my $ldapRunning              = 0;
my $sqlConfigured            = 0;
my $sqlRunning               = 0;
my @installedServiceList     = ();
my @enabledServiceList       = ();

my $ldapRootPassChanged                   = 0;
my $ldapAdminPassChanged                  = 0;
my $ldapRepChanged                        = 0;
my $ldapPostChanged                       = 0;
my $ldapAmavisChanged                     = 0;
my $ldapNginxChanged                      = 0;
my $ldapReplica                           = 0;
my $starttls                              = 0;
my $needNewCert                           = "";
my $ssl_cert_type                         = "self";
my $publicServiceHostnameAlreadySet = 0;

my @ssl_digests = ( "ripemd160", "sha", "sha1", "sha224", "sha256", "sha384", "sha512" );
my @interfaces  = ();

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
    open( LOG, ">>$logfile" );
    print LOG "$date $msg\n";
    close(LOG);
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

# Helper function to set LDAP passwords - consolidates repeated pattern
# $name: display name (e.g., "replication", "Postfix")
# $flag: zmldappasswd flag (e.g., "-l", "-p", "-a", "-n")
# $configKey: config hash key for the password
# $localConfigKey: localconfig key for remote LDAP case
# $quotePassword: whether to quote the password (for post-LDAP-init calls)
sub setLdapPasswordHelper {
    my ( $name, $flag, $configKey, $localConfigKey, $quotePassword ) = @_;
    progress("Setting $name password...");
    if ( $config{LDAPHOST} eq $config{HOSTNAME} ) {
        my $pass = $quotePassword ? "'$config{$configKey}'" : $config{$configKey};
        runAsZextras("/opt/zextras/bin/zmldappasswd $flag $pass");
    }
    else {
        setLocalConfig( $localConfigKey, "$config{$configKey}" );
    }
    progress("done.\n");
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

# Helper to ask for LDAP password - consolidates 6 nearly identical functions
sub askLdapPasswordHelper {
    my ( $prompt, $configKey, $changedFlagRef, $checkLdapAvailable ) = @_;
    while (1) {
        my $new = askPassword( "Password for $prompt (min 6 characters):", $config{$configKey} );
        if ( length($new) >= 6 ) {
            if ( $config{$configKey} ne $new ) {
                $config{$configKey} = $new;
                $$changedFlagRef = 1;
            }
            ldapIsAvailable() if ( $checkLdapAvailable && $config{HOSTNAME} ne $config{LDAPHOST} );
            return;
        }
        print "Minimum length of 6 characters!\n";
    }
}

# Helper to set proxy port - consolidates 6 nearly identical functions
sub setProxyPortHelper {
    my ( $prompt, $proxyKey, $backendKey, $proxyTypeKey ) = @_;
    $config{$proxyKey} = askNum( "Please enter the $prompt:", $config{$proxyKey} );
    if ( $config{$proxyTypeKey} eq "TRUE" || $config{zimbraMailProxy} eq "TRUE" ) {
        $config{$backendKey} = "UNSET" if ( $config{$proxyKey} == $config{$backendKey} );
    }
}

# Helper to resolve port collision for a port/proxy pair
# When proxyEnabled: port gets alternate at standard, proxy gets standard at alternate
# When !proxyEnabled: proxy gets alternate at standard, port gets standard at alternate
sub resolvePortPairCollision {
    my ( $portKey, $proxyKey, $standardVal, $alternateVal, $proxyEnabled ) = @_;
    return unless $config{$portKey} == $config{$proxyKey};
    if ( $config{$portKey} == $standardVal ) {
        if ($proxyEnabled) { $config{$portKey} = $alternateVal; }
        else               { $config{$proxyKey} = $alternateVal; }
    }
    elsif ( $config{$portKey} == $alternateVal ) {
        if ($proxyEnabled) { $config{$proxyKey} = $standardVal; }
        else               { $config{$portKey} = $standardVal; }
    }
}

# Helper to resolve port collision using offset-based logic for setUseProxy
# When proxyEnabled=1: if ports equal, add offset to port; if port+offset==proxy, swap with subtract
# When proxyEnabled=0: if proxy+offset==port, swap with add
sub resolvePortOffsetCollision {
    my ( $portKey, $proxyKey, $offset, $proxyEnabled ) = @_;
    if ($proxyEnabled) {
        if ( $config{$proxyKey} == $config{$portKey} ) {
            $config{$portKey} = $offset + $config{$proxyKey};
        }
        if ( $config{$portKey} + $offset == $config{$proxyKey} ) {
            $config{$portKey}  = $config{$proxyKey};
            $config{$proxyKey} = $config{$proxyKey} - $offset;
        }
    }
    else {
        if ( $config{$proxyKey} + $offset == $config{$portKey} ) {
            $config{$portKey}  = $config{$proxyKey};
            $config{$proxyKey} = $config{$proxyKey} + $offset;
        }
    }
}

# Helper to resolve all mail port pair collisions (IMAP, IMAPSSL, POP, POPSSL)
sub resolveMailPortPairCollisions {
    my ($proxyEnabled) = @_;
    resolvePortPairCollision( 'IMAPPORT',    'IMAPPROXYPORT',    143, 7143, $proxyEnabled );
    resolvePortPairCollision( 'IMAPSSLPORT', 'IMAPSSLPROXYPORT', 993, 7993, $proxyEnabled );
    resolvePortPairCollision( 'POPPORT',     'POPPROXYPORT',     110, 7110, $proxyEnabled );
    resolvePortPairCollision( 'POPSSLPORT',  'POPSSLPROXYPORT',  995, 7995, $proxyEnabled );
}

# Helper to resolve HTTP port pair collisions
sub resolveHttpPortPairCollisions {
    my ($proxyEnabled) = @_;
    resolvePortPairCollision( 'HTTPPORT',  'HTTPPROXYPORT',  80,  8080, $proxyEnabled );
    resolvePortPairCollision( 'HTTPSPORT', 'HTTPSPROXYPORT', 443, 8443, $proxyEnabled );
}

# Helper to resolve all mail port offset collisions (IMAP, IMAPSSL, POP, POPSSL)
sub resolveMailPortOffsetCollisions {
    my ($proxyEnabled) = @_;
    resolvePortOffsetCollision( 'IMAPPORT',    'IMAPPROXYPORT',    7000, $proxyEnabled );
    resolvePortOffsetCollision( 'IMAPSSLPORT', 'IMAPSSLPROXYPORT', 7000, $proxyEnabled );
    resolvePortOffsetCollision( 'POPPORT',     'POPPROXYPORT',     7000, $proxyEnabled );
    resolvePortOffsetCollision( 'POPSSLPORT',  'POPSSLPROXYPORT',  7000, $proxyEnabled );
}

# Helper to resolve HTTP port offset collisions
sub resolveHttpPortOffsetCollisions {
    my ($proxyEnabled) = @_;
    resolvePortOffsetCollision( 'HTTPPORT',  'HTTPPROXYPORT',  8000, $proxyEnabled );
    resolvePortOffsetCollision( 'HTTPSPORT', 'HTTPSPROXYPORT', 8000, $proxyEnabled );
}

# Helper to update password display status for menu (UNSET, set, or Not Verified)
sub updatePasswordDisplayStatus {
    my ( $passKey, $passSetKey ) = @_;
    if ( $config{$passKey} eq "" ) {
        $config{$passSetKey} = "UNSET";
    }
    else {
        $config{$passSetKey} = "set" unless ( $config{$passSetKey} eq "Not Verified" );
    }
}

# Helper to add a menu item - reduces boilerplate
sub addMenuItem {
    my ( $lm, $i_ref, $prompt, $varKey, $callback, $arg ) = @_;
    $$lm{menuitems}{$$i_ref} = {
        "prompt"   => $prompt,
        "var"      => \$config{$varKey},
        "callback" => $callback,
    };
    $$lm{menuitems}{$$i_ref}{"arg"} = $arg if defined $arg;
    $$i_ref++;
}

# Helper to ask for domain-validated user account - consolidates 4 nearly identical functions
sub askDomainUserHelper {
    my ( $prompt, $configKey ) = @_;
    while (1) {
        my $new = ask( $prompt, $config{$configKey} );
        my ( $u, $d ) = split( '@', $new );
        my ( $adminUser, $adminDomain ) = split( '@', $config{CREATEADMIN} );
        if ( $d ne $config{CREATEDOMAIN} && $d ne $adminDomain ) {
            if ( $config{CREATEDOMAIN} eq $adminDomain ) {
                progress("You must create the user under the domain $config{CREATEDOMAIN}\n");
            }
            else {
                progress("You must create the user under the domain $config{CREATEDOMAIN} or $adminDomain\n");
            }
        }
        else {
            $config{$configKey} = $new;
            last;
        }
    }
}

# Helper to update email address domain - used when domain changes
sub updateEmailDomain {
    my ( $configKey, $newDomain, $oldDomain ) = @_;
    my ( $user, $domain ) = split( '@', $config{$configKey} );
    return if !defined $oldDomain;    # unconditional update
    return if $domain ne $oldDomain;  # conditional: only if old domain matches
    $config{$configKey} = $user . '@' . $newDomain;
}

# Helper to unconditionally update email domain
sub setEmailDomain {
    my ( $configKey, $newDomain ) = @_;
    my ( $user, $domain ) = split( '@', $config{$configKey} );
    $config{$configKey} = $user . '@' . $newDomain;
}

# Helper to get LDAP values - consolidates 6 nearly identical functions
sub getLdapValueHelper {
    my ( $attrib, $sub, $sec, $cmd, $detailType ) = @_;
    my ( $val, $err );
    if ( exists $main::loaded{$sec}{$sub}{$attrib} ) {
        $val = $main::loaded{$sec}{$sub}{$attrib};
        detail("Returning cached $detailType config attribute for $sub: $attrib=$val.");
        return $val;
    }
    my ( $rfh, $wfh, $efh, $rc );
    $rfh = new FileHandle;
    $wfh = new FileHandle;
    $efh = new FileHandle;
    my $pid = open3( $wfh, $rfh, $efh, $cmd );
    unless ( defined($pid) ) {
        return undef;
    }
    close $wfh;
    my @d = <$rfh>;
    while ( scalar(@d) > 0 ) {
        chomp( my $line = shift(@d) );
        my ( $k, $v ) = $line =~ m/^(\w+):\s(.*)/;
        while ( $d[0] !~ m/^\w+:\s.*/ && scalar(@d) > 0 ) {
            chomp( $v .= shift(@d) );
        }
        if ( !$main::loaded{$sec}{$sub}{zmsetuploaded} || ( $main::loaded{$sec}{$sub}{zmsetuploaded} && $k eq $attrib ) ) {
            if ( exists $main::loaded{$sec}{$sub}{$k} ) {
                $main::loaded{$sec}{$sub}{$k} = "$main::loaded{$sec}{$sub}{$k}\n$v";
            }
            else {
                $main::loaded{$sec}{$sub}{$k} = "$v";
            }
        }
    }
    chomp( $err = join "", <$efh> );
    detail("$err") if ( length($err) > 0 );
    waitpid( $pid, 0 );
    if ( $? == -1 ) {
        close $rfh;
        close $efh;
        return undef;
    }
    elsif ( $? & 127 ) {
        close $rfh;
        close $efh;
        return undef;
    }
    else {
        $rc = $? >> 8;
        close $rfh;
        close $efh;
        return undef if ( $rc != 0 );
    }
    close $rfh;
    close $efh;
    $main::loaded{$sec}{$sub}{zmsetuploaded} = 1;
    $val = $main::loaded{$sec}{$sub}{$attrib};
    detail("Returning retrieved $detailType config attribute for $sub: $attrib=$val.");
    return $val;
}

# Helper to set LDAP config values - consolidates 5 nearly identical functions
sub setLdapConfigHelper {
    my ( $sec, $entity, $zmprovCmd, $detailType, @args ) = @_;
    my $zmprov_arg_str;
    while (@args) {
        my $key = shift @args;
        my $val = shift @args;
        if ( ifKeyValueEquate( $sec, $key, $val, $entity ) ) {
            detail("Skipping update of unchanged value for $key=$val.");
        }
        else {
            detail("Updating cached config attribute for $detailType $entity: $key=$val.");
            updateKeyValue( $sec, $key, $val, $entity );
            $zmprov_arg_str .= " $key \'$val\'";
        }
    }
    if ($zmprov_arg_str) {
        return runAsZextras("$zmprovCmd $zmprov_arg_str");
    }
}

# Helper to create a system account if it doesn't exist
sub createSystemAccountIfMissing {
    my ( $configKey, $description, $extraAttrs ) = @_;
    $extraAttrs //= "";
    $config{$configKey} = lc( $config{$configKey} );
    progress("Creating user $config{$configKey}...");
    my $acctId = getLdapAccountValue( "zimbraId", $config{$configKey} );
    if ( $acctId ne "" ) {
        progress("already exists.\n");
        return 0;
    }
    my $pass = genRandomPass();
    my $rc   = runAsZextras(
        "$ZMPROV ca $config{$configKey} \'$pass\' "
          . "amavisBypassSpamChecks TRUE zimbraAttachmentsIndexingEnabled FALSE "
          . "zimbraIsSystemResource TRUE zimbraIsSystemAccount TRUE zimbraHideInGal TRUE "
          . "zimbraMailQuota 0 $extraAttrs description \'$description\'"
    );
    progress( ( $rc == 0 ) ? "done.\n" : "failed.\n" );
    return $rc;
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
        progress("Can't open $fname: $!\n");
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

    # get list of previously installed packages on upgrade
    if ( $newinstall != 1 ) {
        $config{zimbra_server_hostname} = getLocalConfig("zimbra_server_hostname")
          if ( $config{zimbra_server_hostname} eq "" );
        detail("DEBUG: zimbra_server_hostname=$config{zimbra_server_hostname}")
          if $options{d};

        $config{ldap_url} = getLocalConfig("ldap_url")
          if ( $config{ldap_url} eq "" );
        detail("DEBUG: ldap_url=$config{ldap_url}")
          if $options{d};

        if ( index( $config{ldap_url}, "/" . $config{zimbra_server_hostname} ) != -1 ) {
            detail("Server hostname found in ldap_url, checking LDAP status...");
            if ( startLdap() ) { return 1; }
        }
        else {
            detail("Server hostname not in ldap_url, not starting slapd.");
        }
        detail("Getting installed services from LDAP...");
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
            else {
                detail("DEBUG: skipping not zimbraServiceInstalled =>  $_") if $debug;
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

    # lookup service in ldap
    if ( $newinstall == 0 ) {
        $config{zimbra_server_hostname} = getLocalConfig("zimbra_server_hostname")
          if ( $config{zimbra_server_hostname} eq "" );
        detail("DEBUG: zimbra_server_hostname=$config{zimbra_server_hostname}")
          if $options{d};

        $config{ldap_url} = getLocalConfig("ldap_url")
          if ( $config{ldap_url} eq "" );
        detail("DEBUG: ldap_url=$config{ldap_url}")
          if $options{d};

        if ( index( $config{ldap_url}, "/" . $config{zimbra_server_hostname} ) != -1 ) {
            detail("Server hostname found in ldap_url, checking LDAP status...");
            if ( startLdap() ) { return 1; }
        }
        else {
            detail("Server hostname not in ldap_url, not starting slapd.");
        }
        detail("Getting enabled services from LDAP...");
        $enabledPackages{"carbonio-core"} = "Enabled"
          if ( isInstalled("carbonio-core") );

        open( ZMPROV, "$ZMPROV gs $config{zimbra_server_hostname}|" );
        while (<ZMPROV>) {
            chomp;
            if (/zimbraServiceEnabled:\s(.*)/) {
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
                detail("DEBUG: skipping not zimbraServiceEnabled => $_") if $debug;
            }
        }
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
        close(ZMPROV);
    }
    else {
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

sub isInstalled {
    my $pkg = shift;

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
    if ( ( $platform =~ /ubuntu/ ) && $rc == 0 ) {
        $good     = 1;
        $pkgQuery = "dpkg -s $pkg | egrep '^Status: ' | grep 'not-installed'";
        $rc       = 0xffff & system("$pkgQuery > /dev/null 2>&1");
        $rc >>= 8;
        return ( $rc == $good );
    }
    else {
        return ( $rc == $good );
    }
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
    my $rc;
    if ( isEnabled("carbonio-directory-server") ) {
        if ( -f "/opt/zextras/data/ldap/mdb/db/data.mdb" ) {
            $ldapConfigured = 1;
            if ( isSystemd() ) {
                $rc = isSystemdActiveUnit("carbonio-openldap.service");
            }
            else {
                $rc = 0xffff & system("/opt/zextras/bin/ldap status > /dev/null 2>&1");
            }
            if ($rc) {
                $ldapRunning = 0;
            }
            else {
                $ldapRunning = 1;
            }
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

sub getAllServers {
    my ($service) = @_;
    my @servers;
    detail("Running $ZMPROV gas $service...");
    open( ZMPROV, "$ZMPROV gas $service 2>/dev/null|" );
    chomp( @servers = <ZMPROV> );
    close(ZMPROV);

    return @servers;
}

sub getLdapAccountValue($$) {
    my ( $attrib, $sub ) = @_;
    return getLdapValueHelper( $attrib, $sub, "acct", "$ZMPROV ga $sub", "account" );
}

sub getLdapCOSValue {
    my ( $attrib, $sub ) = @_;
    $sub = "default" if ( $sub eq "" );
    return getLdapValueHelper( $attrib, $sub, "gc", "$ZMPROV gc $sub", "cos" );
}

sub getLdapConfigValue {
    my $attrib = shift;
    return getLdapValueHelper( $attrib, "gcf", "gcf", "$ZMPROV gacf", "global" );
}

sub getLdapDomainValue {
    my ( $attrib, $sub ) = @_;
    $sub = $config{zimbraDefaultDomainName} if ( $sub eq "" );
    return undef if ( $sub eq "" );
    return getLdapValueHelper( $attrib, $sub, "domain", "$ZMPROV gd $sub", "domain" );
}

sub getLdapServerValue {
    my ( $attrib, $sub ) = @_;
    $sub = $main::config{HOSTNAME} if ( $sub eq "" );
    return getLdapValueHelper( $attrib, $sub, "gs", "$ZMPROV gs $sub", "server" );
}

sub getRealLdapServerValue {
    my ( $attrib, $sub ) = @_;
    $sub = $main::config{HOSTNAME} if ( $sub eq "" );
    return getLdapValueHelper( $attrib, $sub, "gsreal", "$ZMPROV gs -e $sub", "server" );
}

sub setLdapDefaults {

    return if exists $config{LDAPDEFAULTSLOADED};
    progress("Setting defaults from LDAP...");

    #
    # Load server specific attributes only if server exists
    #
    my $serverid = getLdapServerValue("zimbraId");
    if ( $serverid ne "" ) {

        # Load server attributes in bulk using data-driven mapping
        my %ldapServerAttribs = (
            'zimbraIPMode'                 => 'zimbraIPMode',
            'IMAPPORT'                     => 'zimbraImapBindPort',
            'IMAPSSLPORT'                  => 'zimbraImapSSLBindPort',
            'REMOTEIMAPBINDPORT'           => 'zimbraRemoteImapBindPort',
            'REMOTEIMAPSSLBINDPORT'        => 'zimbraRemoteImapSSLBindPort',
            'POPPORT'                      => 'zimbraPop3BindPort',
            'POPSSLPORT'                   => 'zimbraPop3SSLBindPort',
            'IMAPPROXYPORT'                => 'zimbraImapProxyBindPort',
            'IMAPSSLPROXYPORT'             => 'zimbraImapSSLProxyBindPort',
            'POPPROXYPORT'                 => 'zimbraPop3ProxyBindPort',
            'POPSSLPROXYPORT'              => 'zimbraPop3SSLProxyBindPort',
            'MAILPROXY'                    => 'zimbraReverseProxyMailEnabled',
            'MODE'                         => 'zimbraMailMode',
            'PROXYMODE'                    => 'zimbraReverseProxyMailMode',
            'HTTPPORT'                     => 'zimbraMailPort',
            'HTTPSPORT'                    => 'zimbraMailSSLPort',
            'HTTPPROXYPORT'                => 'zimbraMailProxyPort',
            'HTTPSPROXYPORT'               => 'zimbraMailSSLProxyPort',
            'HTTPPROXY'                    => 'zimbraReverseProxyHttpEnabled',
            'SMTPHOST'                     => 'zimbraSmtpHostname',
        );
        for my $key ( keys %ldapServerAttribs ) {
            $config{$key} = getLdapServerValue( $ldapServerAttribs{$key} );
        }

        $config{zimbraReverseProxyLookupTarget} = getLdapServerValue("zimbraReverseProxyLookupTarget")
          if ( $config{zimbraReverseProxyLookupTarget} eq "" );

        if ( isEnabled("carbonio-mta") ) {
            my $tmpval = getLdapServerValue("zimbraMtaMyNetworks");
            $config{zimbraMtaMyNetworks} = $tmpval
              unless ( $tmpval eq "" );
        }
    }

    #
    # Load Global config values
    #
    # default domain name
    # get zimbraPublicServiceHostname from ldap
    my $publicServiceHostnameLdap = getLdapConfigValue("zimbraPublicServiceHostname");

    # if zimbraPublicServiceHostname is already set on ldap...
    if ( !( $publicServiceHostnameLdap eq "" ) ) {

        # ...use the ldap value
        $config{PUBLICSERVICEHOSTNAME} = $publicServiceHostnameLdap;

        # set the flag to avoid overwriting zimbraPublicServiceHostname on ldap
        $publicServiceHostnameAlreadySet = 1;
    }

    $config{zimbraDefaultDomainName} = getLdapConfigValue("zimbraDefaultDomainName");
    if ( $config{zimbraDefaultDomainName} eq "" ) {
        $config{zimbraDefaultDomainName} = $config{CREATEDOMAIN};
    }
    else {
        $config{CREATEDOMAIN} = $config{zimbraDefaultDomainName};
        $config{CREATEADMIN}  = "zextras\@$config{CREATEDOMAIN}";
    }

    if ( $config{SMTPHOST} eq "" ) {
        my $smtphost = getLdapConfigValue("zimbraSmtpHostname");
        $smtphost =~ s/\n/ /g;
        $config{SMTPHOST} = $smtphost if ( $smtphost ne "localhost" );
    }

    $config{TRAINSASPAM} = getLdapConfigValue("zimbraSpamIsSpamAccount");
    if ( $config{TRAINSASPAM} eq "" ) {
        $config{TRAINSASPAM} = "spam." . lc( genRandomPass() ) . '@' . $config{CREATEDOMAIN};
    }
    $config{TRAINSAHAM} = getLdapConfigValue("zimbraSpamIsNotSpamAccount");
    if ( $config{TRAINSAHAM} eq "" ) {
        $config{TRAINSAHAM} = "ham." . lc( genRandomPass() ) . '@' . $config{CREATEDOMAIN};
    }
    $config{VIRUSQUARANTINE} = getLdapConfigValue("zimbraAmavisQuarantineAccount");
    if ( $config{VIRUSQUARANTINE} eq "" ) {
        $config{VIRUSQUARANTINE} = "virus-quarantine." . lc( genRandomPass() ) . '@' . $config{CREATEDOMAIN};
    }

    #
    # Load default COS
    #
    $config{USEKBSHORTCUTS}       = getLdapCOSValue("zimbraPrefUseKeyboardShortcuts");
    $config{zimbraPrefTimeZoneId} = getLdapCOSValue("zimbraPrefTimeZoneId");

    #
    # Load default domain values
    #
    my $galacct = getLdapDomainValue("zimbraGalAccountId");
    $config{ENABLEGALSYNCACCOUNTS} = ( ( $galacct eq "" ) ? "no" : "yes" );

    #
    # Set some sane defaults if values were missing in LDAP
    #
    $config{HTTPPORT}              = 80      if ( $config{HTTPPORT} eq 0 );
    $config{HTTPSPORT}             = 443     if ( $config{HTTPSPORT} eq 0 );
    $config{MODE}                  = "https" if ( $config{MODE} eq "" );
    $config{PROXYMODE}             = "https" if ( $config{PROXYMODE} eq "" );
    $config{REMOTEIMAPBINDPORT}    = 8143    if ( $config{REMOTEIMAPBINDPORT} eq 0 );
    $config{REMOTEIMAPSSLBINDPORT} = 8993    if ( $config{REMOTEIMAPSSLBINDPORT} eq 0 );

    if ( isInstalled("carbonio-proxy") && isEnabled("carbonio-proxy") ) {
        resolveMailPortPairCollisions(1) if ( $config{MAILPROXY} eq "TRUE" );
        if ( $config{HTTPPROXY} eq "TRUE" ) {
            # Add proxy component to a configured node
            $config{HTTPPROXYPORT}  = 80  if ( ( $config{HTTPPORT} == 80 || $config{HTTPPORT} == 0 ) && $config{HTTPPROXYPORT} == 0 );
            $config{HTTPSPROXYPORT} = 443 if ( ( $config{HTTPSPORT} == 443 || $config{HTTPSPORT} == 0 ) && $config{HTTPSPROXYPORT} == 0 );
            resolveHttpPortPairCollisions(1);
        }
    }
    else {
        resolveMailPortPairCollisions(0);
        resolveHttpPortPairCollisions(0);
    }

    #
    # debug output
    #
    if ( $options{d} ) {
        dumpConfig();
    }
    $config{LDAPDEFAULTSLOADED} = 1;
    progress("done.\n");
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

                my @answer = $ans->answer;
                foreach my $a (@answer) {
                    if ( $a->type eq "MX" ) {
                        my $h    = getDnsRecords( $a->exchange, 'A' );
                        my $ipv6 = 0;
                        if ( !defined $h ) {
                            $h    = getDnsRecords( $a->exchange, 'AAAA' );
                            $ipv6 = 1;
                        }
                        if ( defined $h ) {
                            my @ha = $h->answer;
                            foreach $h (@ha) {
                                if ($ipv6) {
                                    if ( $h->type eq 'AAAA' ) {
                                        progress "\tMX: " . $a->exchange . " (" . $h->address . ")\n";
                                    }
                                }
                                else {
                                    if ( $h->type eq 'A' ) {
                                        progress "\tMX: " . $a->exchange . " (" . $h->address . ")\n";
                                    }
                                }
                            }
                        }
                        else {
                            progress "\n\nDNS ERROR - No \"A\" or \"AAAA\" record for $config{CREATEDOMAIN}.\n";
                        }
                    }
                }
                progress "\n";
                foreach my $i (@interfaces) {
                    progress "\tInterface: $i\n";
                }
                foreach my $a (@answer) {
                    foreach my $i (@interfaces) {
                        if ( $a->type eq "MX" ) {
                            my $h = getDnsRecords( $a->exchange, 'A' );
                            if ( !defined $h ) {
                                $h = getDnsRecords( $a->exchange, 'AAAA' );
                            }
                            if ( defined $h ) {
                                my @ha = $h->answer;
                                foreach $h (@ha) {
                                    my $interIp   = NetAddr::IP->new("$i");
                                    my $interface = lc( $interIp->addr );
                                    if ( $h->type eq 'A' || $h->type eq 'AAAA' ) {
                                        print "\t\t" . $h->address . "\n";
                                        if ( $h->address eq $interface ) {
                                            $good = 1;
                                            last;
                                        }
                                    }
                                }
                                if ($good) { last; }
                            }
                        }
                    }
                    if ($good) { last; }
                }
                if ( !$good ) {
                    progress("\n\nDNS ERROR - none of the \"MX\" records for $config{CREATEDOMAIN}\n");
                    progress("resolve to this host\n");
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
    $config{PUBLICSERVICEHOSTNAME} = lc(qx(hostname --fqdn));
    chomp $config{PUBLICSERVICEHOSTNAME};
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

    # do not set empty mailboxd_keystore
    $config{mailboxd_keystore} = getLocalConfig("mailboxd_keystore")
      if ( getLocalConfig("mailboxd_keystore") ne "" );

    $config{mailboxd_keystore_password} = getLocalConfig("mailboxd_keystore_password")
      if ( getLocalConfig("mailboxd_keystore_password") ne "" );

    $config{mailboxd_truststore_password} = getLocalConfig("mailboxd_truststore_password")
      if ( getLocalConfig("mailboxd_truststore_password") ne "" );

    $config{zimbra_ldap_userdn} = getLocalConfig("zimbra_ldap_userdn")
      if ( getLocalConfig("zimbra_ldap_userdn") ne "" );

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

sub ask {
    my $prompt  = shift;
    my $default = shift;
    if ( $default eq "" ) {
        print "$prompt ";
    }
    else {
        print "$prompt [$default] ";
    }
    my $rc = <>;
    chomp $rc;
    if ( $rc eq "" ) { return $default; }
    return $rc;
}

sub askPassword {
    my $prompt  = shift;
    my $default = shift;
    while (1) {
        my $v = ask( $prompt, $default );

        # although they are valid pass characters avoid $ and |
        # here because they cause quoting problems.
        if ( $v =~ /\$|\\/g ) {
            print "Invalid metacharater used.\n";
            next;
        }
        if ( $v ne "" ) { return $v; }
        print "A non-blank answer is required\n";
    }
}

sub askYN {
    my $prompt  = shift;
    my $default = shift;
    while (1) {
        my $v = ask( $prompt, $default );
        $v = lc($v);
        $v = substr( $v, 0, 1 );
        if ( $v eq "y" ) { return "yes"; }
        if ( $v eq "n" ) { return "no"; }
        print "A Yes/No answer is required\n";
    }
}

sub askTF {
    my $prompt  = shift;
    my $default = shift;
    while (1) {
        my $v = ask( $prompt, $default );
        $v = lc($v);
        $v = substr( $v, 0, 1 );
        if ( $v eq "t" ) { return "TRUE"; }
        if ( $v eq "f" ) { return "FALSE"; }
        print "A True/False answer is required\n";
    }
}

sub askNum {
    my $prompt  = shift;
    my $default = shift;
    while (1) {
        my $v = ask( $prompt, $default );
        my $i = int($v);
        if ( $v eq $i ) { return $v; }
        print "A numeric response is required!\n";
    }
}

sub askPositiveInt {
    my $prompt  = shift;
    my $default = shift;
    while (1) {
        my $v = ask( $prompt, $default );
        my $i = int($v);
        if ( $v eq $i && $v > 0 ) { return $v; }
        print "A positive integer response is required!\n";
    }
}

sub askNonBlank {
    my $prompt  = shift;
    my $default = shift;
    while (1) {
        my $v = ask( $prompt, $default );
        if ( $v ne "" ) { return $v; }
        print "A non-blank answer is required\n";
    }
}

sub askFileName {
    my $prompt  = shift;
    my $default = shift;
    while (1) {
        my $v = ask( $prompt, $default );
        if ( $v ne "" && -f $v ) { return $v; }
        print "A non-blank answer is required\n" if ( $v eq "" );
        print "$v must exist and be readable\n"  if ( !-f $v && $v ne "" );
    }
}

sub setCreateDomain {
    my $oldDomain = $config{CREATEDOMAIN};
    my $good      = 0;
    while (1) {
        $config{CREATEDOMAIN} = ask( "Create domain:", $config{CREATEDOMAIN} );
        my $ans = getDnsRecords( $config{CREATEDOMAIN}, 'MX' );
        if ( !defined($ans) ) {
            progress("\n\nDNS ERROR - resolving \"MX\" for $config{CREATEDOMAIN}\n");
            progress("It is suggested that the domain name have an \"MX\" record configured in DNS.\n");
            if ( askYN( "Re-Enter domain name?", "Yes" ) eq "no" ) {
                last;
            }
            $config{CREATEDOMAIN} = $oldDomain;
            next;
        }
        elsif ( isEnabled("carbonio-mta") ) {
            my @answer = $ans->answer;
            foreach my $a (@answer) {
                if ( $a->type eq "MX" ) {
                    my $h    = getDnsRecords( $a->exchange, 'A' );
                    my $ipv6 = 0;
                    if ( !defined $h ) {
                        $h    = getDnsRecords( $a->exchange, 'AAAA' );
                        $ipv6 = 1;
                    }
                    if ( defined $h ) {
                        my @ha = $h->answer;
                        foreach $h (@ha) {
                            if ($ipv6) {
                                if ( $h->type eq 'AAAA' ) {
                                    progress "\tMX: " . $a->exchange . " (" . $h->address . ")\n";
                                }
                            }
                            else {
                                if ( $h->type eq 'A' ) {
                                    progress "\tMX: " . $a->exchange . " (" . $h->address . ")\n";
                                }
                            }
                        }
                    }
                    else {
                        progress "\n\nDNS ERROR - No \"A\" or \"AAAA\" record for $config{CREATEDOMAIN}.\n";
                    }
                }
            }
            progress "\n";
            foreach my $i (@interfaces) {
                progress "\tInterface: $i\n";
            }
            foreach my $a (@answer) {
                foreach my $i (@interfaces) {
                    if ( $a->type eq "MX" ) {
                        my $h = getDnsRecords( $a->exchange, 'A' );
                        if ( !defined $h ) {
                            $h = getDnsRecords( $a->exchange, 'AAAA' );
                        }
                        if ( defined $h ) {
                            my @ha = $h->answer;
                            foreach $h (@ha) {
                                my $interIp   = NetAddr::IP->new("$i");
                                my $interface = lc( $interIp->addr );
                                if ( $h->type eq 'A' || $h->type eq 'AAAA' ) {
                                    if ( $h->address eq $interface ) {
                                        $good = 1;
                                        last;
                                    }
                                }
                            }
                        }
                        if ($good) { last; }
                    }
                }
                if ($good) { last; }
            }
            if ($good) { last; }
            else {
                progress("\n\nDNS ERROR - none of the \"MX\" records for $config{CREATEDOMAIN}\n");
                progress("resolve to this host\n");
                progress("It is suggested that the \"MX\" record resolve to this host.\n");
                if ( askYN( "Re-Enter domain name?", "Yes" ) eq "no" ) {
                    last;
                }
                $config{CREATEDOMAIN} = $oldDomain;
                next;
            }
        }
        last;
    }
    my $oldAdmin = $config{CREATEADMIN};
    setEmailDomain( 'CREATEADMIN', $config{CREATEDOMAIN} );

    $config{AVUSER}   = $config{CREATEADMIN} if ( $oldAdmin eq $config{AVUSER} );
    $config{AVDOMAIN} = $config{CREATEDOMAIN} if ( $config{AVDOMAIN} eq $oldDomain );
    $config{SMTPDEST}   = $config{CREATEADMIN} if ( $oldAdmin eq $config{SMTPDEST} );
    $config{SMTPSOURCE} = $config{CREATEADMIN} if ( $oldAdmin eq $config{SMTPSOURCE} );

    updateEmailDomain( 'TRAINSASPAM',     $config{CREATEDOMAIN}, $oldDomain );
    updateEmailDomain( 'TRAINSAHAM',      $config{CREATEDOMAIN}, $oldDomain );
    updateEmailDomain( 'VIRUSQUARANTINE', $config{CREATEDOMAIN}, $oldDomain );
}

sub setLdapBaseDN {
    while (1) {
        print "Warning: Do not change this from the default value unless\n";
        print "you are absolutely sure you know what you are doing!\n\n";
        my $new = askNonBlank( "Ldap base DN:", $config{ldap_dit_base_dn_config} );
        if ( $config{ldap_dit_base_dn_config} ne $new ) {
            $config{ldap_dit_base_dn_config} = $new;
        }
        return;
    }
}

sub setNotebookAccount {
    askDomainUserHelper( "Global Documents account:", "NOTEBOOKACCOUNT" );
}

sub setTrainSASpam {
    askDomainUserHelper( "Spam training user:", "TRAINSASPAM" );
}

sub setTrainSAHam {
    askDomainUserHelper( "Ham training user:", "TRAINSAHAM" );
}

sub setAmavisVirusQuarantine {
    askDomainUserHelper( "Anti-virus quarantine user:", "VIRUSQUARANTINE" );
}

sub setCreateAdmin {

    while (1) {
        my $new = ask( "Create admin user:", $config{CREATEADMIN} );
        my ( $u, $d ) = split( '@', $new );

        unless ( validEmailAddress($new) ) {
            progress("Admin user must be a valid email account [$u\@$config{CREATEDOMAIN}]\n");
            next;
        }

        # spam/ham/quanrantine accounts follow admin domain if ldap isn't install
        # this prevents us from trying to provision in a non-existent domain
        if ( !isEnabled("carbonio-directory-server") ) {
            my ( $spamUser,  $spamDomain )  = split( '@', $config{TRAINSASPAM} );
            my ( $hamUser,   $hamDomain )   = split( '@', $config{TRAINSAHAM} );
            my ( $virusUser, $virusDomain ) = split( '@', $config{VIRUSQUARANTINE} );
            $config{CREATEDOMAIN} = $d
              if ( $config{CREATEDOMAIN} ne $d );

            $config{TRAINSASPAM} = $spamUser . '@' . $d
              if ( $spamDomain ne $d );

            $config{TRAINSAHAM} = $hamUser . '@' . $d
              if ( $hamDomain ne $d );

            $config{VIRUSQUARANTINE} = $virusUser . '@' . $d
              if ( $virusDomain ne $d );

            $config{AVDOMAIN} = $d
              if ( $config{AVDOMAIN} ne $d );
        }

        if ( $config{CREATEADMIN} eq $config{AVUSER} ) {
            $config{AVUSER} = $new;
        }
        if ( $config{CREATEADMIN} eq $config{SMTPDEST} ) {
            $config{SMTPDEST} = $new;
        }
        if ( $config{CREATEADMIN} eq $config{SMTPSOURCE} ) {
            $config{SMTPSOURCE} = $new;
        }
        $config{CREATEADMIN} = $new;
        last;
    }
}

sub removeUnusedWebapps {
    defineInstallWebapps();
}

sub validEmailAddress {
    return ( $_[0] =~ m/^[^@]+@([-\w]+\.)+[A-Za-z]{2,4}/ ? 1 : 0 );
}

sub validIPAddress {
    my $rc = 0;
    foreach my $ip (@_) {
        chomp($ip);
        my $testip = NetAddr::IP->new($ip);
        if ( ref($testip) ne 'NetAddr::IP' ) {
            $rc = 1;
        }
    }
    return $rc;
}

sub setLdapRootPass {
    askLdapPasswordHelper( "ldap root user", "LDAPROOTPASS", \$ldapRootPassChanged, 0 );
}

sub setLdapAdminPass {
    askLdapPasswordHelper( "ldap admin user", "LDAPADMINPASS", \$ldapAdminPassChanged, 1 );
}

sub setLdapRepPass {
    askLdapPasswordHelper( "ldap replication user", "LDAPREPPASS", \$ldapRepChanged, 1 );
}

sub setLdapPostPass {
    askLdapPasswordHelper( "ldap Postfix user", "LDAPPOSTPASS", \$ldapPostChanged, 1 );
}

sub setLdapAmavisPass {
    askLdapPasswordHelper( "ldap Amavis user", "LDAPAMAVISPASS", \$ldapAmavisChanged, 1 );
}

sub setLdapNginxPass {
    askLdapPasswordHelper( "ldap Nginx user", "ldap_nginx_password", \$ldapNginxChanged, 1 );
}

sub setSmtpSource {
    $config{SMTPSOURCE} = askNonBlank( "SMTP Source address:", $config{SMTPSOURCE} );
}

sub setSmtpDest {
    $config{SMTPDEST} = askNonBlank( "SMTP Destination address:", $config{SMTPDEST} );
}

sub setAvUser {
    $config{AVUSER} = askNonBlank( "Notification address for AV alerts:", $config{AVUSER} );
    ( undef, $config{AVDOMAIN} ) = ( split( '@', $config{AVUSER} ) )[1];
}

sub toggleYN {
    my $key = shift;
    $config{$key} = ( $config{$key} eq "yes" ) ? "no" : "yes";
}

sub toggleTF {
    my $key = shift;
    $config{$key} = ( $config{$key} eq "TRUE" ) ? "FALSE" : "TRUE";
    if ( $key eq "MAILPROXY" ) {
        &toggleMailProxy();
    }
    if ( $key eq "HTTPPROXY" ) {
        &toggleWebProxy();
    }
}

sub toggleConfigEnabled {
    my $key = shift;
    $config{$key} = ( $config{$key} eq "Enabled" ) ? "Disabled" : "Enabled";
}

sub toggleMailProxy() {
    if ( $config{MAILPROXY} eq "TRUE" ) {
        $config{IMAPPORT}         = 7143;
        $config{IMAPSSLPORT}      = 7993;
        $config{POPPORT}          = 7110;
        $config{POPSSLPORT}       = 7995;
        $config{IMAPPROXYPORT}    = 143;
        $config{IMAPSSLPROXYPORT} = 993;
        $config{POPPROXYPORT}     = 110;
        $config{POPSSLPROXYPORT}  = 995;
    }
    else {
        $config{IMAPPORT}         = 143;
        $config{IMAPSSLPORT}      = 993;
        $config{POPPORT}          = 110;
        $config{POPSSLPORT}       = 995;
        $config{IMAPPROXYPORT}    = 7143;
        $config{IMAPSSLPROXYPORT} = 7993;
        $config{POPPROXYPORT}     = 7110;
        $config{POPSSLPROXYPORT}  = 7995;
    }
}

sub toggleWebProxy() {
    if ( $config{HTTPPROXY} eq "TRUE" ) {
        $config{HTTPPORT}       = 8080;
        $config{HTTPSPORT}      = 8443;
        $config{HTTPPROXYPORT}  = 80;
        $config{HTTPSPROXYPORT} = 443;
    }
    else {
        $config{HTTPPORT}       = 80;
        $config{HTTPSPORT}      = 443;
        $config{HTTPPROXYPORT}  = 8080;
        $config{HTTPSPROXYPORT} = 8443;
    }
}

sub setUseProxy {
    if ( isEnabled("carbonio-proxy") ) {
        my $mailProxyEnabled = ( $config{MAILPROXY} eq "TRUE" );
        my $httpProxyEnabled = ( $config{HTTPPROXY} eq "TRUE" );
        resolveMailPortOffsetCollisions($mailProxyEnabled);
        resolveHttpPortOffsetCollisions($httpProxyEnabled);
    }
    else {
        if ( !isInstalled("carbonio-appserver") ) {
            resolveMailPortOffsetCollisions(0);
            resolveHttpPortOffsetCollisions(0);
        }
        else {
            my $mailProxyEnabled = ( $config{zimbraMailProxy} eq "TRUE" );
            my $httpProxyEnabled = ( $config{zimbraWebProxy} eq "TRUE" );
            resolveMailPortOffsetCollisions($mailProxyEnabled);
            resolveHttpPortOffsetCollisions($httpProxyEnabled);
        }
    }
}

sub setStoreMode {
    while (1) {
        my $m = askNonBlank( "Please enter the web server mode (http,https,both,mixed,redirect)", $config{MODE} );
        if ( isInstalled("carbonio-proxy") ) {
            if ( $config{zimbra_require_interprocess_security} ) {
                if ( $m eq "https" || $m eq "both" ) {
                    $config{MODE} = $m;
                    return;
                }
                else {
                    print qq(Only "https" and "both" are valid modes when requiring interprocess security with web proxy.\n);
                }
            }
            else {
                if ( $m eq "http" || $m eq "both" ) {
                    $config{MODE} = $m;
                    return;
                }
                else {
                    print qq(Only "http" and "both" are valid modes when not requiring interprocess security with web proxy.\n);
                }
            }
        }
        else {
            my @proxytargets;
            open( ZMPROV, "$ZMPROV gas proxy 2>/dev/null|" );
            chomp( @proxytargets = <ZMPROV> );
            close(ZMPROV);
            if ( scalar @proxytargets ) {
                if ( $config{zimbra_require_interprocess_security} ) {
                    if ( $m eq "https" || $m eq "both" ) {
                        $config{MODE} = $m;
                        return;
                    }
                    else {
                        print qq(Only "https" and "both" are valid modes when requiring interprocess security with web proxy.\n);
                    }
                }
                else {
                    if ( $m eq "http" || $m eq "both" ) {
                        $config{MODE} = $m;
                        return;
                    }
                    else {
                        print qq(Only "http" and "both" are valid modes when not requiring interprocess security with web proxy.\n);
                    }
                }
            }
            else {
                if ( $m eq "http" || $m eq "https" || $m eq "mixed" || $m eq "both" || $m eq "redirect" ) {
                    $config{MODE} = $m;
                    return;
                }
            }
        }
        print "Please enter a valid mode!\n";
    }
}

sub setProxyMode {
    while (1) {
        my $m = askNonBlank( "Please enter the proxy server mode (https,redirect)", $config{PROXYMODE} );
        if ( $config{zimbra_require_interprocess_security} ) {
            if ( $m eq "https" || $m eq "redirect" ) {
                $config{PROXYMODE} = $m;
                return;
            }
            else {
                print qq(Only "https" and "redirect" are valid modes when requiring interprocess security with web proxy.\n);
            }
        }
        else {
            if ( $m eq "https" || $m eq "redirect" ) {
                $config{PROXYMODE} = $m;
                return;
            }
        }
        print "Please enter a valid mode!\n";
    }
}

sub changeLdapHost {
    $config{LDAPHOST} = shift;
    $config{LDAPHOST} = lc( $config{LDAPHOST} );
    if ( isInstalled("carbonio-directory-server") && $config{LDAPHOST} eq "" ) {
        $ldapReplica = 0;
        $config{LDAPREPLICATIONTYPE} = "master";
    }
    elsif ( isInstalled("carbonio-directory-server") && $config{LDAPHOST} ne $config{HOSTNAME} ) {
        $ldapReplica = 1;
        $config{LDAPREPLICATIONTYPE} = "replica";
    }
    elsif ( isInstalled("carbonio-directory-server") && $config{LDAPHOST} eq $config{HOSTNAME} ) {
        $ldapReplica = 0;
        $config{LDAPREPLICATIONTYPE} = "master";
    }
}

sub changeLdapPort {
    $config{LDAPPORT} = shift;
}

sub changeLdapServerID {
    $config{LDAPSERVERID} = shift;
}

sub changePublicServiceHostname {
    $config{PUBLICSERVICEHOSTNAME} = shift;
}

sub getDnsRecords {
    my $hostname   = shift;
    my $query_type = shift;

    progress("\n\nQuerying DNS for \"$query_type\" record of $hostname...");

    my $resolver = Net::DNS::Resolver->new;
    my $ans      = $resolver->search( $hostname, $query_type );

    return $ans;
}

sub lookupHostName {
    my $hostname   = shift;
    my $query_type = shift;

    progress("\n\nQuerying DNS for \"$query_type\" record of current hostname $hostname...");

    # perform DNS lookup for asked query_type for supplied hostname
    my $resolver = Net::DNS::Resolver->new;
    my $ans      = $resolver->search( $hostname, $query_type );
    if ( !defined $ans ) {
        progress("\n\tNo results returned for \"$query_type\" record of current hostname $hostname\n");
        progress("\nChecked nameservers:\n");
        foreach my $server ( $resolver->nameservers() ) {
            progress("\t$server\n");
        }

        # return if no record was found
        return 1;
    }

    # else check if resolved IP address is pointing to a loopback device or interface
    foreach my $rr ( $ans->answer ) {
        next unless $rr->type eq 'A';
        my $ip = $rr->address;

        # regexp based check that matches IP to check if its a possible loopback addresses (covers both IPv4 and IPv6)
        if ( $ip =~ /^127\.|^::1$/ ) {
            progress("\n\tERROR: Resolved IP address $ip for current hostname $hostname is pointing to a loopback device or interface");
            return 1;
        }

        # check if IP address belongs to a local network interface on the current host by
        # looking for "scope host" in interface detail
        my $ipo = `ip addr show $ip 2>&1`;
        if ( $? == 0 && $ipo =~ /scope host/ ) {
            progress("\n\tERROR: Resolved IP address $ip for current hostname $hostname is pointing to a loopback device or interface");
            return 1;
        }
    }

    # if everything is okay
    return 0;
}

sub setHostName {
    my $old = $config{HOSTNAME};
    while (1) {
        $config{HOSTNAME} = askNonBlank( "Please enter the logical hostname for this host", $config{HOSTNAME} );
        if ( lookupHostName( $config{HOSTNAME}, 'A' ) ) {
            progress("\n\nDNS ERROR - resolving $config{HOSTNAME}\n");
            progress("It is recommended that the hostname be resolvable via DNS and the resolved IP address not point to a loopback device\n");
            if ( askYN( "Re-Enter hostname", "Yes" ) eq "no" ) {
                last;
            }
            $config{HOSTNAME} = $old;
        }
        else { last; }
    }
    $config{HOSTNAME} = lc( $config{HOSTNAME} );
    if ( $config{SMTPHOST} eq $old ) {
        $config{SMTPHOST} = $config{HOSTNAME};
    }
    if ( $config{LDAPHOST} eq $old ) {
        changeLdapHost( $config{HOSTNAME} );
    }
    if ( $config{CREATEDOMAIN} eq $old ) {
        $config{CREATEDOMAIN} = $config{HOSTNAME};
        $config{AVDOMAIN}     = $config{CREATEDOMAIN};
        setEmailDomain( 'CREATEADMIN',     $config{CREATEDOMAIN} );
        setEmailDomain( 'AVUSER',          $config{CREATEDOMAIN} );
        setEmailDomain( 'TRAINSASPAM',     $config{CREATEDOMAIN} );
        setEmailDomain( 'TRAINSAHAM',      $config{CREATEDOMAIN} );
        setEmailDomain( 'VIRUSQUARANTINE', $config{CREATEDOMAIN} );
    }
    updateEmailDomain( 'SMTPSOURCE', $config{CREATEDOMAIN}, $old );
    updateEmailDomain( 'SMTPDEST',   $config{CREATEDOMAIN}, $old );
}

sub setSmtpHost {
    $config{SMTPHOST} = askNonBlank( "Please enter the SMTP server hostname:", $config{SMTPHOST} );
}

sub setLdapHost {
    changeLdapHost( askNonBlank( "Please enter the ldap server hostname:", $config{LDAPHOST} ) );
}

sub setLdapPort {
    changeLdapPort( askNum( "Please enter the ldap server port:", $config{LDAPPORT} ) );
}

sub setLdapServerID {
    changeLdapServerID( askPositiveInt( "Please enter the ldap Server ID:", $config{LDAPSERVERID} ) );
}

sub setLdapReplicationType {
    while (1) {
        my $m = askNonBlank( "Please enter the LDAP replication type (replica, mmr)", $config{LDAPREPLICATIONTYPE} );
        if ( $m eq "replica" || $m eq "mmr" ) {
            $config{LDAPREPLICATIONTYPE} = $m;
            return;
        }
        print "Please enter a valid replication type!\n";
    }
}

sub setImapProxyPort {
    setProxyPortHelper( "IMAP Proxy server port", "IMAPPROXYPORT", "IMAPPORT", "MAILPROXY" );
}

sub setImapSSLProxyPort {
    setProxyPortHelper( "IMAP SSL Proxy server port", "IMAPSSLPROXYPORT", "IMAPSSLPORT", "MAILPROXY" );
}

sub setPopProxyPort {
    setProxyPortHelper( "POP Proxy server port", "POPPROXYPORT", "POPPORT", "MAILPROXY" );
}

sub setPopSSLProxyPort {
    setProxyPortHelper( "POP SSL Proxy server port", "POPSSLPROXYPORT", "POPSSLPORT", "MAILPROXY" );
}

sub setPublicServiceHostname {
    my $old = $config{PUBLICSERVICEHOSTNAME};
    while (1) {
        $config{PUBLICSERVICEHOSTNAME} = askNonBlank( "Please enter the Public Service hostname (FQDN):", $config{PUBLICSERVICEHOSTNAME} );
        if ( $config{PUBLICSERVICEHOSTNAME} ne $old ) {
            $publicServiceHostnameAlreadySet = 0;
        }
        if ( lookupHostName( $config{PUBLICSERVICEHOSTNAME}, 'A' ) ) {
            progress("\n\nDNS ERROR - resolving $config{PUBLICSERVICEHOSTNAME}\n");
            progress("It is suggested that the Public Service Hostname be resolvable via DNS.\n");
            if ( askYN( "Re-Enter Public Service Hostname", "Yes" ) eq "no" ) {
                last;
            }
            $config{PUBLICSERVICEHOSTNAME} = $old;
        }
        else {
            last;
        }
    }
}

sub setHttpProxyPort {
    setProxyPortHelper( "HTTP Proxy server port", "HTTPPROXYPORT", "HTTPPORT", "HTTPPROXY" );
}

sub setHttpsProxyPort {
    setProxyPortHelper( "HTTPS Proxy server port", "HTTPSPROXYPORT", "HTTPSPORT", "HTTPPROXY" );
}

sub setTimeZone {
    my $timezones = "/opt/zextras/conf/timezones.ics";
    if ( -f $timezones ) {
        detail("Loading default list of timezones.\n");
        my $tz = new Zextras::Util::Timezone;
        $tz->parse;

        my $new;

        # build a hash of the timezone objects with a unique number as the value
        my %TZID = undef;
        my $ctr  = 1;
        $TZID{$_} = $ctr++ foreach sort $tz->dump;
        my %RTZID = reverse %TZID;

        # get a reference to the default value or attempt to lookup the system locale.
        detail("Previous TimeZoneID: $config{zimbraPrefTimeZoneId}.\n");
        my $ltzref = $tz->gettzbyid("$config{zimbraPrefTimeZoneId}");
        unless ( defined $ltzref ) {
            detail("Determining system locale.\n");
            my $localtzname = qx(/bin/date '+%Z');
            chomp($localtzname);
            detail("DEBUG: Local tz name $localtzname\n");
            $ltzref = $tz->gettzbyname($localtzname);
        }

        # look up the current value and present a list
        my $default = $TZID{ $ltzref->tzid } || "21";
        while ( $new eq "" ) {
            foreach ( sort { $TZID{$a} <=> $TZID{$b} } keys %TZID ) {
                print "$TZID{$_} $_\n";
            }
            my $ans = askNum( "Enter the number for the local timezone:", $default );
            $new = $RTZID{$ans};
        }
        $config{zimbraPrefTimeZoneId} = $new;
    }
}

sub setIPMode {
    while (1) {
        my $new = askPassword( "IP Mode (ipv4, both, ipv6):", $config{zimbraIPMode} );
        if ( $new eq "ipv4" || $new eq "both" || $new eq "ipv6" ) {
            if ( $config{zimbraIPMode} ne $new ) {
                $config{zimbraIPMode} = $new;
            }
            return;
        }
        else {
            print "IP Mode must be one of ipv4, both, or ipv6!\n";
        }
    }
}

sub setSSLDefaultDigest {
    while (1) {
        my $new         = askPassword( "Default OpenSSL digest:", $config{ssl_default_digest} );
        my $ssl_digests = join( ' ', @ssl_digests );
        if ( $ssl_digests =~ /\b$new\b/ ) {
            if ( $config{ssl_default_digest} ne $new ) {
                $config{ssl_default_digest} = $new;
            }
            return;
        }
        else {
            print "Valid digest modes are: $ssl_digests!\n";
        }
    }
}

sub setEnabledDependencies {
    if ( isEnabled("carbonio-directory-server") ) {
        if ( $config{LDAPHOST} eq "" ) {
            changeLdapHost( $config{HOSTNAME} );
        }
    }
    else {
        if ( $config{LDAPHOST} eq $config{HOSTNAME} ) {
            changeLdapHost("");
            $config{LDAPADMINPASS} = "";
            $config{LDAPROOTPASS}  = "";
        }
    }

    if ( isEnabled("carbonio-appserver") ) {
        if ( isEnabled("carbonio-mta") ) {
            $config{SMTPHOST} = $config{HOSTNAME};
        }
        if ( $config{zimbraMailProxy} eq "TRUE" || $config{zimbraWebProxy} eq "TRUE" ) {
            setUseProxy();
        }
    }

    if ( isEnabled("carbonio-mta") ) {
        if ($newinstall) {
            $config{RUNAV}        = ( isServiceEnabled("antivirus") ? "yes" : "no" );
            $config{RUNSA}        = "yes";
            $config{RUNDKIM}      = "yes";
            $config{RUNCBPOLICYD} = "no";
        }
        else {
            $config{RUNSA} = ( isServiceEnabled("antispam")  ? "yes" : "no" );
            $config{RUNAV} = ( isServiceEnabled("antivirus") ? "yes" : "no" );
            if ( $config{RUNDKIM} ne "yes" ) {
                $config{RUNDKIM} = ( isServiceEnabled("opendkim") ? "yes" : "no" );
            }
            $config{RUNCBPOLICYD} = ( isServiceEnabled("cbpolicyd") ? "yes" : "no" );
        }
    }

    if ( isEnabled("carbonio-clamav") ) {
        if ($newinstall) {
            $config{RUNAV} = "yes";
        }
        else {
            $config{RUNAV} = ( isServiceEnabled("antivirus") ? "yes" : "no" );
        }
    }

    if ( isInstalled("carbonio-proxy") ) {
        setUseProxy();
    }
}

sub toggleEnabled {
    my $p = shift;
    $enabledPackages{$p} = ( isEnabled($p) ) ? "Disabled" : "Enabled";
    setEnabledDependencies();
}

sub verifyQuit {
    if ( askYN( "Quit without applying changes?", "No" ) eq "yes" ) { return 1; }
    return 0;
}

sub genPackageMenu {
    my $package = shift;
    my %lm      = ();
    $lm{menuitems}{1} = {
        "prompt"   => "Status:",
        "var"      => \$enabledPackages{$package},
        "callback" => \&toggleEnabled,
        "arg"      => $package
    };
    $lm{promptitem} = {
        "selector" => "r",
        "prompt"   => "Select, or 'r' for previous menu ",
        "action"   => "return"
    };
    $lm{default} = "r";
    return \%lm;
}

sub genSubMenu {
    my %lm = ();
    $lm{promptitem} = {
        "selector" => "r",
        "prompt"   => "Select, or 'r' for previous menu ",
        "action"   => "return"
    };
    $lm{default} = "r";
    return \%lm;
}

sub isLdapMaster {
    return ( ( $config{LDAPHOST} eq $config{HOSTNAME} ) ? 1 : 0 );
}

sub isZCS {
    return ( ( grep( /\b\w+-appserver\b/, @packageList ) ) ? 1 : 0 );
}

sub createPackageMenu {
    my $package = shift;
    if ( $package eq "carbonio-directory-server" ) {
        return createLdapMenu($package);
    }
    elsif ( $package eq "carbonio-mta" ) {
        return createMtaMenu($package);
    }
    elsif ( $package eq "carbonio-appserver" ) {
        return createStoreMenu($package);
    }
    elsif ( $package eq "carbonio-proxy" ) {
        return createProxyMenu($package);
    }
}

sub createCommonMenu {
    my $package = shift;
    my $lm      = genSubMenu();

    $$lm{title} = "Common configuration";

    $$lm{createsub} = \&createCommonMenu;
    $$lm{createarg} = $package;

    my $i = 1;
    addMenuItem( $lm, \$i, "Hostname:",         'HOSTNAME', \&setHostName );
    addMenuItem( $lm, \$i, "Ldap master host:", 'LDAPHOST', \&setLdapHost );
    addMenuItem( $lm, \$i, "Ldap port:",        'LDAPPORT', \&setLdapPort );

    updatePasswordDisplayStatus( 'LDAPADMINPASS', 'LDAPADMINPASSSET' );
    addMenuItem( $lm, \$i, "Ldap Admin password:", 'LDAPADMINPASSSET', \&setLdapAdminPass );

    # ldap users
    if ( !defined( $installedPackages{"carbonio-directory-server"} ) ) {
        addMenuItem( $lm, \$i, "LDAP Base DN:", 'ldap_dit_base_dn_config', \&setLdapBaseDN );
    }

    # interprocess security
    addMenuItem( $lm, \$i, "Secure interprocess communications:", 'ZIMBRA_REQ_SECURITY', \&toggleYN, "ZIMBRA_REQ_SECURITY" );
    if ( $config{ZIMBRA_REQ_SECURITY} eq "yes" ) {
        $config{zimbra_require_interprocess_security} = 1;
    }
    else {
        $config{zimbra_require_interprocess_security} = 0;
        $starttls = 0;
    }
    addMenuItem( $lm, \$i, "TimeZone:",           'zimbraPrefTimeZoneId', \&setTimeZone );
    addMenuItem( $lm, \$i, "IP Mode:",            'zimbraIPMode',         \&setIPMode );
    addMenuItem( $lm, \$i, "Default SSL digest:", 'ssl_default_digest',   \&setSSLDefaultDigest );
    return $lm;
}

sub createLdapMenu {
    my $package = shift;
    my $lm      = genPackageMenu($package);

    $$lm{title} = "Ldap configuration";

    $$lm{createsub} = \&createLdapMenu;
    $$lm{createarg} = $package;

    my $i = 2;
    if ( isEnabled($package) ) {
        addMenuItem( $lm, \$i, "Create Domain:", 'DOCREATEDOMAIN', \&toggleYN, "DOCREATEDOMAIN" );
        if ( $config{DOCREATEDOMAIN} eq "yes" ) {
            addMenuItem( $lm, \$i, "Domain to create:", 'CREATEDOMAIN', \&setCreateDomain );
        }

        if ( $config{LDAPREPLICATIONTYPE} ne "master" ) {
            addMenuItem( $lm, \$i, "Ldap replication type:", 'LDAPREPLICATIONTYPE', \&setLdapReplicationType );
        }
        if ( $config{LDAPREPLICATIONTYPE} eq "mmr" ) {
            addMenuItem( $lm, \$i, "Ldap Server ID:", 'LDAPSERVERID', \&setLdapServerID );
        }

        # LDAPROOTPASS has inverted logic: "Not Verified" preserved when empty
        if ( $config{LDAPROOTPASS} ne "" ) {
            $config{LDAPROOTPASSSET} = "set";
        }
        else {
            $config{LDAPROOTPASSSET} = "UNSET" unless ( $config{LDAPROOTPASSSET} eq "Not Verified" );
        }
        addMenuItem( $lm, \$i, "Ldap root password:", 'LDAPROOTPASSSET', \&setLdapRootPass );

        updatePasswordDisplayStatus( 'LDAPREPPASS', 'LDAPREPPASSSET' );
        addMenuItem( $lm, \$i, "Ldap replication password:", 'LDAPREPPASSSET', \&setLdapRepPass );

        if ( $config{HOSTNAME} eq $config{LDAPHOST} || $config{LDAPREPLICATIONTYPE} ne "replica" || isEnabled("carbonio-mta") ) {
            updatePasswordDisplayStatus( 'LDAPPOSTPASS', 'LDAPPOSTPASSSET' );
            addMenuItem( $lm, \$i, "Ldap postfix password:", 'LDAPPOSTPASSSET', \&setLdapPostPass );

            updatePasswordDisplayStatus( 'LDAPAMAVISPASS', 'LDAPAMAVISPASSSET' );
            addMenuItem( $lm, \$i, "Ldap amavis password:", 'LDAPAMAVISPASSSET', \&setLdapAmavisPass );
        }
        if ( $config{HOSTNAME} eq $config{LDAPHOST} || $config{LDAPREPLICATIONTYPE} ne "replica" || isEnabled("carbonio-proxy") ) {
            updatePasswordDisplayStatus( 'ldap_nginx_password', 'LDAPNGINXPASSSET' );
            addMenuItem( $lm, \$i, "Ldap nginx password:", 'LDAPNGINXPASSSET', \&setLdapNginxPass );
        }
    }
    return $lm;
}

sub createLdapUsersMenu {
    my $package = shift;
    my $lm      = genSubMenu();

    $$lm{title} = "Ldap Users configuration";

    $$lm{createsub} = \&createLdapUsersMenu;
    $$lm{createarg} = $package;

    my $i = 1;
    return $lm;
}

sub createMtaMenu {
    my $package = shift;
    my $lm      = genPackageMenu($package);

    $$lm{title} = "Mta configuration";

    $$lm{createsub} = \&createMtaMenu;
    $$lm{createarg} = $package;

    my $i = 2;
    if ( isEnabled($package) ) {
        addMenuItem( $lm, \$i, "Enable Spamassassin:",              'RUNSA',   \&toggleYN, "RUNSA" );
        addMenuItem( $lm, \$i, "Enable OpenDKIM:",                  'RUNDKIM', \&toggleYN, "RUNDKIM" );
        addMenuItem( $lm, \$i, "Notification address for AV alerts:", 'AVUSER', \&setAvUser );

        updatePasswordDisplayStatus( 'LDAPPOSTPASS', 'LDAPPOSTPASSSET' );
        addMenuItem( $lm, \$i, "Bind password for postfix ldap user:", 'LDAPPOSTPASSSET', \&setLdapPostPass );

        updatePasswordDisplayStatus( 'LDAPAMAVISPASS', 'LDAPAMAVISPASSSET' );
        addMenuItem( $lm, \$i, "Bind password for amavis ldap user:", 'LDAPAMAVISPASSSET', \&setLdapAmavisPass );
    }
    return $lm;
}

sub createProxyMenu {
    my $package = shift;
    my $lm      = genPackageMenu($package);

    $$lm{title} = "Proxy configuration";

    $$lm{createsub} = \&createProxyMenu;
    $$lm{createarg} = $package;

    my $i = 2;
    if ( isInstalled($package) ) {
        addMenuItem( $lm, \$i, "Public Service Hostname:",               'PUBLICSERVICEHOSTNAME',   \&setPublicServiceHostname );
        addMenuItem( $lm, \$i, "Enable POP/IMAP Proxy:",                 'MAILPROXY',               \&toggleTF, "MAILPROXY" );
        addMenuItem( $lm, \$i, "Enable strict server name enforcement?", 'STRICTSERVERNAMEENABLED', \&toggleYN, "STRICTSERVERNAMEENABLED" );

        if ( $config{MAILPROXY} eq "TRUE" ) {
            addMenuItem( $lm, \$i, "IMAP proxy port:",     'IMAPPROXYPORT',    \&setImapProxyPort );
            addMenuItem( $lm, \$i, "IMAP SSL proxy port:", 'IMAPSSLPROXYPORT', \&setImapSSLProxyPort );
            addMenuItem( $lm, \$i, "POP proxy port:",      'POPPROXYPORT',     \&setPopProxyPort );
            addMenuItem( $lm, \$i, "POP SSL proxy port:",  'POPSSLPROXYPORT',  \&setPopSSLProxyPort );
        }
        if ( $config{HTTPPROXY} eq "TRUE" || $config{MAILPROXY} eq "TRUE" ) {
            updatePasswordDisplayStatus( 'ldap_nginx_password', 'LDAPNGINXPASSSET' );
            addMenuItem( $lm, \$i, "Bind password for nginx ldap user:", 'LDAPNGINXPASSSET', \&setLdapNginxPass );
        }
        addMenuItem( $lm, \$i, "Enable HTTP[S] Proxy:", 'HTTPPROXY', \&toggleTF, "HTTPPROXY" );

        if ( $config{HTTPPROXY} eq "TRUE" ) {
            addMenuItem( $lm, \$i, "HTTP proxy port:",   'HTTPPROXYPORT',  \&setHttpProxyPort );
            addMenuItem( $lm, \$i, "HTTPS proxy port:",  'HTTPSPROXYPORT', \&setHttpsProxyPort );
            addMenuItem( $lm, \$i, "Proxy server mode:", 'PROXYMODE',      \&setProxyMode );
        }
    }
    return $lm;
}

sub createStoreMenu {
    my $package = shift;
    my $lm      = genPackageMenu($package);

    $$lm{title} = "Store configuration";

    $$lm{createsub} = \&createStoreMenu;
    $$lm{createarg} = $package;

    my $i = 2;
    if ( isEnabled($package) ) {
        addMenuItem( $lm, \$i, "Create Admin User:", 'DOCREATEADMIN', \&toggleYN, "DOCREATEADMIN" );

        my $ldap_virusquarantine = getLdapConfigValue("zimbraAmavisQuarantineAccount")
          if ( ldapIsAvailable() );

        if ( $ldap_virusquarantine eq "" ) {
            addMenuItem( $lm, \$i, "Anti-virus quarantine user:", 'VIRUSQUARANTINE', \&setAmavisVirusQuarantine );
        }
        else {
            $config{VIRUSQUARANTINE} = $ldap_virusquarantine;
        }

        addMenuItem( $lm, \$i, "Enable automated spam training:", 'DOTRAINSA', \&toggleYN, "DOTRAINSA" );

        if ( $config{DOTRAINSA} eq "yes" ) {
            my $ldap_trainsaspam = getLdapConfigValue("zimbraSpamIsSpamAccount")
              if ( ldapIsAvailable() );

            if ( $ldap_trainsaspam eq "" ) {
                addMenuItem( $lm, \$i, "Spam training user:", 'TRAINSASPAM', \&setTrainSASpam );
            }
            else {
                $config{TRAINSASPAM} = $ldap_trainsaspam;
            }

            my $ldap_trainsaham = getLdapConfigValue("zimbraSpamIsNotSpamAccount")
              if ( ldapIsAvailable() );

            if ( $ldap_trainsaham eq "" ) {
                addMenuItem( $lm, \$i, "Non-spam(Ham) training user:", 'TRAINSAHAM', \&setTrainSAHam );
            }
            else {
                $config{TRAINSAHAM} = $ldap_trainsaham;
            }
        }

        addMenuItem( $lm, \$i, "SMTP host:", 'SMTPHOST', \&setSmtpHost );

        if ( !isEnabled("carbonio-proxy") && $config{zimbraWebProxy} eq "TRUE" ) {
            addMenuItem( $lm, \$i, "HTTP proxy port:",  'HTTPPROXYPORT',  \&setHttpProxyPort );
            addMenuItem( $lm, \$i, "HTTPS proxy port:", 'HTTPSPROXYPORT', \&setHttpsProxyPort );
        }

        addMenuItem( $lm, \$i, "Web server mode:", 'MODE', \&setStoreMode );

        if ( !isEnabled("carbonio-proxy") && $config{zimbraMailProxy} eq "TRUE" ) {
            addMenuItem( $lm, \$i, "IMAP proxy port:",     'IMAPPROXYPORT',    \&setImapProxyPort );
            addMenuItem( $lm, \$i, "IMAP SSL proxy port:", 'IMAPSSLPROXYPORT', \&setImapSSLProxyPort );
            addMenuItem( $lm, \$i, "POP proxy port:",      'POPPROXYPORT',     \&setPopProxyPort );
            addMenuItem( $lm, \$i, "POP SSL proxy port:",  'POPSSLPROXYPORT',  \&setPopSSLProxyPort );
        }
    }
    return $lm;
}

sub displaySubMenuItems {
    my $items         = shift;
    my $parentmenuvar = shift;
    my $indent        = shift;

    if ( defined( $$items{createsub} ) ) {
        $items = &{ $$items{createsub} }( $$items{createarg} );
    }

    #  print "$indent$$items{title}\n";
    foreach my $i ( sort menuSort keys %{ $$items{menuitems} } ) {
        if ( defined( $$items{menuitems}{$i}{var} ) && $$items{menuitems}{$i}{var} == $parentmenuvar ) { next; }
        my $len = 44 - ( length($indent) );
        my $v;
        my $ind = $indent;
        if ( defined $$items{menuitems}{$i}{var} ) {
            $v = ${ $$items{menuitems}{$i}{var} };
            if ( $v eq "" || $v eq "none" || $v eq "UNSET" ) {
                $v = "UNSET";
                $ind =~ s/ /*/g;
            }
            if ( $v eq "Not Verified" ) {
                $v = "Not Verified";
                $ind =~ s/ /*/g;
            }
        }
        printf( "%s +%-${len}s %-30s\n", $ind, $$items{menuitems}{$i}{prompt}, $v );
        if ( defined( $$items{menuitems}{$i}{submenu} ) ) {
            displaySubMenuItems( $$items{menuitems}{$i}{submenu}, "$indent  " );
        }
    }
}

sub menuSort {
    if ( ( $a eq int($a) ) && ( $b eq int($b) ) ) {
        return $a <=> $b;
    }
    return $a cmp $b;
}

sub displayMenu {
    my $items = shift;
    while (1) {
        if ( defined( $$items{createsub} ) ) {
            $items = &{ $$items{createsub} }( $$items{createarg} );
        }

        print "\n$$items{title}\n\n";
        foreach my $i ( sort menuSort keys %{ $$items{menuitems} } ) {
            my $v;
            my $ind = "  ";
            if ( defined $$items{menuitems}{$i}{var} ) {
                $v = ${ $$items{menuitems}{$i}{var} };
                if ( $v eq "" || $v eq "none" || $v eq "UNSET" ) {
                    $v   = "UNSET";
                    $ind = "**";
                }
                if ( $v eq "Not Verified" ) { $ind = "**"; }
            }
            my $subMenuCheck = 1;
            if (   defined( $$items{menuitems}{$i}{submenu} )
                || defined( $$items{menuitems}{$i}{callback} ) )
            {
                if ( defined( $$items{menuitems}{$i}{submenu} ) ) {
                    $subMenuCheck = checkMenuConfig( $$items{menuitems}{$i}{submenu} );
                }
                printf( "${ind}%2s) %-40s %-30s\n", $i, $$items{menuitems}{$i}{prompt}, $v );
            }
            else {
                # Disabled items
                printf( "${ind}    %-40s %-30s\n", $$items{menuitems}{$i}{prompt}, $v );
            }
            if ( $config{EXPANDMENU} eq "yes" || !$subMenuCheck ) {
                if ( defined( $$items{menuitems}{$i}{submenu} ) ) {
                    displaySubMenuItems( $$items{menuitems}{$i}{submenu}, $$items{menuitems}{$i}{var}, "       " );
                    print "\n";
                }
            }
        }
        if ( defined( $$items{lastitem} ) ) {
            printf( "  %2s) %-40s\n", $$items{lastitem}{selector}, $$items{lastitem}{prompt} );
        }
        my $menuprompt = "\n";
        if ( defined( $$items{promptitem} ) ) {
            $menuprompt .= $$items{promptitem}{prompt};
        }
        else {
            $menuprompt .= "Select ";
        }
        if ( defined( $$items{help} ) ) {
            $menuprompt .= " (? - help) ";
        }
        print "$menuprompt";
        if ( defined $$items{default} ) {
            print "[$$items{default}] ";
        }
        my $r = <>;
        chomp $r;
        if ( $r eq "" ) { $r = $$items{default}; }
        if ( $r eq "" ) { next; }
        if ( $r eq $$items{lastitem}{selector} ) {
            if ( $$items{lastitem}{action} eq "quit" ) {
                if ( verifyQuit() ) {
                    exit 0;
                }
            }
            elsif ( $$items{lastitem}{action} eq "return" ) {
                return;
            }
        }
        elsif ( defined $$items{help} && $r eq "?" ) {
            print "\n\n";
            print $$items{help}{helptext};
            print "\n";
            ask( "Press any key to continue", "" );
            print "\n\n";
        }
        elsif ( defined $$items{promptitem} && $r eq $$items{promptitem}{selector} ) {
            if ( defined $$items{promptitem}{callback} ) {
                &{ $$items{promptitem}{callback} }( $$items{promptitem}{arg} );
            }
            elsif ( defined $$items{promptitem}{action} ) {
                if ( $$items{promptitem}{action} eq "quit" ) {
                    if ( verifyQuit() ) {
                        exit 0;
                    }
                }
                elsif ( $$items{promptitem}{action} eq "return" ) {
                    return;
                }
            }
        }
        elsif ( defined $$items{menuitems}{$r} ) {
            print "\n";
            if ( defined $$items{menuitems}{$r}{callback} ) {
                &{ $$items{menuitems}{$r}{callback} }( $$items{menuitems}{$r}{arg} );
            }
            elsif ( defined( $$items{menuitems}{$r}{submenu} ) ) {
                displayMenu( $$items{menuitems}{$r}{submenu} );
            }
        }
        else {
            ask( "Invalid selection! - press any key to continue", "" );
            print "\n\n";
        }
    }
}

sub createMainMenu {
    my %mm = ();
    $mm{createsub} = \&createMainMenu;
    $mm{title}     = "Main menu";
    $mm{help}      = {
        "selector" => "?",
        "prompt"   => "Help",
        "action"   => "help",
        "helptext" => "Main Menu help\n\n" . "Items marked with ** MUST BE CONFIGURED prior to applying configuration\n\n" . "",
    };
    $mm{lastitem} = {
        "selector" => "q",
        "prompt"   => "Quit",
        "action"   => "quit",
    };
    my $i       = 1;
    my $submenu = createCommonMenu("carbonio-core");
    $mm{menuitems}{$i} = {
        "prompt"  => "Common Configuration:",
        "submenu" => $submenu,
    };
    $i++;

    foreach my $package (@packageList) {
        if ( $package eq "carbonio-core" )      { next; }
        if ( $package eq "carbonio-memcached" ) { next; }

        if ( defined( $installedPackages{$package} ) ) {

            # override "prompt" of carbonio-clamav package menu
            if ( $package eq "carbonio-clamav" ) {
                $mm{menuitems}{$i} = {
                    "prompt"   => "carbonio-antivirus:",
                    "var"      => \$enabledPackages{$package},
                    "callback" => \&toggleEnabled,
                    "arg"      => $package
                };
                $i++;
                next;
            }
            my $submenu = createPackageMenu($package);
            $mm{menuitems}{$i} = {
                "prompt"  => "$package:",
                "var"     => \$enabledPackages{$package},
                "submenu" => $submenu,
            };
            $i++;
        }
        else {
            #push @mm, "$package not installed";
        }
    }
    $i = mainMenuExtensions( \%mm, $i );

    if ( $config{EXPANDMENU} eq "yes" ) {
        $mm{menuitems}{c} = {
            "prompt"   => "Collapse menu",
            "callback" => \&toggleYN,
            "arg"      => "EXPANDMENU"
        };
    }
    else {
        $mm{menuitems}{x} = {
            "prompt"   => "Expand menu",
            "callback" => \&toggleYN,
            "arg"      => "EXPANDMENU"
        };
    }

    # Allow save of even incomplete config
    $mm{menuitems}{s} = {
        "prompt"   => "Save config to file",
        "callback" => \&saveConfig,
    };
    if ( checkMenuConfig( \%mm ) ) {
        $mm{promptitem} = {
            "selector" => "y",
            "prompt"   => "*** CONFIGURATION COMPLETE - press 'y' to apply configuration\nSelect from menu, or press 'y' to apply config",
            "callback" => \&applyConfig,
        };
    }
    else {
        $mm{promptitem} = {
            "selector" => "qqazyre",
            "prompt"   => "Address unconfigured (**) items ",
            "callback" => \&applyConfig,
        };
        if ( !ldapIsAvailable() && $ldapConfigured ) {
            $mm{promptitem}{prompt} .= "or correct ldap configuration ";
        }
        if ( $config{LDAPHOST} ne $config{HOSTNAME} && !ldapIsAvailable() && isInstalled("carbonio-directory-server") ) {
            $mm{promptitem}{prompt} .= "and enable ldap replication on ldap master "
              if ( checkLdapReplicationEnabled( $config{zimbra_ldap_userdn}, $config{LDAPADMINPASS} ) );
        }
    }
    return \%mm;
}

sub checkMenuConfig {
    my $items = shift;

    my $needldapverified = 0;

    foreach my $i ( sort menuSort keys %{ $$items{menuitems} } ) {
        my $v;
        my $ind = "  ";
        if ( defined $$items{menuitems}{$i}{var} ) {
            $v = ${ $$items{menuitems}{$i}{var} };
            if ( $v eq "" || $v eq "none" || $v eq "UNSET" || $v eq "Not Verified" ) { return 0; }
            foreach my $var (qw(LDAPHOST LDAPPORT)) {
                if ( $$items{menuitems}{$i}{var} == \$config{$var} ) {
                    $needldapverified = 1;
                }
            }
        }
        if ( defined( $$items{menuitems}{$i}{submenu} ) ) {
            if ( !checkMenuConfig( $$items{menuitems}{$i}{submenu} ) ) {
                return 0;
            }
        }
    }
    if ($needldapverified) {
        return 1 if ( $config{LDAPHOST} eq $config{HOSTNAME} && !$ldapConfigured );
        return 0 if ( !ldapIsAvailable() );
    }
    if ( defined( $installedPackages{"carbonio-appserver"} ) && $config{SERVICEWEBAPP} eq "no" ) {
        $config{SERVICEWEBAPP} = "UNSET";
        return 0;
    }
    return 1;
}

sub ldapIsAvailable {
    my $failedcheck = 0;
    if ( ( $config{LDAPHOST} eq $config{HOSTNAME} ) && !$ldapConfigured ) {
        detail("This is the LDAP master and LDAP has not been configured yet.");
        return 0;
    }

    # check zimbra ldap admin user binding to the master
    if ( $config{LDAPADMINPASS} eq "" || $config{LDAPPORT} eq "" || $config{LDAPHOST} eq "" ) {
        detail("LDAP configuration not complete.\n");
        return 0;
    }

    if ( checkLdapBind( $config{zimbra_ldap_userdn}, $config{LDAPADMINPASS} ) ) {
        detail("Could not bind to $config{LDAPHOST} as $config{zimbra_ldap_userdn}.\n");
        $config{LDAPADMINPASSSET} = "Not Verified";
        $failedcheck++;
    }
    else {
        detail("Verified $config{zimbra_ldap_userdn} on $config{LDAPHOST}.\n");
        $config{LDAPADMINPASSSET} = "set";
        setLocalConfig( "zimbra_ldap_password", $config{LDAPADMINPASS} );
        setLdapDefaults() if ( $config{LDAPHOST} ne $config{HOSTNAME} );
    }

    # check nginx user binding to the master
    if ( isInstalled("carbonio-proxy") ) {
        if ( $config{ldap_nginx_password} eq "" ) {
            detail("Nginx configuration not complete.\n");
            $failedcheck++;
        }
        my $binduser = "uid=zmnginx,cn=appaccts,$config{ldap_dit_base_dn_config}";
        if ( checkLdapBind( $binduser, $config{ldap_nginx_password} ) ) {
            detail("Could not bind to $config{LDAPHOST} as $binduser.\n");
            $config{LDAPNGINXPASSSET} = "Not Verified";
            $failedcheck++;
        }
        else {
            detail("Verified $binduser on $config{LDAPHOST}.\n");
            $config{LDAPNGINXPASSSET} = "set";
        }
    }

    # check postfix and amavis user binding to the master
    if ( isInstalled("carbonio-mta") ) {
        if ( $config{LDAPPOSTPASS} eq "" || $config{LDAPAMAVISPASS} eq "" ) {
            detail("MTA configuration not complete.\n");
            $failedcheck++;
        }
        my $binduser = "uid=zmpostfix,cn=appaccts,$config{ldap_dit_base_dn_config}";
        if ( checkLdapBind( $binduser, $config{LDAPPOSTPASS} ) ) {
            detail("Could not bind to $config{LDAPHOST} as $binduser.\n");
            $config{LDAPPOSTPASSSET} = "Not Verified";
            detail("Setting LDAPPOSTPASSSET to $config{LDAPPOSTPASSSET}.") if $debug;
            $failedcheck++;
        }
        else {
            detail("Verified $binduser on $config{LDAPHOST}.\n");
            $config{LDAPPOSTPASSSET} = "set";
        }
        my $binduser = "uid=zmamavis,cn=appaccts,$config{ldap_dit_base_dn_config}";
        if ( checkLdapBind( $binduser, $config{LDAPAMAVISPASS} ) ) {
            detail("Could not bind to $config{LDAPHOST} as $binduser.\n");
            $config{LDAPAMAVISPASSSET} = "Not Verified";
            detail("Setting LDAPAMAVISPASSSET to $config{LDAPAMAVISPASSSET}.") if $debug;
            $failedcheck++;
        }
        else {
            detail("Verified $binduser on $config{LDAPHOST}.\n");
            $config{LDAPAMAVISPASSSET} = "set";
        }
    }

    # check replication user binding to master
    if ( isInstalled("carbonio-directory-server") && $config{LDAPHOST} ne $config{HOSTNAME} ) {
        if ( $config{LDAPREPPASS} eq "" ) {
            detail("LDAP configuration not complete: replication password is not set.\n");
            $failedcheck++;
        }
        my $binduser = "uid=zmreplica,cn=admins,$config{ldap_dit_base_dn_config}";
        if ( checkLdapBind( $binduser, $config{LDAPREPPASS} ) ) {
            detail("Could not bind to $config{LDAPHOST} as $binduser.\n");
            $config{LDAPREPPASSSET} = "Not Verified";
            detail("Setting LDAPREPPASSSET to $config{LDAPREPPASSSET}.") if $debug;
            $failedcheck++;
        }
        else {
            detail("Verified $binduser on $config{LDAPHOST}.\n");
            $config{LDAPREPPASSSET} = "set";
        }
        if ( checkLdapReplicationEnabled( $config{zimbra_ldap_userdn}, $config{LDAPADMINPASS} ) ) {
            detail("LDAP configuration not complete: unable to verify LDAP replication is enabled on $config{LDAPHOST}.\n");
            $failedcheck++;
        }
        else {
            detail("LDAP replication ability verified.\n");
        }
    }
    return ( $failedcheck > 0 ) ? 0 : 1;
}

sub checkLdapBind() {
    my ( $binduser, $bindpass ) = @_;

    detail("Checking LDAP on $config{LDAPHOST}:$config{LDAPPORT}...");
    my $ldap;
    my $ldap_secure = ( ( $config{LDAPPORT} == "636" ) ? "s" : "" );
    my $ldap_url    = "ldap${ldap_secure}://$config{LDAPHOST}:$config{LDAPPORT}";
    unless ( $ldap = Net::LDAP->new($ldap_url) ) {
        detail("Failed: Unable to contact LDAP at $ldap_url: $!");
        return 1;
    }

    if ( $ldap_secure ne "s" && $config{zimbra_require_interprocess_security} ) {
        $starttls = 1;
        my $result = $ldap->start_tls( verify => 'none' );
        if ( $result->code() ) {
            detail("Unable to startTLS: $!\n");
            detail("Disabling the requirement for interprocess security.\n");
            $config{zimbra_require_interprocess_security} = 0;
            $config{ZIMBRA_REQ_SECURITY}                  = "no";
            $starttls                                     = 0;
        }
    }
    else {
        $starttls = 0;
    }
    my $result = $ldap->bind( $binduser, password => $bindpass );
    if ( $result->code() ) {
        detail("Unable to bind to $ldap_url with user $binduser.");
        return 1;
    }
    else {
        $ldap->unbind;
        detail("Verified LDAP running at $ldap_url.\n");
        if ($newinstall) {
            setLocalConfigBatch(
                ldap_url                             => $ldap_url,
                ldap_starttls_supported              => $starttls,
                zimbra_require_interprocess_security => $config{zimbra_require_interprocess_security},
                ssl_allow_untrusted_certs            => "true"
            );
        }
        return 0;
    }

}

sub checkLdapReplicationEnabled() {
    my ( $binduser, $bindpass ) = @_;
    detail("Checking LDAP replication is enabled on $config{LDAPHOST}:$config{LDAPPORT}...");
    my $ldap;
    my $ldap_secure = ( ( $config{LDAPPORT} == "636" ) ? "s" : "" );
    my $ldap_url    = "ldap${ldap_secure}://$config{LDAPHOST}:$config{LDAPPORT}";
    unless ( $ldap = Net::LDAP->new($ldap_url) ) {
        detail("Failed: Unable to contact LDAP at $ldap_url: $!");
        return 1;
    }
    if ( $ldap_secure ne "s" && $starttls ) {
        my $result = $ldap->start_tls( verify => 'none' );
        if ( $result->code() ) {
            detail("Unable to startTLS: $!\n");
            detail("Disabling the requirement for interprocess security.\n");
            $config{zimbra_require_interprocess_security} = 0;
            $config{ZIMBRA_REQ_SECURITY}                  = "no";
            $starttls                                     = 0;
        }
    }
    my $result = $ldap->bind( $binduser, password => $bindpass );
    if ( $result->code() ) {
        detail("Unable to bind to $ldap_url with user $binduser.");
        return 1;
    }
    else {
        my $result = $ldap->search( base => "cn=accesslog", scope => "base", filter => "cn=accesslog", attrs => ['cn'] );
        if ( $result->code() ) {
            detail("Unable to find accesslog database on master.\n");
            if ( $config{LDAPREPLICATIONTYPE} eq "replica" ) {
                detail("Please run zmldapenablereplica on the master.\n");
            }
            elsif ( $config{LDAPREPLICATIONTYPE} eq "mmr" ) {
                detail("Please run zmldapenable-mmr on the master.\n");
            }
            return 1;
        }
        else {
            detail("Verified ability to query accesslog on master.\n");
        }
    }
    return 0;
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
    detail("DEBUG: exit status from cmd was $exit_value") if $debug;
    return $exit_value;
}

sub getLocalConfig {
    my ( $key, $force ) = @_;

    return $main::loaded{lc}{$key}
      if ( exists $main::loaded{lc}{$key} && !$force );

    detail("Getting local config $key...");
    my $val = qx(/opt/zextras/bin/zmlocalconfig -x -s -m nokey ${key} 2> /dev/null);
    chomp $val;
    detail("DEBUG: LC Loaded $key=$val") if $debug;
    $main::loaded{lc}{$key} = $val;
    return $val;
}

sub getLocalConfigRaw {
    my ( $key, $force ) = @_;

    return $main::loaded{lc}{$key}
      if ( exists $main::loaded{lc}{$key} && !$force );

    detail("Getting local config $key...");
    my $val = qx(/opt/zextras/bin/zmlocalconfig -s -m nokey ${key} 2> /dev/null);
    chomp $val;
    detail("DEBUG: LC Loaded $key=$val") if $debug;
    $main::loaded{lc}{$key} = $val;
    return $val;
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

sub updateKeyValue {
    my ( $sec, $key, $val, $sub ) = @_;
    if ( $key =~ /^\+(.*)/ ) {

        # TODO remove duplicates
        $main::loaded{$sec}{$sub}{$1} = "$main::loaded{$sec}{$sub}{$1}\n$val";
        $main::saved{$sec}{$sub}{$1}  = $main::loaded{$sec}{$sub}{$1};
    }
    elsif ( $key =~ /^-(.*)/ ) {
        if ( exists $main::loaded{$sec}{$sub}{$1} ) {
            my %tmp = map { $_ => 1 } split( /\n/, $main::loaded{$sec}{$sub}{$1} );
            delete $tmp{$val};
            $main::loaded{$sec}{$sub}{$1} = join "\n", keys %tmp;
            $main::saved{$sec}{$sub}{$1}  = $main::loaded{$sec}{$sub}{$1};
        }
    }
    else {
        $main::loaded{$sec}{$sub}{$key} = $val;
        $main::saved{$sec}{$sub}{$key}  = $val;
    }
}

sub ifKeyValueEquate {
    my ( $sec, $key, $val, $sub ) = @_;
    $key = $1 if ( $key =~ /^[+|-](.*)/ );
    detail("Checking to see if $key=$val has changed for $sec $sub\n") if $debug;
    if ( exists $main::saved{$sec}{$sub}{$key} && $main::saved{$sec}{$sub}{$key} eq $val ) {

        #detail("DEBUG: \"$main::saved{$sec}{$sub}{$key}\" eq \"$val\"\n") if $debug;
        return 1;
    }
    else {
        #detail("DEBUG: \"$main::saved{$sec}{$sub}{$key}\" ne \"$val\"\n") if $debug;
        return 0;
    }
}

#
#  setLdapGlobalConfig(key, val [, key, val ...])
#
sub setLdapGlobalConfig {
    return setLdapConfigHelper( "gcf", "gcf", "$ZMPROV mcf", "Global", @_ );
}

sub setLdapServerConfig {
    my $server = ( $#_ % 2 ) == 0 ? shift : $config{HOSTNAME};
    return undef if ( $server eq "" );
    return setLdapConfigHelper( "gs", $server, "$ZMPROV ms $server", "Server", @_ );
}

sub setLdapDomainConfig {
    my $domain = ( $#_ % 2 ) == 0 ? shift : getLdapConfigValue("zimbraDefaultDomainName");
    return undef if ( $domain eq "" );
    return setLdapConfigHelper( "domain", $domain, "$ZMPROV md $domain", "Domain", @_ );
}

sub setLdapCOSConfig {
    my $cos = ( $#_ % 2 ) == 0 ? shift : 'default';
    return setLdapConfigHelper( "gc", $cos, "$ZMPROV mc $cos", "COS", @_ );
}

sub setLdapAccountConfig {
    my $acct = ( $#_ % 2 ) == 0 ? shift : "";
    return undef if ( $acct eq "" );
    return setLdapConfigHelper( "acct", $acct, "$ZMPROV ma $acct", "Account", @_ );
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

sub configCASetup {

    if ( $configStatus{configCASetup} eq "CONFIGURED" && -d "/opt/zextras/ssl/carbonio/ca" ) {
        configLog("configCASetup");
        return 0;
    }

    if ( $config{LDAPHOST} ne $config{HOSTNAME} ) {

        # fetch it from ldap if ldap has been configed
        progress("Updating ldap_root_password and zimbra_ldap_password...");
        setLocalConfigBatch(
            ldap_root_password   => $config{LDAPROOTPASS},
            zimbra_ldap_password => $config{LDAPADMINPASS}
        );
        progress("done.\n");
    }
    progress("Setting up CA...");
    if ( !$newinstall ) {
        if ( -f "/opt/zextras/conf/ca/ca.pem" ) {
            my $rc = runAsRoot("/opt/zextras/common/bin/openssl verify -purpose sslserver -CAfile /opt/zextras/conf/ca/ca.pem /opt/zextras/conf/ca/ca.pem | egrep \"^error 10\"");
            $needNewCert = "-new" if ( $rc == 0 );
        }
    }

    # regenerate the certificate authority if this is the ldap master and
    # either the ca is expired from the test above or the ca directory doesn't exist.
    my $needNewCA;
    if ( isLdapMaster() ) {
        $needNewCA = "-new" if ( !-d "/opt/zextras/ssl/carbonio/ca" || $needNewCert eq "-new" );
    }

    # we are going to download a new CA or otherwise create one so we need to regenerate the self signed cert.
    $needNewCert = "-new" if ( !-d "/opt/zextras/ssl/carbonio/ca" );

    my $rc = runAsZextras("/opt/zextras/bin/zmcertmgr createca $needNewCA");
    progressResult( $rc, 1 );

    progress("Deploying CA to /opt/zextras/conf/ca ...");
    $rc = runAsZextras("/opt/zextras/bin/zmcertmgr deployca -localonly");
    progressResult( $rc, 1 );

    configLog("configCASetup");
}

sub updatePasswordsInLocalConfig {

    if ( isEnabled("carbonio-directory-server") ) {

        # On new install where we're the LDAP host and LDAP isn't configured yet,
        # skip password setting here - it will be done after LDAP is started in configSetupLdap
        if ( $newinstall && !$ldapConfigured && ( $config{LDAPHOST} eq $config{HOSTNAME} ) ) {
            detail("Skipping password update - LDAP not yet started, will be set after initialization\n");
            return;
        }

        # zmldappasswd starts ldap and re-applies the ldif
        if ( $ldapRootPassChanged || $ldapAdminPassChanged || $ldapRepChanged || $ldapPostChanged || $ldapAmavisChanged || $ldapNginxChanged ) {

            if ($ldapRootPassChanged) {
                progress("Setting LDAP root password...");
                runAsZextras("/opt/zextras/bin/zmldappasswd -r $config{LDAPROOTPASS}");
                progress("done.\n");
            }
            setLdapPasswordHelper( "LDAP admin", "", "LDAPADMINPASS", "zimbra_ldap_password" )         if $ldapAdminPassChanged;
            setLdapPasswordHelper( "replication", "-l", "LDAPREPPASS", "ldap_replication_password" )  if $ldapRepChanged;
            setLdapPasswordHelper( "Postfix", "-p", "LDAPPOSTPASS", "ldap_postfix_password" )         if $ldapPostChanged;
            setLdapPasswordHelper( "amavis", "-a", "LDAPAMAVISPASS", "ldap_amavis_password" )         if $ldapAmavisChanged;
            setLdapPasswordHelper( "nginx", "-n", "ldap_nginx_password", "ldap_nginx_password" )     if $ldapNginxChanged;
        }
        else {
            progress("Stopping LDAP...");
            if ( isSystemd() ) {
                system("systemctl stop carbonio-openldap.service");
            }
            else {
                runAsZextras("/opt/zextras/bin/ldap stop");
            }
            progress("done.\n");
            startLdap();
        }
    }
    else {
        # this sets the password for each component if they are enabled, use full in case of multiserver
        # especially when we add components to existing configured node
        if ( isEnabled("carbonio-mta") && ( $ldapPostChanged || $ldapAmavisChanged ) ) {
            setLdapPasswordHelper( "postfix", "-p", "LDAPPOSTPASS", "ldap_postfix_password" ) if $ldapPostChanged;
            setLdapPasswordHelper( "amavis", "-a", "LDAPAMAVISPASS", "ldap_amavis_password" ) if $ldapAmavisChanged;
        }

        if ( isEnabled("carbonio-proxy") && $ldapNginxChanged ) {
            setLdapPasswordHelper( "nginx", "-n", "ldap_nginx_password", "ldap_nginx_password" );
        }
    }
}

sub configSetupLdap {

    updatePasswordsInLocalConfig();

    #Check if skipping configSetupLdap on existing install is distructive
    if ( $configStatus{configSetupLdap} eq "CONFIGURED" ) {
        detail("LDAP already configured, bypassing configuration.\n");
        configLog("configSetupLdap");
        return 0;
    }

    if ( !$ldapConfigured && isEnabled("carbonio-directory-server") && !-f "/opt/zextras/.enable_replica" && $newinstall && ( $config{LDAPHOST} eq $config{HOSTNAME} ) ) {
        progress("Initializing LDAP...");
        ldapinit->preLdapStart( $config{LDAPROOTPASS}, $config{LDAPADMINPASS} );
        if ( isSystemd() ) {
            system("systemctl start carbonio-openldap.service");
            sleep 5;
        }
        else {
            runAsZextras("/opt/zextras/bin/ldap start");
        }

        if ( my $rc = ldapinit->postLdapStart() ) {
            progress("failed. ($rc)\n");
            failConfig();
        }
        else {
            progress("done.\n");
            # Set passwords after LDAP init (use quoted passwords for shell safety)
            setLdapPasswordHelper( "replication", "-l", "LDAPREPPASS", "ldap_replication_password", 1 ) if $ldapRepChanged;
            setLdapPasswordHelper( "Postfix", "-p", "LDAPPOSTPASS", "ldap_postfix_password", 1 )        if $ldapPostChanged;
            setLdapPasswordHelper( "amavis", "-a", "LDAPAMAVISPASS", "ldap_amavis_password", 1 )        if $ldapAmavisChanged;
            setLdapPasswordHelper( "nginx", "-n", "ldap_nginx_password", "ldap_nginx_password", 1 )    if $ldapNginxChanged;
        }
        if ( $config{FORCEREPLICATION} eq "yes" ) {
            my $rc   = system("/opt/zextras/libexec/zmldapenablereplica");
            my $file = "/opt/zextras/.enable_replica";
            open( ER, ">>$file" );
            close ER;
        }
    }
    elsif ( isEnabled("carbonio-directory-server") ) {
        my $rc;
        if ($newinstall) {
            $rc = runAsZextras("/opt/zextras/libexec/zmldapapplyldif");
        }
        if ( !$newinstall ) {
            $rc = runAsZextras("/opt/zextras/libexec/zmldapupdateldif");
        }

        # enable replica for both new and upgrade installs if we are adding ldap
        if ( $config{LDAPHOST} ne $config{HOSTNAME} || -f "/opt/zextras/.enable_replica" ) {
            progress("Updating ldap_root_password and zimbra_ldap_password...");
            setLocalConfigBatch(
                ldap_root_password        => $config{LDAPROOTPASS},
                zimbra_ldap_password      => $config{LDAPADMINPASS},
                ldap_replication_password => $config{LDAPREPPASS}
            );
            if ( $newinstall && $config{LDAPREPLICATIONTYPE} eq "mmr" ) {
                setLdapPasswordHelper( "Postfix", "-p", "LDAPPOSTPASS", "ldap_postfix_password", 1 )     if $ldapPostChanged;
                setLdapPasswordHelper( "amavis", "-a", "LDAPAMAVISPASS", "ldap_amavis_password", 1 )     if $ldapAmavisChanged;
                setLdapPasswordHelper( "nginx", "-n", "ldap_nginx_password", "ldap_nginx_password", 1 ) if $ldapNginxChanged;
            }
            progress("done.\n");
            progress("Enabling LDAP replication...");
            if ( !-f "/opt/zextras/.enable_replica" ) {
                if ( $newinstall && $config{LDAPREPLICATIONTYPE} eq "mmr" ) {
                    my $ldapMasterUrl = getLocalConfig("ldap_master_url");
                    my $proto = ( $config{LDAPPORT} == 636 ) ? "ldaps" : "ldap";
                    setLocalConfigBatch(
                        ldap_is_master => "true",
                        ldap_url       => "$proto://$config{HOSTNAME}:$config{LDAPPORT} $ldapMasterUrl"
                    );
                    $ldapMasterUrl .= "/" unless $ldapMasterUrl =~ /\/$/;
                    if ( isSystemd() ) {
                        system("systemctl start carbonio-openldap.service");
                    }
                    else {
                        runAsZextras("/opt/zextras/bin/ldap start");
                    }
                    $rc = runAsZextras("/opt/zextras/libexec/zmldapenable-mmr -s $config{LDAPSERVERID} -m $ldapMasterUrl");
                }
                else {
                    $rc = system("/opt/zextras/libexec/zmldapenablereplica");
                }
                my $file = "/opt/zextras/.enable_replica";
                open( ER, ">>$file" );
                close ER;
            }
            if ( $rc == 0 ) {
                if ( !isEnabled("carbonio-appserver") ) {
                    $config{DOCREATEADMIN} = "no";
                }
                $config{DOCREATEDOMAIN} = "no";
                progress("done.\n");
                progress("Stopping LDAP...");
                if ( isSystemd() ) {
                    $rc = system("systemctl stop carbonio-openldap.service");
                }
                else {
                    $rc = runAsZextras("/opt/zextras/bin/ldap stop");
                }
                progress("done.\n");
                startLdap();
            }
            else {
                progress("failed.\n");
                progress("You will have to correct the problem and manually enable replication.\n");
                progress("Disabling LDAP on $config{HOSTNAME}...");
                my $rc = setLdapServerConfig( "-zimbraServiceEnabled", "directory-server" );
                progress( ( $rc == 0 ) ? "done.\n" : "failed.\n" );
                progress("Stopping LDAP...");
                if ( isSystemd() ) {
                    $rc = system("systemctl stop carbonio-openldap.service");
                }
                else {
                    $rc = runAsZextras("/opt/zextras/bin/ldap stop");
                }
                progress("done.\n");
            }
        }
    }
    else {
        detail("Updating LDAP user passwords.\n");
        setLocalConfigBatch(
            ldap_root_password        => $config{LDAPROOTPASS},
            zimbra_ldap_password      => $config{LDAPADMINPASS},
            ldap_replication_password => $config{LDAPREPPASS},
            ldap_postfix_password     => $config{LDAPPOSTPASS},
            ldap_amavis_password      => $config{LDAPAMAVISPASS},
            ldap_nginx_password       => $config{ldap_nginx_password}
        );
    }

    configLog("configSetupLdap");
    return 0;

}

sub configLDAPSchemaVersion {
    return if ($haveSetLdapSchemaVersion);
    if ( isEnabled("carbonio-directory-server") ) {
        progress("Updating LDAP Schema version to '$ldapSchemaVersion'...");
        my $ec = setLdapGlobalConfig( 'zimbraLDAPSchemaVersion', $ldapSchemaVersion );
        if ( $ec != 0 ) {
            progress("failed.\n");
        }
        else {
            $haveSetLdapSchemaVersion = 1;
            progress("done.\n");
        }
    }
}

sub configSaveCA {

    if ( $configStatus{configSaveCA} eq "CONFIGURED" ) {
        configLog("configSaveCA");
        return 0;
    }
    progress("Saving CA in LDAP...");
    my $rc = runAsZextras("/opt/zextras/bin/zmcertmgr deployca");
    progressResult( $rc, 1 );
    configLog("configSaveCA");
}

sub configCreateCert {

    if ( $configStatus{configCreateCert} eq "CONFIGURED" && -d "/opt/zextras/ssl/carbonio/server" ) {
        configLog("configCreateCert");
        return 0;
    }

    if ( !$newinstall ) {
        my $rc = runAsZextras("/opt/zextras/bin/zmcertmgr verifycrt comm > /dev/null 2>&1");
        if ( $rc != 0 ) {
            $rc = runAsZextras("/opt/zextras/bin/zmcertmgr verifycrt self > /dev/null 2>&1");
            if ( $rc != 0 ) {
                progress("WARNING: No valid SSL certificates were found.\n");
                progress("New self-signed certificates will be generated and installed.\n");
                $needNewCert   = "-new" if ( $rc != 0 );
                $ssl_cert_type = "self";
            }
        }
        else {
            $ssl_cert_type = "comm";
            $needNewCert   = "";
        }
    }

    my $rc;

    # Helper to create certificate for a component
    my $createCertFor = sub {
        my ($component, $msg) = @_;
        progress("$msg...");
        $rc = runAsZextras("/opt/zextras/bin/zmcertmgr createcrt $needNewCert");
        progressResult( $rc, 1 );
    };

    if ( isInstalled("carbonio-appserver") ) {
        if ( !-f "$config{mailboxd_keystore}" && !-f "/opt/zextras/ssl/carbonio/server/server.crt" ) {
            if ( !-d "$config{mailboxd_directory}" ) {
                qx(mkdir -p $config{mailboxd_directory}/etc);
                qx(chown -R zextras:zextras $config{mailboxd_directory});
                qx(chmod 744 $config{mailboxd_directory}/etc);
            }
            $createCertFor->( "appserver", "Creating SSL carbonio-appserver certificate" );
        }
        elsif ( $needNewCert ne "" && $ssl_cert_type eq "self" ) {
            $createCertFor->( "appserver", "Creating new carbonio-appserver SSL certificate" );
        }
    }

    if ( isInstalled("carbonio-directory-server") ) {
        if ( !-f "/opt/zextras/conf/slapd.crt" && !-f "/opt/zextras/ssl/carbonio/server/server.crt" ) {
            $createCertFor->( "ldap", "Creating carbonio-directory-server SSL certificate" );
        }
        elsif ( $needNewCert ne "" && $ssl_cert_type eq "self" ) {
            $createCertFor->( "ldap", "Creating new carbonio-directory-server SSL certificate" );
        }
    }

    if ( isInstalled("carbonio-mta") ) {
        if ( !-f "/opt/zextras/conf/smtpd.crt" && !-f "/opt/zextras/ssl/carbonio/server/server.crt" ) {
            $createCertFor->( "mta", "Creating carbonio-mta SSL certificate" );
        }
        elsif ( $needNewCert ne "" && $ssl_cert_type eq "self" ) {
            $createCertFor->( "mta", "Creating new carbonio-mta SSL certificate" );
        }
    }

    if ( isInstalled("carbonio-proxy") ) {
        if ( !-f "/opt/zextras/conf/nginx.crt" && !-f "/opt/zextras/ssl/carbonio/server/server.crt" ) {
            $createCertFor->( "proxy", "Creating carbonio-proxy SSL certificate" );
        }
        elsif ( $needNewCert ne "" && $ssl_cert_type eq "self" ) {
            $createCertFor->( "proxy", "Creating new carbonio-proxy SSL certificate" );
        }
    }

    configLog("configCreateCert");
}

sub configSaveCert {

    if ( $configStatus{configSaveCert} eq "CONFIGURED" ) {
        configLog("configSaveCert");
        return 0;
    }
    if ( -f "/opt/zextras/ssl/carbonio/server/server.crt" ) {
        progress("Saving SSL Certificate in LDAP...");
        my $rc = runAsZextras("/opt/zextras/bin/zmcertmgr savecrt $ssl_cert_type");
        progressResult( $rc, 1 );
        configLog("configSaveCert");
    }
}

sub configInstallCert {
    my $rc;

    # Determine which certificates need to be installed
    my $needStoreInstall = 0;
    my $needMtaInstall   = 0;
    my $needLdapInstall  = 0;
    my $needProxyInstall = 0;

    # Check Store/Mailbox certificate
    if ( $configStatus{configInstallCertStore} eq "CONFIGURED" && $needNewCert eq "" ) {
        configLog("configInstallCertStore");
    }
    elsif ( isInstalled("carbonio-appserver") ) {
        if ( !( -f "$config{mailboxd_keystore}" ) || $needNewCert ne "" ) {
            detail("Keystore $config{mailboxd_keystore} does not exist.")
              if ( !-f "$config{mailboxd_keystore}" );
            detail("New certificate required: $needNewCert.")
              if ( $needNewCert ne "" );
            $needStoreInstall = 1;
        }
        else {
            configLog("configInstallCertStore");
        }
    }

    # Check MTA certificate
    if ( $configStatus{configInstallCertMTA} eq "CONFIGURED" && $needNewCert eq "" ) {
        configLog("configInstallCertMTA");
    }
    elsif ( isInstalled("carbonio-mta") ) {
        if ( !( -f "/opt/zextras/conf/smtpd.key" || -f "/opt/zextras/conf/smtpd.crt" )
            || $needNewCert ne "" )
        {
            $needMtaInstall = 1;
        }
        else {
            configLog("configInstallCertMTA");
        }
    }

    # Check LDAP certificate
    if ( $configStatus{configInstallCertLDAP} eq "CONFIGURED" && $needNewCert eq "" ) {
        configLog("configInstallCertLDAP");
    }
    elsif ( isInstalled("carbonio-directory-server") ) {
        if ( !( -f "/opt/zextras/conf/slapd.key" || -f "/opt/zextras/conf/slapd.crt" )
            || $needNewCert ne "" )
        {
            $needLdapInstall = 1;
        }
        else {
            configLog("configInstallCertLDAP");
        }
    }

    # Check Proxy certificate
    if ( $configStatus{configInstallCertProxy} eq "CONFIGURED" && $needNewCert eq "" ) {
        configLog("configInstallCertProxy");
    }
    elsif ( isInstalled("carbonio-proxy") ) {
        if ( !( -f "/opt/zextras/conf/nginx.key" || -f "/opt/zextras/conf/nginx.crt" )
            || $needNewCert ne "" )
        {
            $needProxyInstall = 1;
        }
        else {
            configLog("configInstallCertProxy");
        }
    }

    # Run deploycrt only once if any certificate needs to be installed
    if ( $needStoreInstall || $needMtaInstall || $needLdapInstall || $needProxyInstall ) {
        my @components;
        push @components, "mailboxd" if $needStoreInstall;
        push @components, "MTA"      if $needMtaInstall;
        push @components, "LDAP"     if $needLdapInstall;
        push @components, "Proxy"    if $needProxyInstall;
        progress( "Installing SSL certificates for: " . join( ", ", @components ) . "..." );

        $rc = runAsZextras("/opt/zextras/bin/zmcertmgr deploycrt $ssl_cert_type");
        progressResult( $rc, 1 );
        configLog("configInstallCertStore") if $needStoreInstall;
        configLog("configInstallCertMTA")   if $needMtaInstall;
        if ($needLdapInstall) {
            stopLdap()  if ($ldapConfigured);
            startLdap() if ($ldapConfigured);
            configLog("configInstallCertLDAP");
        }
        configLog("configInstallCertProxy") if $needProxyInstall;
    }

}

sub configCreateServerEntry {

    if ( $configStatus{configCreateServerEntry} eq "CONFIGURED" ) {
        configLog("configCreateServerEntry");
        return 0;
    }

    progress("Creating server entry for $config{HOSTNAME}...");
    my $serverId = getLdapServerValue("zimbraId");
    if ( $serverId ne "" ) {
        progress("already exists.\n");
    }
    else {
        my $rc = runAsZextras("$ZMPROV cs $config{HOSTNAME}");
        progress( ( $rc == 0 ) ? "done.\n" : "failed.\n" );
    }
    progress("Setting IP Mode...");
    my $rc = setLdapServerConfig( "zimbraIPMode", $config{zimbraIPMode} );
    progress( ( $rc == 0 ) ? "done.\n" : "failed.\n" );
    my $rc = runAsZextras("/opt/zextras/libexec/zmiptool >/dev/null 2>/dev/null");

    configLog("configCreateServerEntry");
}

sub configSetStoreDefaults {
    if ( isEnabled("carbonio-proxy") || $config{zimbraMailProxy} eq "TRUE" || $config{zimbraWebProxy} eq "TRUE" ) {
        $config{zimbraReverseProxyLookupTarget} = "TRUE";
    }

    # for mailstore split, set zimbraReverseProxyAvailableLookupTargets on service-only nodes
    if ( $newinstall && isStoreServiceNode() ) {
        my $adding = 0;
        progress("Checking current setting of ReverseProxyAvailableLookupTargets...\n");
        my $zrpALT = getLdapConfigValue("zimbraReverseProxyAvailableLookupTargets");
        if ( $zrpALT ne "" ) {
            $adding = 1;
        }
        else {
            progress("Querying LDAP for other mailstores...\n");

            # query LDAP to see if there are other mailstores.  If there are none, add this
            # new service node to zimbraReverseProxyAvailableLookupTargets.  Otherwise do not
            my $count = countReverseProxyLookupTargets();
            if ( !defined($count) || $count == 0 ) {
                $adding = 1;
            }
        }
        if ($adding) {
            progress("Adding $config{HOSTNAME} to ReverseProxyAvailableLookupTargets...\n");
            setLdapGlobalConfig( "+zimbraReverseProxyAvailableLookupTargets", $config{HOSTNAME} );
        }
    }
    $config{zimbraMtaAuthTarget} = "TRUE";
    if ( !isStoreServiceNode() ) {
        $config{zimbraMtaAuthTarget} = "FALSE";
    }
    if ( $newinstall && isStoreServiceNode() ) {
        setLdapGlobalConfig( "+zimbraReverseProxyUpstreamEwsServers", "$config{HOSTNAME}" );
    }

    setLdapServerConfig( "zimbraReverseProxyLookupTarget", $config{zimbraReverseProxyLookupTarget} );
    setLdapServerConfig( "zimbraMtaAuthTarget",            $config{zimbraMtaAuthTarget} );
    my $upstream = "-u";
    if ( $config{zimbra_require_interprocess_security} ) {
        $upstream = "-U";
    }
    if ( $newinstall && ( $config{zimbraWebProxy} eq "TRUE" || $config{zimbraMailProxy} eq "TRUE" ) ) {
        if ( $config{zimbraMailProxy} eq "TRUE" ) {
            my $rc = runAsZextras( "/opt/zextras/libexec/zmproxyconfig $upstream -m -e -o " . "-i $config{IMAPPORT}:$config{IMAPPROXYPORT}:$config{IMAPSSLPORT}:$config{IMAPSSLPROXYPORT} " . "-p $config{POPPORT}:$config{POPPROXYPORT}:$config{POPSSLPORT}:$config{POPSSLPROXYPORT} -H $config{HOSTNAME}" );
            if ( $rc != 0 ) {
                progress("WARNING: zmproxyconfig for mail proxy returned non-zero exit code: $rc\n");
            }
        }
        if ( $config{zimbraWebProxy} eq "TRUE" ) {
            my $rc = runAsZextras( "/opt/zextras/libexec/zmproxyconfig $upstream -w -e -o " . "-x $config{PROXYMODE} " . "-a $config{HTTPPORT}:$config{HTTPPROXYPORT}:$config{HTTPSPORT}:$config{HTTPSPROXYPORT} -H $config{HOSTNAME}" );
            if ( $rc != 0 ) {
                progress("WARNING: zmproxyconfig for web proxy returned non-zero exit code: $rc\n");
            }
        }
    }
}

sub isStoreServiceNode {
    if ( $installedWebapps{"service"} eq "Enabled" ) {
        return 1;
    }
    else {
        return 0;
    }
}

sub configSetServicePorts {

    if ( $configStatus{configSetServicePorts} eq "CONFIGURED" ) {
        configLog("configSetServicePorts");
        return 0;
    }

    progress("Setting service ports on $config{HOSTNAME}...");
    if ( $config{MAILPROXY} eq "FALSE" ) {
        if ( $config{IMAPPORT} == 7143 && $config{IMAPPROXYPORT} == $config{IMAPPORT} ) {
            $config{IMAPPROXYPORT} = 143;
        }
        if ( $config{IMAPSSLPORT} == 7993 && $config{IMAPSSLPROXYPORT} == $config{IMAPSSLPORT} ) {
            $config{IMAPSSLPROXYPORT} = 993;
        }
        if ( $config{POPPORT} == 7110 && $config{POPPROXYPORT} == $config{POPPORT} ) {
            $config{POPPROXYPORT} = 110;
        }
        if ( $config{POPSSLPORT} == 7995 && $config{POPSSLPROXYPORT} == $config{POPSSLPORT} ) {
            $config{POPSSLPORT} = 995;
        }
    }
    setLdapServerConfig( $config{HOSTNAME}, "zimbraImapBindPort", $config{IMAPPORT}, "zimbraImapSSLBindPort", $config{IMAPSSLPORT}, "zimbraImapProxyBindPort", $config{IMAPPROXYPORT}, "zimbraImapSSLProxyBindPort", $config{IMAPSSLPROXYPORT} );
    setLdapServerConfig( $config{HOSTNAME}, "zimbraPop3BindPort", $config{POPPORT},  "zimbraPop3SSLBindPort", $config{POPSSLPORT},  "zimbraPop3ProxyBindPort", $config{POPPROXYPORT},  "zimbraPop3SSLProxyBindPort", $config{POPSSLPROXYPORT} );
    if ( $config{HTTPPROXY} eq "FALSE" ) {
        if ( $config{HTTPPORT} == 8080 && $config{HTTPPROXYPORT} == $config{HTTPPORT} ) {
            $config{HTTPPROXYPORT} = 80;
        }
        if ( $config{HTTPSPORT} == 8443 && $config{HTTPSPROXYPORT} == $config{HTTPSPORT} ) {
            $config{HTTPSPROXYPORT} = 443;
        }
    }
    setLdapServerConfig( $config{HOSTNAME}, "zimbraMailPort", $config{HTTPPORT}, "zimbraMailSSLPort", $config{HTTPSPORT}, "zimbraMailProxyPort", $config{HTTPPROXYPORT}, "zimbraMailSSLProxyPort", $config{HTTPSPROXYPORT}, "zimbraMailMode", $config{MODE} );
    setLocalConfig( "zimbra_mail_service_port", $config{HTTPPORT} );

    progress("done.\n");
    configLog("configSetServicePorts");
}

sub configSetKeyboardShortcutsPref {
    if ( $configStatus{zimbraPrefUseKeyboardShortcuts} eq "CONFIGURED" ) {
        configLog("zimbraPrefUseKeyboardShortcuts");
        return 0;
    }
    progress("Setting Keyboard Shortcut Preferences...");
    my $rc = setLdapCOSConfig( "zimbraPrefUseKeyboardShortcuts", $config{USEKBSHORTCUTS} );
    progress( ( $rc == 0 ) ? "done.\n" : "failed.\n" );
    configLog("zimbraPrefUseKeyboardShortcuts");
}

sub configSetTimeZonePref {
    if ( $configStatus{zimbraPrefTimeZoneId} eq "CONFIGURED" ) {
        configLog("zimbraPrefTimeZoneId");
        return 0;
    }
    if ( $config{LDAPHOST} eq $config{HOSTNAME} ) {
        progress("Setting TimeZone Preference...");
        my $rc = setLdapCOSConfig( "zimbraPrefTimeZoneId", $config{zimbraPrefTimeZoneId} );
        progress( ( $rc == 0 ) ? "done.\n" : "failed.\n" );
    }
    configLog("zimbraPrefTimeZoneId");
}

sub setProxyBits {
    detail("Setting proxy configuration...\n");
    my $ReverseProxyMailHostQuery   = "\(\|\(zimbraMailDeliveryAddress=\${USER}\)\(zimbraMailAlias=\${USER}\)\(zimbraId=\${USER}\)\)";
    my $ReverseProxyDomainNameQuery = '\(\&\(zimbraVirtualIPAddress=\${IPADDR}\)\(objectClass=zimbraDomain\)\)';
    my $ReverseProxyPortQuery       = '\(\&\(zimbraServiceHostname=\${MAILHOST}\)\(objectClass=zimbraServer\)\)';

    my @proxy_defaults = (
        [ 'zimbraReverseProxyMailHostQuery',          $ReverseProxyMailHostQuery ],
        [ 'zimbraReverseProxyPortQuery',              $ReverseProxyPortQuery ],
        [ 'zimbraReverseProxyDomainNameQuery',        $ReverseProxyDomainNameQuery ],
        [ 'zimbraMemcachedBindPort',                  '11211' ],
        [ 'zimbraMemcachedBindAddress',               '127.0.0.1' ],
        [ 'zimbraReverseProxyMailHostAttribute',      'zimbraMailHost' ],
        [ 'zimbraReverseProxyPop3PortAttribute',      'zimbraPop3BindPort' ],
        [ 'zimbraReverseProxyPop3SSLPortAttribute',   'zimbraPop3SSLBindPort' ],
        [ 'zimbraReverseProxyImapPortAttribute',      'zimbraImapBindPort' ],
        [ 'zimbraReverseProxyImapSSLPortAttribute',   'zimbraImapSSLBindPort' ],
        [ 'zimbraReverseProxyDomainNameAttribute',    'zimbraDomainName' ],
        [ 'zimbraImapCleartextLoginEnabled',          'FALSE' ],
        [ 'zimbraPop3CleartextLoginEnabled',          'FALSE' ],
        [ 'zimbraReverseProxyAuthWaitInterval',       '10s' ],
        [ 'zimbraReverseProxyIPLoginLimit',           '0' ],
        [ 'zimbraReverseProxyIPLoginLimitTime',       '3600' ],
        [ 'zimbraReverseProxyUserLoginLimit',         '0' ],
        [ 'zimbraReverseProxyUserLoginLimitTime',     '3600' ],
        [ 'zimbraMailProxyPort',                      '0' ],
        [ 'zimbraMailSSLProxyPort',                   '0' ],
        [ 'zimbraReverseProxyHttpEnabled',            'FALSE' ],
        [ 'zimbraReverseProxyMailEnabled',            'TRUE' ],
    );

    my @zmprov_args = ();
    for my $pair (@proxy_defaults) {
        my ( $key, $val ) = @$pair;
        push( @zmprov_args, ( $key, $val ) ) if ( getLdapConfigValue($key) eq "" );
    }
    setLdapGlobalConfig(@zmprov_args);
}

sub configSetProxyPrefs {
    if ( isEnabled("carbonio-proxy") ) {
        if ( $config{STRICTSERVERNAMEENABLED} eq "yes" ) {
            progress("Enabling strict server name enforcement on $config{HOSTNAME}...");
            runAsZextras("$ZMPROV ms $config{HOSTNAME} zimbraReverseProxyStrictServerNameEnabled TRUE");
            progress("done.\n");
        }
        else {
            progress("Disabling strict server name enforcement on $config{HOSTNAME}...");
            runAsZextras("$ZMPROV ms $config{HOSTNAME} zimbraReverseProxyStrictServerNameEnabled FALSE");
            progress("done.\n");
        }
        if ( $config{MAILPROXY} eq "FALSE" && $config{HTTPPROXY} eq "FALSE" ) {
            $enabledPackages{"carbonio-proxy"} = "Disabled";
        }
        else {
            my $upstream = "-u";
            if ( $config{zimbra_require_interprocess_security} ) {
                $upstream = "-U";
            }
            if ( $config{MAILPROXY} eq "TRUE" ) {
                runAsZextras( "/opt/zextras/libexec/zmproxyconfig $upstream -m -e -o " . "-i $config{IMAPPORT}:$config{IMAPPROXYPORT}:$config{IMAPSSLPORT}:$config{IMAPSSLPROXYPORT} " . "-p $config{POPPORT}:$config{POPPROXYPORT}:$config{POPSSLPORT}:$config{POPSSLPROXYPORT} -H $config{HOSTNAME}" );
            }
            else {
                runAsZextras( "/opt/zextras/libexec/zmproxyconfig -m -d -o " . "-i $config{IMAPPORT}:$config{IMAPPROXYPORT}:$config{IMAPSSLPORT}:$config{IMAPSSLPROXYPORT} " . "-p $config{POPPORT}:$config{POPPROXYPORT}:$config{POPSSLPORT}:$config{POPSSLPROXYPORT} -H $config{HOSTNAME}" );
            }
            if ( $config{HTTPPROXY} eq "TRUE" ) {
                runAsZextras( "/opt/zextras/libexec/zmproxyconfig $upstream -w -e -o " . " -x $config{PROXYMODE} " . "-a $config{HTTPPORT}:$config{HTTPPROXYPORT}:$config{HTTPSPORT}:$config{HTTPSPROXYPORT} -H $config{HOSTNAME}" );
            }
            else {
                runAsZextras( "/opt/zextras/libexec/zmproxyconfig -w -d -o " . "-x $config{MODE} " . "-a $config{HTTPPORT}:$config{HTTPPROXYPORT}:$config{HTTPSPORT}:$config{HTTPSPROXYPORT} -H $config{HOSTNAME}" );
            }
        }
        if ( !( isEnabled("carbonio-appserver") ) ) {
            my @storetargets;
            detail("Running $ZMPROV garpu...");
            open( ZMPROV, "$ZMPROV garpu 2>/dev/null|" );
            chomp( @storetargets = <ZMPROV> );
            close(ZMPROV);
            if ( $storetargets[0] !~ /nginx-lookup/ ) {
                progress("WARNING: There is currently no mailstore to proxy. Proxy will restart once one becomes available.\n");
            }
        }
        if ( !( isEnabled("carbonio-memcached") ) ) {
            my @memcachetargets;
            detail("Running $ZMPROV gamcs...");
            open( ZMPROV, "$ZMPROV gamcs 2>/dev/null|" );
            chomp( @memcachetargets = <ZMPROV> );
            close(ZMPROV);
            if ( $memcachetargets[0] !~ /:11211/ ) {
                progress("WARNING: There are currently no memcached servers for the proxy.  Proxy will start once one becomes available.\n");
            }
        }
        if ( ( !( $config{PUBLICSERVICEHOSTNAME} eq "" ) ) && ( !($publicServiceHostnameAlreadySet) ) ) {
            progress("Setting Public Service Hostname $config{PUBLICSERVICEHOSTNAME}...");
            runAsZextras("$ZMPROV mcf zimbraPublicServiceHostname $config{PUBLICSERVICEHOSTNAME}");
            progress("done.\n");
        }
    }
    else {
        runAsZextras( "/opt/zextras/libexec/zmproxyconfig -m -d -o " . "-i $config{IMAPPORT}:$config{IMAPPROXYPORT}:$config{IMAPSSLPORT}:$config{IMAPSSLPROXYPORT} " . "-p $config{POPPORT}:$config{POPPROXYPORT}:$config{POPSSLPORT}:$config{POPSSLPROXYPORT} -H $config{HOSTNAME}" );
        runAsZextras( "/opt/zextras/libexec/zmproxyconfig -w -d -o " . "-x $config{MODE} " . "-a $config{HTTPPORT}:$config{HTTPPROXYPORT}:$config{HTTPSPORT}:$config{HTTPSPROXYPORT} -H $config{HOSTNAME}" );
    }
}

sub countReverseProxyLookupTargets {
    my $count           = 0;
    my $ldap_pass       = getLocalConfig("zimbra_ldap_password");
    my $ldap_master_url = getLocalConfig("ldap_master_url");
    my $ldap;
    my @masters    = split( / /, $ldap_master_url );
    my $master_ref = \@masters;

    unless ( $ldap = Net::LDAP->new($master_ref) ) {
        detail("Unable to contact $ldap_master_url.");
        return;
    }
    my $ldap_dn   = $config{zimbra_ldap_userdn};
    my $ldap_base = "";

    my $result = $ldap->bind( $ldap_dn, password => $ldap_pass );
    if ( $result->code() ) {
        detail("LDAP bind failed for $ldap_dn.");
        return;
    }
    else {
        detail("LDAP bind done for $ldap_dn.");
        progress("Searching LDAP for reverseProxyLookupTargets...");
        $result = $ldap->search( base => 'cn=zimbra', filter => '(zimbraReverseProxyLookupTarget=TRUE)', attrs => ['1.1'] );

        progress( ( $result->code() ) ? "failed.\n" : "done.\n" );
        return if ( $result->code() );
        $count = $result->count;
    }
    return "$count";
}

sub countUsers {
    return $main::loaded{stats}{numAccts}
      if ( exists $main::loaded{stats}{numAccts} );
    my $count           = 0;
    my $ldap_pass       = getLocalConfig("zimbra_ldap_password");
    my $ldap_master_url = getLocalConfig("ldap_master_url");
    my $ldap;
    my @masters    = split( / /, $ldap_master_url );
    my $master_ref = \@masters;
    unless ( $ldap = Net::LDAP->new($master_ref) ) {
        detail("Unable to contact $ldap_master_url.");
        return undef;
    }
    my $ldap_dn   = $config{zimbra_ldap_userdn};
    my $ldap_base = "";

    my $result = $ldap->bind( $ldap_dn, password => $ldap_pass );
    if ( $result->code() ) {
        detail("LDAP bind failed for $ldap_dn.");
        return undef;
    }
    else {
        detail("LDAP bind done for $ldap_dn.");
        progress("Searching LDAP for zimbra accounts...");
        $result = $ldap->search(
            filter => "(objectclass=zimbraAccount)",
            \attrs => ['zimbraMailDeliveryAddress']
        );
        progress( ( $result->code() ) ? "failed.\n" : "done.\n" );
        return undef if ( $result->code() );
        $count = $result->count;
    }
    $result = $ldap->unbind;
    $main::loaded{stats}{numAccts} = $count
      if ( $count > 0 );
    return ( ( $count > 0 ) ? "$count" : undef );
}

sub configCreateDomain {

    if ( $configStatus{configCreateDomain} eq "CONFIGURED" ) {
        configLog("configCreateDomain");
        return 0;
    }

    if ( !$ldapConfigured && isEnabled("carbonio-directory-server") ) {
        if ( $config{DOCREATEDOMAIN} eq "yes" ) {
            progress("Creating domain $config{CREATEDOMAIN}...");
            my $domainId = getLdapDomainValue("zimbraId");
            if ( $domainId ne "" ) {
                progress("already exists.\n");
            }
            else {
                my $rc = runAsZextras("$ZMPROV cd $config{CREATEDOMAIN}");
                progress( ( $rc == 0 ) ? "done.\n" : "failed.\n" );
            }

            progress("Setting default domain name...");
            my $rc = setLdapGlobalConfig( "zimbraDefaultDomainName", $config{CREATEDOMAIN} );
            progress( ( $rc == 0 ) ? "done.\n" : "failed.\n" );

            progress("Setting value of postfix myorigin...");
            my $rc = setLdapGlobalConfig( "zimbraMtaMyOrigin", $config{CREATEDOMAIN} );
            progress( ( $rc == 0 ) ? "done.\n" : "failed.\n" );
        }
    }
    if ( isEnabled("carbonio-appserver") ) {
        if ( $config{DOCREATEADMIN} eq "yes" ) {
            $config{CREATEADMIN} = lc( $config{CREATEADMIN} );
            my ( $u, $d ) = split( '@', $config{CREATEADMIN} );

            progress("Creating domain $d...");
            my $domainId = getLdapDomainValue( "zimbraId", $d );
            if ( $domainId ne "" ) {
                progress("already exists.\n");
            }
            else {
                my $rc = runAsZextras("$ZMPROV cd $d");
                progress( ( $rc == 0 ) ? "done.\n" : "failed.\n" );
            }

            progress("Creating admin account $config{CREATEADMIN}...");
            my $acctId = getLdapAccountValue( "zimbraId", $config{CREATEADMIN} );
            if ( $acctId ne "" ) {
                progress("already exists.\n");
            }
            else {
                my $rc = runAsZextras( "$ZMPROV ca " . "$config{CREATEADMIN} \'$config{CREATEADMINPASS}\' " . "zimbraAdminConsoleUIComponents cartBlancheUI " . "description \'Administrative Account\' " . "displayName \'Carbonio Admin\' " . "zimbraIsAdminAccount TRUE" );
                progress( ( $rc == 0 ) ? "done.\n" : "failed.\n" );
            }

            # no root/postmaster accounts on web-only nodes
            if ( isStoreServiceNode() ) {
                progress("Creating root alias...");
                my $rc = runAsZextras( "$ZMPROV aaa " . "$config{CREATEADMIN} root\@$config{CREATEDOMAIN}" );
                progress( ( $rc == 0 ) ? "done.\n" : "failed.\n" );

                progress("Creating postmaster alias...");
                $rc = runAsZextras( "$ZMPROV aaa " . "$config{CREATEADMIN} postmaster\@$config{CREATEDOMAIN}" );
                progress( ( $rc == 0 ) ? "done.\n" : "failed.\n" );
            }

            # set carbonioNotificationFrom & carbonioNotificationRecipients global config attributes
            progress("Setting infrastructure notification sender and recipients accounts...");
            my $rc = setLdapGlobalConfig( 'carbonioNotificationFrom', "$config{CREATEADMIN}", 'carbonioNotificationRecipients', "$config{CREATEADMIN}" );
            progress( ( $rc == 0 ) ? "done.\n" : "failed.\n" );
        }

        if ( $config{DOTRAINSA} eq "yes" ) {
            createSystemAccountIfMissing( "TRAINSASPAM", "System account for spam training.", "" );
            createSystemAccountIfMissing( "TRAINSAHAM", "System account for Non-Spam (Ham) training.", "" );
            createSystemAccountIfMissing( "VIRUSQUARANTINE", "System account for Anti-virus quarantine.", "zimbraMailMessageLifetime 30d" );

            progress("Setting spam, training and anti-virus quarantine accounts...");
            my $rc = setLdapGlobalConfig( 'zimbraSpamIsSpamAccount', "$config{TRAINSASPAM}", 'zimbraSpamIsNotSpamAccount', "$config{TRAINSAHAM}", 'zimbraAmavisQuarantineAccount', "$config{VIRUSQUARANTINE}" );
            progress( ( $rc == 0 ) ? "done.\n" : "failed.\n" );
        }
    }
    configLog("configCreateDomain");
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
        progress("Initializing mta config...");

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

sub configInitGALSyncAccts {

    if ( $configStatus{configInitGALSyncAccts} eq "CONFIGURED" ) {
        configLog("configInitGALSyncAccts");
        return 0;
    }

    return 1
      unless ( isEnabled("carbonio-directory-server") && $config{LDAPHOST} eq $config{HOSTNAME} );

    #if ($config{ENABLEGALSYNCACCOUNTS} eq "yes") {
    #progress("Creating galsync accounts in all domains...");
    #my $rc = runAsZextras("zmjava com.zimbra.cs.account.ldap.upgrade.LdapUpgrade -b 14531 -v");
    #progress(($rc == 0) ? "done.\n" : "failed.\n");
    #configLog("configInitGALSyncAccts") if ($rc == 0);
    #}
}

sub configCreateDefaultDomainGALSyncAcct {

    if ( $configStatus{configCreateDefaultGALSyncAcct} eq "CONFIGURED" ) {
        configLog("configCreateDefaultGALSyncAcct");
        return 0;
    }

    if ( isEnabled("carbonio-appserver") ) {
        progress("Creating galsync account for default domain...");
        my $_server  = getLocalConfig("zimbra_server_hostname");
        my $default_domain = ( ($newinstall) ? "$config{CREATEDOMAIN}" : "$config{zimbraDefaultDomainName}" );
        my $galsyncacct    = "galsync." . lc( genRandomPass() ) . '@' . $default_domain;
        my $rc             = runAsZextras("/opt/zextras/bin/zmgsautil createAccount -a $galsyncacct -n InternalGAL --domain $default_domain -s $_server -t zimbra -f _InternalGAL -p 1d");
        progress( ( $rc == 0 ) ? "done.\n" : "failed.\n" );
        configLog("configCreateDefaultDomainGALSyncAcct") if ( $rc == 0 );
    }
}

sub configSetEnabledServices {

    foreach my $p ( keys %installedPackages ) {
        if ( $p eq "carbonio-core" ) {
            push( @installedServiceList, ( 'zimbraServiceInstalled', 'stats' ) );
            next;
        }
        $p =~ s/carbonio-//;
        if ( $p eq "appserver" ) { $p = "mailbox"; }

        # do not push antivirus if already exists, required to enable support for single & multi-node installs
        if ( $p eq "clamav" && !grep( /^antivirus$/, @installedServiceList ) ) { $p = "antivirus"; }

        # do not add clamav as service, it is known as antivirus
        if ( $p eq "clamav" ) { next; }
        push( @installedServiceList, ( 'zimbraServiceInstalled', "$p" ) );
    }

    foreach my $p ( keys %enabledPackages ) {
        if ( $p eq "carbonio-core" ) {
            push( @enabledServiceList, ( 'zimbraServiceEnabled', 'stats' ) );
            next;
        }
        if ( $enabledPackages{$p} eq "Enabled" ) {
            $p =~ s/carbonio-//;
            if ( $p eq "appserver" ) {
                $p = "mailbox";

                # Add carbonio-appserver webapps to service list
                if ( $installedWebapps{$serviceWebApp} eq "Enabled" ) {
                    push( @enabledServiceList, 'zimbraServiceEnabled', "$serviceWebApp" );
                }
            }

            # do not push antivirus if already exists, required to enable support for single & multi-node installs
            if ( $p eq "clamav" && !grep( /^antivirus$/, @enabledServiceList ) ) { $p = "antivirus"; }

            # do not add clamav as service, it is known as antivirus
            if ( $p eq "clamav" ) { next; }
            push( @enabledServiceList, 'zimbraServiceEnabled', "$p" );
        }
    }

    progress("Setting services on $config{HOSTNAME}...");

    # add service-discover as enabled service if it was in zimbraServiceEnabled before.
    # service-discover is special case which is not handled by regular logic, since it
    # has no explicit package mapping. we also do not add it to installedServiceList
    # for the same reason.
    if ( $prevEnabledServices{"service-discover"} && $prevEnabledServices{"service-discover"} eq "Enabled" ) {
        detail("Restoring service-discover serviceEnabled state from previous install.");
        push( @enabledServiceList, ( 'zimbraServiceEnabled', 'service-discover' ) );
    }

    setLdapServerConfig( $config{HOSTNAME}, @installedServiceList );
    setLdapServerConfig( $config{HOSTNAME}, @enabledServiceList );
    progress("done.\n");

    my $rc = runAsZextras("/opt/zextras/libexec/zmiptool >/dev/null 2>/dev/null");

    configLog("configSetEnabledServices");
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

sub addServerToHostPool {
    progress("Adding $config{HOSTNAME} to MailHostPool in default COS...");
    my $id = getLdapServerValue( "zimbraId", $config{HOSTNAME} );
    my $hp = getLdapCOSValue("zimbraMailHostPool");

    if ( $id eq "" ) {
        progress("failed. Could not find a server entry for $config{HOSTNAME}.\n");
        return undef;
    }
    $hp .= ( ( $hp eq "" ) ? "$id" : "\n$id" );

    my %k;
    my @zmprov_args = ();
    foreach my $serverid ( split( /\n/, $hp ) ) {
        $k{$serverid} = 1;
    }
    foreach my $host ( keys %k ) {
        push( @zmprov_args, ( 'zimbraMailHostPool', $host ) );
    }
    my $rc = setLdapCOSConfig( 'default', @zmprov_args );
    progress( ( $rc == 0 ) ? "done.\n" : "failed.\n" );
}

sub mainMenu {
    my %mm = ();
    $mm{createsub} = \&createMainMenu;

    displayMenu( \%mm );
}

sub startLdap {
    my $rc;
    detail("Checking LDAP status...");
    if ( isSystemd() ) {
        $rc = isSystemdActiveUnit("carbonio-openldap.service");
    }
    else {
        $rc = runAsZextras("/opt/zextras/bin/ldap status");
    }
    detail( ( $rc == 0 ) ? "already running.\n" : "not running.\n" );

    if ($rc) {
        progress("Starting LDAP...");
        if ( isSystemd() ) {
            $rc = system("systemctl start carbonio-openldap.service");
        }
        else {
            $rc = runAsZextras("/opt/zextras/bin/ldap start");
        }
        progress( ( $rc == 0 ) ? "done.\n" : "failed with exit code: $rc.\n" );
    }
    return $rc;
}

sub stopLdap {
    my $rc;
    detail("Checking LDAP status...");
    if ( isSystemd() ) {
        $rc = isSystemdActiveUnit("carbonio-openldap.service");
    }
    else {
        $rc = runAsZextras("/opt/zextras/bin/ldap status");
    }
    detail( ( $rc == 0 ) ? "already stopped.\n" : "running.\n" );

    if ($rc) {
        progress("Stopping LDAP...");
        if ( isSystemd() ) {
            $rc = system("systemctl stop carbonio-openldap.service");
        }
        else {
            $rc = runAsZextras("/opt/zextras/bin/ldap stop");
        }
        progress( ( $rc == 0 ) ? "done.\n" : "failed with exit code: $rc.\n" );
    }
    return $rc;
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

sub dumpConfig {
    foreach my $key ( sort keys %config ) {
        print "\tDEBUG: $key=$config{$key}\n";
    }
}

sub mainMenuExtensions {
    my ( $mm, $i ) = (@_);
    return $i;
}

### end subs

__END__
