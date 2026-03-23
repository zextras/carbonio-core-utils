#!/usr/bin/perl
#
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

package Zextras::Setup::Menu;
use strict;
use warnings;
use NetAddr::IP;
use Exporter 'import';
use Zextras::Setup::LDAP;
use Zextras::Setup::DNS;

our @EXPORT = qw(
    addMenuItem
    updatePasswordDisplayStatus
    genPackageMenu
    genSubMenu
    displaySubMenuItems
    menuSort
    displayMenu
    checkMenuConfig
    verifyQuit
    mainMenu
    mainMenuExtensions
    ask
    askPassword
    askYN
    askTF
    askNum
    askPositiveInt
    askNonBlank
    askFileName
    askDomainUserHelper
    createMainMenu
    createCommonMenu
    createLdapMenu
    createLdapUsersMenu
    createMtaMenu
    createProxyMenu
    createStoreMenu
    createPackageMenu
    setCreateDomain
    setCreateAdmin
    setHostName
    setSmtpHost
    setLdapHost
    setLdapPort
    setLdapServerID
    setLdapReplicationType
    setLdapBaseDN
    setLdapRootPass
    setLdapAdminPass
    setLdapRepPass
    setLdapPostPass
    setLdapAmavisPass
    setLdapNginxPass
    setSmtpSource
    setSmtpDest
    setAvUser
    setNotebookAccount
    setTrainSASpam
    setTrainSAHam
    setAmavisVirusQuarantine
    setStoreMode
    setProxyMode
    setUseProxy
    setPublicServiceHostname
    setImapProxyPort
    setImapSSLProxyPort
    setPopProxyPort
    setPopSSLProxyPort
    setHttpProxyPort
    setHttpsProxyPort
    setTimeZone
    setIPMode
    setSSLDefaultDigest
    setEnabledDependencies
    setProxyPortHelper
    setEmailDomain
    updateEmailDomain
    toggleYN
    toggleTF
    toggleConfigEnabled
    toggleMailProxy
    toggleWebProxy
    toggleEnabled
    resolvePortPairCollision
    resolvePortOffsetCollision
    resolveMailPortPairCollisions
    resolveHttpPortPairCollisions
    resolveMailPortOffsetCollisions
    resolveHttpPortOffsetCollisions
    changeLdapHost
    changeLdapPort
    changeLdapServerID
    changePublicServiceHostname
    validEmailAddress
    validIPAddress
    removeUnusedWebapps
);

# --- Input helpers ---

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
    $rc //= "";
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

# Helper to ask for domain-validated user account - consolidates 4 nearly identical functions
sub askDomainUserHelper {
    my ( $prompt, $configKey ) = @_;
    while (1) {
        my $new = ask( $prompt, $main::config{$configKey} );
        my ( $u, $d ) = split( '@', $new );
        my ( $adminUser, $adminDomain ) = split( '@', $main::config{CREATEADMIN} );
        if ( $d ne $main::config{CREATEDOMAIN} && $d ne $adminDomain ) {
            if ( $main::config{CREATEDOMAIN} eq $adminDomain ) {
                main::progress("You must create the user under the domain $main::config{CREATEDOMAIN}\n");
            }
            else {
                main::progress("You must create the user under the domain $main::config{CREATEDOMAIN} or $adminDomain\n");
            }
        }
        else {
            $main::config{$configKey} = $new;
            last;
        }
    }
}

# --- Core menu helpers ---

# Helper to update password display status for menu (UNSET, set, or Not Verified)
sub updatePasswordDisplayStatus {
    my ( $passKey, $passSetKey ) = @_;
    if ( $main::config{$passKey} eq "" ) {
        $main::config{$passSetKey} = "UNSET";
    }
    else {
        $main::config{$passSetKey} = "set" unless ( $main::config{$passSetKey} eq "Not Verified" );
    }
}

# Helper to add a menu item - reduces boilerplate
sub addMenuItem {
    my ( $lm, $i_ref, $prompt, $varKey, $callback, $arg ) = @_;
    $$lm{menuitems}{$$i_ref} = {
        "prompt"   => $prompt,
        "var"      => \$main::config{$varKey},
        "callback" => $callback,
    };
    $$lm{menuitems}{$$i_ref}{"arg"} = $arg if defined $arg;
    $$i_ref++;
}

# --- Email domain helpers ---

# Helper to update email address domain - used when domain changes
sub updateEmailDomain {
    my ( $configKey, $newDomain, $oldDomain ) = @_;
    my ( $user, $domain ) = split( '@', $main::config{$configKey} );
    return if !defined $oldDomain;    # unconditional update
    return if $domain ne $oldDomain;  # conditional: only if old domain matches
    $main::config{$configKey} = $user . '@' . $newDomain;
}

# Helper to unconditionally update email domain
sub setEmailDomain {
    my ( $configKey, $newDomain ) = @_;
    my ( $user, $domain ) = split( '@', $main::config{$configKey} );
    $main::config{$configKey} = $user . '@' . $newDomain;
}

# --- Port collision helpers ---

# Helper to resolve port collision for a port/proxy pair
# When proxyEnabled: port gets alternate at standard, proxy gets standard at alternate
# When !proxyEnabled: proxy gets alternate at standard, port gets standard at alternate
sub resolvePortPairCollision {
    my ( $portKey, $proxyKey, $standardVal, $alternateVal, $proxyEnabled ) = @_;
    return unless $main::config{$portKey} == $main::config{$proxyKey};
    if ( $main::config{$portKey} == $standardVal ) {
        if ($proxyEnabled) { $main::config{$portKey} = $alternateVal; }
        else               { $main::config{$proxyKey} = $alternateVal; }
    }
    elsif ( $main::config{$portKey} == $alternateVal ) {
        if ($proxyEnabled) { $main::config{$proxyKey} = $standardVal; }
        else               { $main::config{$portKey} = $standardVal; }
    }
}

# Helper to resolve port collision using offset-based logic for setUseProxy
# When proxyEnabled=1: if ports equal, add offset to port; if port+offset==proxy, swap with subtract
# When proxyEnabled=0: if proxy+offset==port, swap with add
sub resolvePortOffsetCollision {
    my ( $portKey, $proxyKey, $offset, $proxyEnabled ) = @_;
    if ($proxyEnabled) {
        if ( $main::config{$proxyKey} == $main::config{$portKey} ) {
            $main::config{$portKey} = $offset + $main::config{$proxyKey};
        }
        if ( $main::config{$portKey} + $offset == $main::config{$proxyKey} ) {
            $main::config{$portKey}  = $main::config{$proxyKey};
            $main::config{$proxyKey} = $main::config{$proxyKey} - $offset;
        }
    }
    else {
        if ( $main::config{$proxyKey} + $offset == $main::config{$portKey} ) {
            $main::config{$portKey}  = $main::config{$proxyKey};
            $main::config{$proxyKey} = $main::config{$proxyKey} + $offset;
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

# --- LDAP host/port change helpers ---

sub changeLdapHost {
    $main::config{LDAPHOST} = shift;
    $main::config{LDAPHOST} = lc( $main::config{LDAPHOST} );
    if ( main::isInstalled("carbonio-directory-server") && $main::config{LDAPHOST} eq "" ) {
        $main::ldapReplica = 0;
        $main::config{LDAPREPLICATIONTYPE} = "master";
    }
    elsif ( main::isInstalled("carbonio-directory-server") && $main::config{LDAPHOST} ne $main::config{HOSTNAME} ) {
        $main::ldapReplica = 1;
        $main::config{LDAPREPLICATIONTYPE} = "replica";
    }
    elsif ( main::isInstalled("carbonio-directory-server") && $main::config{LDAPHOST} eq $main::config{HOSTNAME} ) {
        $main::ldapReplica = 0;
        $main::config{LDAPREPLICATIONTYPE} = "master";
    }
}

sub changeLdapPort {
    $main::config{LDAPPORT} = shift;
}

sub changeLdapServerID {
    $main::config{LDAPSERVERID} = shift;
}

sub changePublicServiceHostname {
    $main::config{PUBLICSERVICEHOSTNAME} = shift;
}

# --- Validation helpers ---

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

sub removeUnusedWebapps {
    main::defineInstallWebapps();
}

# --- Interactive setters (menu callbacks) ---

sub setCreateDomain {
    my $oldDomain = $main::config{CREATEDOMAIN};
    my $good      = 0;
    while (1) {
        $main::config{CREATEDOMAIN} = ask( "Create domain:", $main::config{CREATEDOMAIN} );
        my $ans = getDnsRecords( $main::config{CREATEDOMAIN}, 'MX' );
        if ( !defined($ans) ) {
            main::progress("\n\nDNS ERROR - resolving \"MX\" for $main::config{CREATEDOMAIN}\n");
            main::progress("It is suggested that the domain name have an \"MX\" record configured in DNS.\n");
            if ( askYN( "Re-Enter domain name?", "Yes" ) eq "no" ) {
                last;
            }
            $main::config{CREATEDOMAIN} = $oldDomain;
            next;
        }
        elsif ( main::isEnabled("carbonio-mta") ) {
            $good = validateMxRecords( $main::config{CREATEDOMAIN}, $ans, \@main::interfaces );
            if ($good) { last; }
            else {
                main::progress("\n\nDNS ERROR - none of the \"MX\" records for $main::config{CREATEDOMAIN}\n");
                main::progress("resolve to this host\n");
                main::progress("It is suggested that the \"MX\" record resolve to this host.\n");
                if ( askYN( "Re-Enter domain name?", "Yes" ) eq "no" ) {
                    last;
                }
                $main::config{CREATEDOMAIN} = $oldDomain;
                next;
            }
        }
        last;
    }
    my $oldAdmin = $main::config{CREATEADMIN};
    setEmailDomain( 'CREATEADMIN', $main::config{CREATEDOMAIN} );

    $main::config{AVUSER}   = $main::config{CREATEADMIN} if ( $oldAdmin eq $main::config{AVUSER} );
    $main::config{AVDOMAIN} = $main::config{CREATEDOMAIN} if ( $main::config{AVDOMAIN} eq $oldDomain );
    $main::config{SMTPDEST}   = $main::config{CREATEADMIN} if ( $oldAdmin eq $main::config{SMTPDEST} );
    $main::config{SMTPSOURCE} = $main::config{CREATEADMIN} if ( $oldAdmin eq $main::config{SMTPSOURCE} );

    updateEmailDomain( 'TRAINSASPAM',     $main::config{CREATEDOMAIN}, $oldDomain );
    updateEmailDomain( 'TRAINSAHAM',      $main::config{CREATEDOMAIN}, $oldDomain );
    updateEmailDomain( 'VIRUSQUARANTINE', $main::config{CREATEDOMAIN}, $oldDomain );
}

sub setLdapBaseDN {
    while (1) {
        print "Warning: Do not change this from the default value unless\n";
        print "you are absolutely sure you know what you are doing!\n\n";
        my $new = askNonBlank( "Ldap base DN:", $main::config{ldap_dit_base_dn_config} );
        if ( $main::config{ldap_dit_base_dn_config} ne $new ) {
            $main::config{ldap_dit_base_dn_config} = $new;
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
        my $new = ask( "Create admin user:", $main::config{CREATEADMIN} );
        my ( $u, $d ) = split( '@', $new );

        unless ( validEmailAddress($new) ) {
            main::progress("Admin user must be a valid email account [$u\@$main::config{CREATEDOMAIN}]\n");
            next;
        }

        # spam/ham/quanrantine accounts follow admin domain if ldap isn't install
        # this prevents us from trying to provision in a non-existent domain
        if ( !main::isEnabled("carbonio-directory-server") ) {
            my ( $spamUser,  $spamDomain )  = split( '@', $main::config{TRAINSASPAM} );
            my ( $hamUser,   $hamDomain )   = split( '@', $main::config{TRAINSAHAM} );
            my ( $virusUser, $virusDomain ) = split( '@', $main::config{VIRUSQUARANTINE} );
            $main::config{CREATEDOMAIN} = $d
              if ( $main::config{CREATEDOMAIN} ne $d );

            $main::config{TRAINSASPAM} = $spamUser . '@' . $d
              if ( $spamDomain ne $d );

            $main::config{TRAINSAHAM} = $hamUser . '@' . $d
              if ( $hamDomain ne $d );

            $main::config{VIRUSQUARANTINE} = $virusUser . '@' . $d
              if ( $virusDomain ne $d );

            $main::config{AVDOMAIN} = $d
              if ( $main::config{AVDOMAIN} ne $d );
        }

        if ( $main::config{CREATEADMIN} eq $main::config{AVUSER} ) {
            $main::config{AVUSER} = $new;
        }
        if ( $main::config{CREATEADMIN} eq $main::config{SMTPDEST} ) {
            $main::config{SMTPDEST} = $new;
        }
        if ( $main::config{CREATEADMIN} eq $main::config{SMTPSOURCE} ) {
            $main::config{SMTPSOURCE} = $new;
        }
        $main::config{CREATEADMIN} = $new;
        last;
    }
}

sub setHostName {
    my $old = $main::config{HOSTNAME};
    while (1) {
        $main::config{HOSTNAME} = askNonBlank( "Please enter the logical hostname for this host", $main::config{HOSTNAME} );
        if ( lookupHostName( $main::config{HOSTNAME}, 'A' ) ) {
            main::progress("\n\nDNS ERROR - resolving $main::config{HOSTNAME}\n");
            main::progress("It is recommended that the hostname be resolvable via DNS and the resolved IP address not point to a loopback device.\n");
            if ( askYN( "Re-Enter hostname", "Yes" ) eq "no" ) {
                last;
            }
            $main::config{HOSTNAME} = $old;
        }
        else { last; }
    }
    $main::config{HOSTNAME} = lc( $main::config{HOSTNAME} );
    if ( $main::config{SMTPHOST} eq $old ) {
        $main::config{SMTPHOST} = $main::config{HOSTNAME};
    }
    if ( $main::config{LDAPHOST} eq $old ) {
        changeLdapHost( $main::config{HOSTNAME} );
    }
    if ( $main::config{CREATEDOMAIN} eq $old ) {
        $main::config{CREATEDOMAIN} = $main::config{HOSTNAME};
        $main::config{AVDOMAIN}     = $main::config{CREATEDOMAIN};
        setEmailDomain( 'CREATEADMIN',     $main::config{CREATEDOMAIN} );
        setEmailDomain( 'AVUSER',          $main::config{CREATEDOMAIN} );
        setEmailDomain( 'TRAINSASPAM',     $main::config{CREATEDOMAIN} );
        setEmailDomain( 'TRAINSAHAM',      $main::config{CREATEDOMAIN} );
        setEmailDomain( 'VIRUSQUARANTINE', $main::config{CREATEDOMAIN} );
    }
    updateEmailDomain( 'SMTPSOURCE', $main::config{CREATEDOMAIN}, $old );
    updateEmailDomain( 'SMTPDEST',   $main::config{CREATEDOMAIN}, $old );
}

sub setSmtpHost {
    $main::config{SMTPHOST} = askNonBlank( "Please enter the SMTP server hostname:", $main::config{SMTPHOST} );
}

sub setLdapHost {
    changeLdapHost( askNonBlank( "Please enter the ldap server hostname:", $main::config{LDAPHOST} ) );
}

sub setLdapPort {
    changeLdapPort( askNum( "Please enter the ldap server port:", $main::config{LDAPPORT} ) );
}

sub setLdapServerID {
    changeLdapServerID( askPositiveInt( "Please enter the ldap Server ID:", $main::config{LDAPSERVERID} ) );
}

sub setLdapReplicationType {
    while (1) {
        my $m = askNonBlank( "Please enter the LDAP replication type (replica, mmr)", $main::config{LDAPREPLICATIONTYPE} );
        if ( $m eq "replica" || $m eq "mmr" ) {
            $main::config{LDAPREPLICATIONTYPE} = $m;
            return;
        }
        print "Please enter a valid replication type!\n";
    }
}

sub setLdapRootPass {
    askLdapPasswordHelper( "ldap root user", "LDAPROOTPASS", \$main::ldapRootPassChanged, 0 );
}

sub setLdapAdminPass {
    askLdapPasswordHelper( "ldap admin user", "LDAPADMINPASS", \$main::ldapAdminPassChanged, 1 );
}

sub setLdapRepPass {
    askLdapPasswordHelper( "ldap replication user", "LDAPREPPASS", \$main::ldapRepChanged, 1 );
}

sub setLdapPostPass {
    askLdapPasswordHelper( "ldap postfix user", "LDAPPOSTPASS", \$main::ldapPostChanged, 1 );
}

sub setLdapAmavisPass {
    askLdapPasswordHelper( "ldap Amavis user", "LDAPAMAVISPASS", \$main::ldapAmavisChanged, 1 );
}

sub setLdapNginxPass {
    askLdapPasswordHelper( "ldap Nginx user", "ldap_nginx_password", \$main::ldapNginxChanged, 1 );
}

sub setSmtpSource {
    $main::config{SMTPSOURCE} = askNonBlank( "SMTP Source address:", $main::config{SMTPSOURCE} );
}

sub setSmtpDest {
    $main::config{SMTPDEST} = askNonBlank( "SMTP Destination address:", $main::config{SMTPDEST} );
}

sub setAvUser {
    $main::config{AVUSER} = askNonBlank( "Notification address for AV alerts:", $main::config{AVUSER} );
    ( undef, $main::config{AVDOMAIN} ) = ( split( '@', $main::config{AVUSER} ) )[1];
}

# Helper to set proxy port - consolidates 6 nearly identical functions
sub setProxyPortHelper {
    my ( $prompt, $proxyKey, $backendKey, $proxyTypeKey ) = @_;
    $main::config{$proxyKey} = askNum( "Please enter the $prompt:", $main::config{$proxyKey} );
    if ( $main::config{$proxyTypeKey} eq "TRUE" || $main::config{zimbraMailProxy} eq "TRUE" ) {
        $main::config{$backendKey} = "UNSET" if ( $main::config{$proxyKey} == $main::config{$backendKey} );
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
    my $old = $main::config{PUBLICSERVICEHOSTNAME};
    while (1) {
        $main::config{PUBLICSERVICEHOSTNAME} = askNonBlank( "Please enter the Public Service hostname (FQDN):", $main::config{PUBLICSERVICEHOSTNAME} );
        if ( $main::config{PUBLICSERVICEHOSTNAME} ne $old ) {
            $main::publicServiceHostnameAlreadySet = 0;
        }
        if ( lookupHostName( $main::config{PUBLICSERVICEHOSTNAME}, 'A' ) ) {
            main::progress("\n\nDNS ERROR - resolving $main::config{PUBLICSERVICEHOSTNAME}\n");
            main::progress("It is suggested that the Public Service Hostname be resolvable via DNS.\n");
            if ( askYN( "Re-Enter Public Service Hostname", "Yes" ) eq "no" ) {
                last;
            }
            $main::config{PUBLICSERVICEHOSTNAME} = $old;
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
        main::detail("Loading default list of timezones.\n");
        my $tz = new Zextras::Util::Timezone;
        $tz->parse;

        my $new;

        # build a hash of the timezone objects with a unique number as the value
        my %TZID = undef;
        my $ctr  = 1;
        $TZID{$_} = $ctr++ foreach sort $tz->dump;
        my %RTZID = reverse %TZID;

        # get a reference to the default value or attempt to lookup the system locale.
        main::detail("Previous TimeZoneID: $main::config{zimbraPrefTimeZoneId}.\n");
        my $ltzref = $tz->gettzbyid("$main::config{zimbraPrefTimeZoneId}");
        unless ( defined $ltzref ) {
            main::detail("Determining system locale.\n");
            my $localtzname = qx(/bin/date '+%Z');
            chomp($localtzname);
            main::detail("DEBUG: Local timezone name: $localtzname.\n");
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
        $main::config{zimbraPrefTimeZoneId} = $new;
    }
}

sub setIPMode {
    while (1) {
        my $new = askPassword( "IP Mode (ipv4, both, ipv6):", $main::config{zimbraIPMode} );
        if ( $new eq "ipv4" || $new eq "both" || $new eq "ipv6" ) {
            if ( $main::config{zimbraIPMode} ne $new ) {
                $main::config{zimbraIPMode} = $new;
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
        my $new         = askPassword( "Default OpenSSL digest:", $main::config{ssl_default_digest} );
        my $ssl_digests = join( ' ', @main::ssl_digests );
        if ( $ssl_digests =~ /\b$new\b/ ) {
            if ( $main::config{ssl_default_digest} ne $new ) {
                $main::config{ssl_default_digest} = $new;
            }
            return;
        }
        else {
            print "Valid digest modes are: $ssl_digests!\n";
        }
    }
}

sub setUseProxy {
    if ( main::isEnabled("carbonio-proxy") ) {
        my $mailProxyEnabled = ( $main::config{MAILPROXY} eq "TRUE" );
        my $httpProxyEnabled = ( $main::config{HTTPPROXY} eq "TRUE" );
        resolveMailPortOffsetCollisions($mailProxyEnabled);
        resolveHttpPortOffsetCollisions($httpProxyEnabled);
    }
    else {
        if ( !main::isInstalled("carbonio-appserver") ) {
            resolveMailPortOffsetCollisions(0);
            resolveHttpPortOffsetCollisions(0);
        }
        else {
            my $mailProxyEnabled = ( $main::config{zimbraMailProxy} eq "TRUE" );
            my $httpProxyEnabled = ( $main::config{zimbraWebProxy} eq "TRUE" );
            resolveMailPortOffsetCollisions($mailProxyEnabled);
            resolveHttpPortOffsetCollisions($httpProxyEnabled);
        }
    }
}

sub setStoreMode {
    while (1) {
        my $m = askNonBlank( "Please enter the web server mode (http,https,both,mixed,redirect)", $main::config{MODE} );
        if ( main::isInstalled("carbonio-proxy") ) {
            if ( $main::config{zimbra_require_interprocess_security} ) {
                if ( $m eq "https" || $m eq "both" ) {
                    $main::config{MODE} = $m;
                    return;
                }
                else {
                    print qq(Only "https" and "both" are valid modes when requiring interprocess security with web proxy.\n);
                }
            }
            else {
                if ( $m eq "http" || $m eq "both" ) {
                    $main::config{MODE} = $m;
                    return;
                }
                else {
                    print qq(Only "http" and "both" are valid modes when not requiring interprocess security with web proxy.\n);
                }
            }
        }
        else {
            my @proxytargets;
            open( ZMPROV, "$main::ZMPROV gas proxy 2>/dev/null|" );
            chomp( @proxytargets = <ZMPROV> );
            close(ZMPROV);
            if ( scalar @proxytargets ) {
                if ( $main::config{zimbra_require_interprocess_security} ) {
                    if ( $m eq "https" || $m eq "both" ) {
                        $main::config{MODE} = $m;
                        return;
                    }
                    else {
                        print qq(Only "https" and "both" are valid modes when requiring interprocess security with web proxy.\n);
                    }
                }
                else {
                    if ( $m eq "http" || $m eq "both" ) {
                        $main::config{MODE} = $m;
                        return;
                    }
                    else {
                        print qq(Only "http" and "both" are valid modes when not requiring interprocess security with web proxy.\n);
                    }
                }
            }
            else {
                if ( $m eq "http" || $m eq "https" || $m eq "mixed" || $m eq "both" || $m eq "redirect" ) {
                    $main::config{MODE} = $m;
                    return;
                }
            }
        }
        print "Please enter a valid mode!\n";
    }
}

sub setProxyMode {
    while (1) {
        my $m = askNonBlank( "Please enter the proxy server mode (https,redirect)", $main::config{PROXYMODE} );
        if ( $main::config{zimbra_require_interprocess_security} ) {
            if ( $m eq "https" || $m eq "redirect" ) {
                $main::config{PROXYMODE} = $m;
                return;
            }
            else {
                print qq(Only "https" and "redirect" are valid modes when requiring interprocess security with web proxy.\n);
            }
        }
        else {
            if ( $m eq "https" || $m eq "redirect" ) {
                $main::config{PROXYMODE} = $m;
                return;
            }
        }
        print "Please enter a valid mode!\n";
    }
}

sub setEnabledDependencies {
    if ( main::isEnabled("carbonio-directory-server") ) {
        if ( $main::config{LDAPHOST} eq "" ) {
            changeLdapHost( $main::config{HOSTNAME} );
        }
    }
    else {
        if ( $main::config{LDAPHOST} eq $main::config{HOSTNAME} ) {
            changeLdapHost("");
            $main::config{LDAPADMINPASS} = "";
            $main::config{LDAPROOTPASS}  = "";
        }
    }

    if ( main::isEnabled("carbonio-appserver") ) {
        if ( main::isEnabled("carbonio-mta") ) {
            $main::config{SMTPHOST} = $main::config{HOSTNAME};
        }
        if ( $main::config{zimbraMailProxy} eq "TRUE" || $main::config{zimbraWebProxy} eq "TRUE" ) {
            setUseProxy();
        }
    }

    if ( main::isEnabled("carbonio-mta") ) {
        if ($main::newinstall) {
            $main::config{RUNAV}        = ( main::isServiceEnabled("antivirus") ? "yes" : "no" );
            $main::config{RUNSA}        = "yes";
            $main::config{RUNDKIM}      = "yes";
            $main::config{RUNCBPOLICYD} = "no";
        }
        else {
            $main::config{RUNSA} = ( main::isServiceEnabled("antispam")  ? "yes" : "no" );
            $main::config{RUNAV} = ( main::isServiceEnabled("antivirus") ? "yes" : "no" );
            if ( $main::config{RUNDKIM} ne "yes" ) {
                $main::config{RUNDKIM} = ( main::isServiceEnabled("opendkim") ? "yes" : "no" );
            }
            $main::config{RUNCBPOLICYD} = ( main::isServiceEnabled("cbpolicyd") ? "yes" : "no" );
        }
    }

    if ( main::isEnabled("carbonio-clamav") ) {
        if ($main::newinstall) {
            $main::config{RUNAV} = "yes";
        }
        else {
            $main::config{RUNAV} = ( main::isServiceEnabled("antivirus") ? "yes" : "no" );
        }
    }

    if ( main::isInstalled("carbonio-proxy") ) {
        setUseProxy();
    }
}

# --- Toggle callbacks ---

sub toggleYN {
    my $key = shift;
    $main::config{$key} = ( $main::config{$key} eq "yes" ) ? "no" : "yes";
}

sub toggleTF {
    my $key = shift;
    $main::config{$key} = ( $main::config{$key} eq "TRUE" ) ? "FALSE" : "TRUE";
    if ( $key eq "MAILPROXY" ) {
        &toggleMailProxy();
    }
    if ( $key eq "HTTPPROXY" ) {
        &toggleWebProxy();
    }
}

sub toggleConfigEnabled {
    my $key = shift;
    $main::config{$key} = ( $main::config{$key} eq "Enabled" ) ? "Disabled" : "Enabled";
}

sub toggleMailProxy() {
    if ( $main::config{MAILPROXY} eq "TRUE" ) {
        $main::config{IMAPPORT}         = 7143;
        $main::config{IMAPSSLPORT}      = 7993;
        $main::config{POPPORT}          = 7110;
        $main::config{POPSSLPORT}       = 7995;
        $main::config{IMAPPROXYPORT}    = 143;
        $main::config{IMAPSSLPROXYPORT} = 993;
        $main::config{POPPROXYPORT}     = 110;
        $main::config{POPSSLPROXYPORT}  = 995;
    }
    else {
        $main::config{IMAPPORT}         = 143;
        $main::config{IMAPSSLPORT}      = 993;
        $main::config{POPPORT}          = 110;
        $main::config{POPSSLPORT}       = 995;
        $main::config{IMAPPROXYPORT}    = 7143;
        $main::config{IMAPSSLPROXYPORT} = 7993;
        $main::config{POPPROXYPORT}     = 7110;
        $main::config{POPSSLPROXYPORT}  = 7995;
    }
}

sub toggleWebProxy() {
    if ( $main::config{HTTPPROXY} eq "TRUE" ) {
        $main::config{HTTPPORT}       = 8080;
        $main::config{HTTPSPORT}      = 8443;
        $main::config{HTTPPROXYPORT}  = 80;
        $main::config{HTTPSPROXYPORT} = 443;
    }
    else {
        $main::config{HTTPPORT}       = 80;
        $main::config{HTTPSPORT}      = 443;
        $main::config{HTTPPROXYPORT}  = 8080;
        $main::config{HTTPSPROXYPORT} = 8443;
    }
}

sub toggleEnabled {
    my $p = shift;
    $main::enabledPackages{$p} = ( main::isEnabled($p) ) ? "Disabled" : "Enabled";
    setEnabledDependencies();
}

# --- Core menu engine ---

sub verifyQuit {
    if ( askYN( "Quit without applying changes?", "No" ) eq "yes" ) { return 1; }
    return 0;
}

sub genPackageMenu {
    my $package = shift;
    my %lm      = ();
    $lm{menuitems}{1} = {
        "prompt"   => "Status:",
        "var"      => \$main::enabledPackages{$package},
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

sub menuSort {
    if ( ( $a eq int($a) ) && ( $b eq int($b) ) ) {
        return $a <=> $b;
    }
    return $a cmp $b;
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
            if ( $main::config{EXPANDMENU} eq "yes" || !$subMenuCheck ) {
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
        $r //= "";
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
                if ( $$items{menuitems}{$i}{var} == \$main::config{$var} ) {
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
        return 1 if ( $main::config{LDAPHOST} eq $main::config{HOSTNAME} && !$main::ldapConfigured );
        return 0 if ( !ldapIsAvailable() );
    }
    if ( defined( $main::installedPackages{"carbonio-appserver"} ) && $main::config{SERVICEWEBAPP} eq "no" ) {
        $main::config{SERVICEWEBAPP} = "UNSET";
        return 0;
    }
    return 1;
}

# --- Menu builder functions ---

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
    if ( !defined( $main::installedPackages{"carbonio-directory-server"} ) ) {
        addMenuItem( $lm, \$i, "LDAP Base DN:", 'ldap_dit_base_dn_config', \&setLdapBaseDN );
    }

    # interprocess security
    addMenuItem( $lm, \$i, "Secure interprocess communications:", 'ZIMBRA_REQ_SECURITY', \&toggleYN, "ZIMBRA_REQ_SECURITY" );
    if ( $main::config{ZIMBRA_REQ_SECURITY} eq "yes" ) {
        $main::config{zimbra_require_interprocess_security} = 1;
    }
    else {
        $main::config{zimbra_require_interprocess_security} = 0;
        $main::starttls = 0;
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
    if ( main::isEnabled($package) ) {
        addMenuItem( $lm, \$i, "Create Domain:", 'DOCREATEDOMAIN', \&toggleYN, "DOCREATEDOMAIN" );
        if ( $main::config{DOCREATEDOMAIN} eq "yes" ) {
            addMenuItem( $lm, \$i, "Domain to create:", 'CREATEDOMAIN', \&setCreateDomain );
        }

        if ( $main::config{LDAPREPLICATIONTYPE} ne "master" ) {
            addMenuItem( $lm, \$i, "Ldap replication type:", 'LDAPREPLICATIONTYPE', \&setLdapReplicationType );
        }
        if ( $main::config{LDAPREPLICATIONTYPE} eq "mmr" ) {
            addMenuItem( $lm, \$i, "Ldap Server ID:", 'LDAPSERVERID', \&setLdapServerID );
        }

        # LDAPROOTPASS has inverted logic: "Not Verified" preserved when empty
        if ( $main::config{LDAPROOTPASS} ne "" ) {
            $main::config{LDAPROOTPASSSET} = "set";
        }
        else {
            $main::config{LDAPROOTPASSSET} = "UNSET" unless ( $main::config{LDAPROOTPASSSET} eq "Not Verified" );
        }
        addMenuItem( $lm, \$i, "Ldap root password:", 'LDAPROOTPASSSET', \&setLdapRootPass );

        updatePasswordDisplayStatus( 'LDAPREPPASS', 'LDAPREPPASSSET' );
        addMenuItem( $lm, \$i, "Ldap replication password:", 'LDAPREPPASSSET', \&setLdapRepPass );

        if ( $main::config{HOSTNAME} eq $main::config{LDAPHOST} || $main::config{LDAPREPLICATIONTYPE} ne "replica" || main::isEnabled("carbonio-mta") ) {
            updatePasswordDisplayStatus( 'LDAPPOSTPASS', 'LDAPPOSTPASSSET' );
            addMenuItem( $lm, \$i, "Ldap postfix password:", 'LDAPPOSTPASSSET', \&setLdapPostPass );

            updatePasswordDisplayStatus( 'LDAPAMAVISPASS', 'LDAPAMAVISPASSSET' );
            addMenuItem( $lm, \$i, "Ldap amavis password:", 'LDAPAMAVISPASSSET', \&setLdapAmavisPass );
        }
        if ( $main::config{HOSTNAME} eq $main::config{LDAPHOST} || $main::config{LDAPREPLICATIONTYPE} ne "replica" || main::isEnabled("carbonio-proxy") ) {
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

    $$lm{title} = "MTA configuration";

    $$lm{createsub} = \&createMtaMenu;
    $$lm{createarg} = $package;

    my $i = 2;
    if ( main::isEnabled($package) ) {
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
    if ( main::isInstalled($package) ) {
        addMenuItem( $lm, \$i, "Public Service Hostname:",               'PUBLICSERVICEHOSTNAME',   \&setPublicServiceHostname );
        addMenuItem( $lm, \$i, "Enable POP/IMAP Proxy:",                 'MAILPROXY',               \&toggleTF, "MAILPROXY" );
        addMenuItem( $lm, \$i, "Enable strict server name enforcement?", 'STRICTSERVERNAMEENABLED', \&toggleYN, "STRICTSERVERNAMEENABLED" );

        if ( $main::config{MAILPROXY} eq "TRUE" ) {
            addMenuItem( $lm, \$i, "IMAP proxy port:",     'IMAPPROXYPORT',    \&setImapProxyPort );
            addMenuItem( $lm, \$i, "IMAP SSL proxy port:", 'IMAPSSLPROXYPORT', \&setImapSSLProxyPort );
            addMenuItem( $lm, \$i, "POP proxy port:",      'POPPROXYPORT',     \&setPopProxyPort );
            addMenuItem( $lm, \$i, "POP SSL proxy port:",  'POPSSLPROXYPORT',  \&setPopSSLProxyPort );
        }
        if ( $main::config{HTTPPROXY} eq "TRUE" || $main::config{MAILPROXY} eq "TRUE" ) {
            updatePasswordDisplayStatus( 'ldap_nginx_password', 'LDAPNGINXPASSSET' );
            addMenuItem( $lm, \$i, "Bind password for nginx ldap user:", 'LDAPNGINXPASSSET', \&setLdapNginxPass );
        }
        addMenuItem( $lm, \$i, "Enable HTTP[S] Proxy:", 'HTTPPROXY', \&toggleTF, "HTTPPROXY" );

        if ( $main::config{HTTPPROXY} eq "TRUE" ) {
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
    if ( main::isEnabled($package) ) {
        addMenuItem( $lm, \$i, "Create Admin User:", 'DOCREATEADMIN', \&toggleYN, "DOCREATEADMIN" );

        my $ldap_virusquarantine = getLdapConfigValue("zimbraAmavisQuarantineAccount")
          if ( ldapIsAvailable() );

        if ( $ldap_virusquarantine eq "" ) {
            addMenuItem( $lm, \$i, "Anti-virus quarantine user:", 'VIRUSQUARANTINE', \&setAmavisVirusQuarantine );
        }
        else {
            $main::config{VIRUSQUARANTINE} = $ldap_virusquarantine;
        }

        addMenuItem( $lm, \$i, "Enable automated spam training:", 'DOTRAINSA', \&toggleYN, "DOTRAINSA" );

        if ( $main::config{DOTRAINSA} eq "yes" ) {
            my $ldap_trainsaspam = getLdapConfigValue("zimbraSpamIsSpamAccount")
              if ( ldapIsAvailable() );

            if ( $ldap_trainsaspam eq "" ) {
                addMenuItem( $lm, \$i, "Spam training user:", 'TRAINSASPAM', \&setTrainSASpam );
            }
            else {
                $main::config{TRAINSASPAM} = $ldap_trainsaspam;
            }

            my $ldap_trainsaham = getLdapConfigValue("zimbraSpamIsNotSpamAccount")
              if ( ldapIsAvailable() );

            if ( $ldap_trainsaham eq "" ) {
                addMenuItem( $lm, \$i, "Non-spam(Ham) training user:", 'TRAINSAHAM', \&setTrainSAHam );
            }
            else {
                $main::config{TRAINSAHAM} = $ldap_trainsaham;
            }
        }

        addMenuItem( $lm, \$i, "SMTP host:", 'SMTPHOST', \&setSmtpHost );

        if ( !main::isEnabled("carbonio-proxy") && $main::config{zimbraWebProxy} eq "TRUE" ) {
            addMenuItem( $lm, \$i, "HTTP proxy port:",  'HTTPPROXYPORT',  \&setHttpProxyPort );
            addMenuItem( $lm, \$i, "HTTPS proxy port:", 'HTTPSPROXYPORT', \&setHttpsProxyPort );
        }

        addMenuItem( $lm, \$i, "Web server mode:", 'MODE', \&setStoreMode );

        if ( !main::isEnabled("carbonio-proxy") && $main::config{zimbraMailProxy} eq "TRUE" ) {
            addMenuItem( $lm, \$i, "IMAP proxy port:",     'IMAPPROXYPORT',    \&setImapProxyPort );
            addMenuItem( $lm, \$i, "IMAP SSL proxy port:", 'IMAPSSLPROXYPORT', \&setImapSSLProxyPort );
            addMenuItem( $lm, \$i, "POP proxy port:",      'POPPROXYPORT',     \&setPopProxyPort );
            addMenuItem( $lm, \$i, "POP SSL proxy port:",  'POPSSLPROXYPORT',  \&setPopSSLProxyPort );
        }
    }
    return $lm;
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

    foreach my $package (@main::packageList) {
        if ( $package eq "carbonio-core" )      { next; }
        if ( $package eq "carbonio-memcached" ) { next; }

        if ( defined( $main::installedPackages{$package} ) ) {

            # override "prompt" of carbonio-clamav package menu
            if ( $package eq "carbonio-clamav" ) {
                $mm{menuitems}{$i} = {
                    "prompt"   => "carbonio-antivirus:",
                    "var"      => \$main::enabledPackages{$package},
                    "callback" => \&toggleEnabled,
                    "arg"      => $package
                };
                $i++;
                next;
            }
            my $submenu = createPackageMenu($package);
            $mm{menuitems}{$i} = {
                "prompt"  => "$package:",
                "var"     => \$main::enabledPackages{$package},
                "submenu" => $submenu,
            };
            $i++;
        }
        else {
            #push @mm, "$package not installed";
        }
    }
    $i = mainMenuExtensions( \%mm, $i );

    if ( $main::config{EXPANDMENU} eq "yes" ) {
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
        "callback" => \&main::saveConfig,
    };
    if ( checkMenuConfig( \%mm ) ) {
        $mm{promptitem} = {
            "selector" => "y",
            "prompt"   => "*** CONFIGURATION COMPLETE - press 'y' to apply configuration\nSelect from menu, or press 'y' to apply config",
            "callback" => \&main::applyConfig,
        };
    }
    else {
        $mm{promptitem} = {
            "selector" => "qqazyre",
            "prompt"   => "Address unconfigured (**) items ",
            "callback" => \&main::applyConfig,
        };
        if ( !ldapIsAvailable() && $main::ldapConfigured ) {
            $mm{promptitem}{prompt} .= "or correct ldap configuration ";
        }
        if ( $main::config{LDAPHOST} ne $main::config{HOSTNAME} && !ldapIsAvailable() && main::isInstalled("carbonio-directory-server") ) {
            $mm{promptitem}{prompt} .= "and enable ldap replication on ldap master "
              if ( checkLdapReplicationEnabled( $main::config{zimbra_ldap_userdn}, $main::config{LDAPADMINPASS} ) );
        }
    }
    return \%mm;
}

sub mainMenu {
    my %mm = ();
    $mm{createsub} = \&createMainMenu;

    displayMenu( \%mm );
}

sub mainMenuExtensions {
    my ( $mm, $i ) = (@_);
    return $i;
}

1;
