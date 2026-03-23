#!/usr/bin/perl
#
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

package Zextras::Setup::LDAP;
use strict;
use warnings;
use FileHandle;
use IPC::Open3;
use Net::LDAP;
use Exporter 'import';

our @EXPORT = qw(
    getLdapValueHelper
    getLdapAccountValue getLdapCOSValue getLdapConfigValue
    getLdapDomainValue getLdapServerValue getRealLdapServerValue
    setLdapConfigHelper
    setLdapGlobalConfig setLdapServerConfig setLdapDomainConfig
    setLdapCOSConfig setLdapAccountConfig
    updateKeyValue ifKeyValueEquate
    isLdapRunning startLdap stopLdap waitForLdap
    isLdapMaster getAllServers
    ldapBindMaster countReverseProxyLookupTargets countUsers
    setLdapPasswordHelper askLdapPasswordHelper
    createSystemAccountIfMissing
    ensureLdapForServerQuery
    setLdapDefaults
    ldapIsAvailable
    checkLdapBind checkLdapReplicationEnabled
    updatePasswordsInLocalConfig
    configSetupLdap
    configLDAPSchemaVersion
    configCreateServerEntry
    configSetStoreDefaults
    configSetServicePorts
    configSetKeyboardShortcutsPref
    configSetTimeZonePref
    setProxyBits
    configSetProxyPrefs
    configCreateDomain
    configInitGALSyncAccts
    configCreateDefaultDomainGALSyncAcct
    configSetEnabledServices
    addServerToHostPool
);

# --- Cache management ---

sub updateKeyValue {
    my ( $sec, $key, $val, $sub ) = @_;
    if ( $key =~ /^\+(.*)/ ) {
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
    main::detail("Checking to see if $key=$val has changed for $sec $sub.\n") if $main::options{d};
    if ( exists $main::saved{$sec}{$sub}{$key} && $main::saved{$sec}{$sub}{$key} eq $val ) {
        return 1;
    }
    else {
        return 0;
    }
}

# --- LDAP value getters ---

sub getLdapValueHelper {
    my ( $attrib, $sub, $sec, $cmd, $detailType ) = @_;
    my ( $val, $err );
    if ( exists $main::loaded{$sec}{$sub}{$attrib} ) {
        $val = $main::loaded{$sec}{$sub}{$attrib};
        main::detail("Returning cached $detailType config attribute for $sub: $attrib=$val.");
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
    main::detail("$err") if ( length($err) > 0 );
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
    main::detail("Returning retrieved $detailType config attribute for $sub: $attrib=$val.");
    return $val;
}

sub getLdapAccountValue($$) {
    my ( $attrib, $sub ) = @_;
    return getLdapValueHelper( $attrib, $sub, "acct", "$main::ZMPROV ga $sub", "account" );
}

sub getLdapCOSValue {
    my ( $attrib, $sub ) = @_;
    $sub = "default" if ( $sub eq "" );
    return getLdapValueHelper( $attrib, $sub, "gc", "$main::ZMPROV gc $sub", "cos" );
}

sub getLdapConfigValue {
    my $attrib = shift;
    return getLdapValueHelper( $attrib, "gcf", "gcf", "$main::ZMPROV gacf", "global" );
}

sub getLdapDomainValue {
    my ( $attrib, $sub ) = @_;
    $sub = $main::config{zimbraDefaultDomainName} if ( $sub eq "" );
    return undef if ( $sub eq "" );
    return getLdapValueHelper( $attrib, $sub, "domain", "$main::ZMPROV gd $sub", "domain" );
}

sub getLdapServerValue {
    my ( $attrib, $sub ) = @_;
    $sub = $main::config{HOSTNAME} if ( $sub eq "" );
    return getLdapValueHelper( $attrib, $sub, "gs", "$main::ZMPROV gs $sub", "server" );
}

sub getRealLdapServerValue {
    my ( $attrib, $sub ) = @_;
    $sub = $main::config{HOSTNAME} if ( $sub eq "" );
    return getLdapValueHelper( $attrib, $sub, "gsreal", "$main::ZMPROV gs -e $sub", "server" );
}

# --- LDAP value setters ---

sub setLdapConfigHelper {
    my ( $sec, $entity, $zmprovCmd, $detailType, @args ) = @_;
    my $zmprov_arg_str;
    while (@args) {
        my $key = shift @args;
        my $val = shift @args;
        if ( ifKeyValueEquate( $sec, $key, $val, $entity ) ) {
            main::detail("Skipping update of unchanged value for $key=$val.");
        }
        else {
            main::detail("Updating cached config attribute for $detailType $entity: $key=$val.");
            updateKeyValue( $sec, $key, $val, $entity );
            $zmprov_arg_str .= " $key \'$val\'";
        }
    }
    if ($zmprov_arg_str) {
        return main::runAsZextras("$zmprovCmd $zmprov_arg_str");
    }
}

sub setLdapGlobalConfig {
    return setLdapConfigHelper( "gcf", "gcf", "$main::ZMPROV mcf", "Global", @_ );
}

sub setLdapServerConfig {
    my $server = ( $#_ % 2 ) == 0 ? shift : $main::config{HOSTNAME};
    return undef if ( $server eq "" );
    return setLdapConfigHelper( "gs", $server, "$main::ZMPROV ms $server", "Server", @_ );
}

sub setLdapDomainConfig {
    my $domain = ( $#_ % 2 ) == 0 ? shift : getLdapConfigValue("zimbraDefaultDomainName");
    return undef if ( $domain eq "" );
    return setLdapConfigHelper( "domain", $domain, "$main::ZMPROV md $domain", "Domain", @_ );
}

sub setLdapCOSConfig {
    my $cos = ( $#_ % 2 ) == 0 ? shift : 'default';
    return setLdapConfigHelper( "gc", $cos, "$main::ZMPROV mc $cos", "COS", @_ );
}

sub setLdapAccountConfig {
    my $acct = ( $#_ % 2 ) == 0 ? shift : "";
    return undef if ( $acct eq "" );
    return setLdapConfigHelper( "acct", $acct, "$main::ZMPROV ma $acct", "Account", @_ );
}

# --- LDAP lifecycle ---

sub isLdapRunning {
    if ( Zextras::Util::Systemd::isSystemd() ) {
        return Zextras::Util::Systemd::isSystemdActiveUnit("carbonio-openldap.service");
    }
    else {
        my $rc = 0xffff & system("/opt/zextras/bin/ldap status > /dev/null 2>&1");
        return ( $rc == 0 ) ? 1 : 0;
    }
}

sub waitForLdap {
    my $timeout = shift // 30;
    my $ldapi   = "ldapi://%2frun%2fcarbonio%2frun%2fldapi/";
    my $ldap_root_password = main::getLocalConfig("ldap_root_password");
    my $elapsed = 0;
    while ( $elapsed < $timeout ) {
        my $ldap = Net::LDAP->new($ldapi);
        if ($ldap) {
            my $mesg = $ldap->bind( "cn=config", password => $ldap_root_password );
            if ( !$mesg->code ) {
                $ldap->unbind;
                return 0;
            }
            $ldap->unbind;
        }
        sleep 1;
        $elapsed++;
    }
    return 1;
}

sub startLdap {
    my $rc;
    main::detail("Checking LDAP status...");
    if ( isLdapRunning() ) {
        main::detail("already running.\n");
        return 0;
    }
    main::detail("not running.\n");

    main::progress("Starting LDAP...");
    if ( Zextras::Util::Systemd::isSystemd() ) {
        $rc = system("systemctl start carbonio-openldap.service");
        if ( $rc == 0 ) {
            $rc = waitForLdap(30);
        }
    }
    else {
        $rc = main::runAsZextras("/opt/zextras/bin/ldap start");
    }
    main::progress( ( $rc == 0 ) ? "done.\n" : "failed with exit code: $rc.\n" );
    return $rc;
}

sub stopLdap {
    my $rc;
    main::detail("Checking LDAP status...");
    unless ( isLdapRunning() ) {
        main::detail("already stopped.\n");
        return 0;
    }
    main::detail("running.\n");

    main::progress("Stopping LDAP...");
    if ( Zextras::Util::Systemd::isSystemd() ) {
        $rc = system("systemctl stop carbonio-openldap.service");
    }
    else {
        $rc = main::runAsZextras("/opt/zextras/bin/ldap stop");
    }
    main::progress( ( $rc == 0 ) ? "done.\n" : "failed with exit code: $rc.\n" );
    return $rc;
}

# --- LDAP utility ---

sub isLdapMaster {
    return ( ( $main::config{LDAPHOST} eq $main::config{HOSTNAME} ) ? 1 : 0 );
}

sub getAllServers {
    my ($service) = @_;
    my @servers;
    main::detail("Running $main::ZMPROV gas $service...");
    open( ZMPROV, "$main::ZMPROV gas $service 2>/dev/null|" );
    chomp( @servers = <ZMPROV> );
    close(ZMPROV);
    return @servers;
}

sub ldapBindMaster {
    my $ldap_pass       = main::getLocalConfig("zimbra_ldap_password");
    my $ldap_master_url = main::getLocalConfig("ldap_master_url");
    my @masters         = split( / /, $ldap_master_url );

    my $ldap = Net::LDAP->new( \@masters );
    unless ($ldap) {
        main::detail("Unable to contact $ldap_master_url.");
        return ( undef, "Unable to contact $ldap_master_url" );
    }

    my $ldap_dn = $main::config{zimbra_ldap_userdn};
    my $result  = $ldap->bind( $ldap_dn, password => $ldap_pass );
    if ( $result->code() ) {
        main::detail("LDAP bind failed for $ldap_dn.");
        return ( undef, "LDAP bind failed for $ldap_dn" );
    }
    main::detail("LDAP bind done for $ldap_dn.");
    return ( $ldap, undef );
}

sub countReverseProxyLookupTargets {
    my ( $ldap, $err ) = ldapBindMaster();
    return unless $ldap;

    main::progress("Searching LDAP for reverseProxyLookupTargets...");
    my $result = $ldap->search( base => 'cn=zimbra', filter => '(zimbraReverseProxyLookupTarget=TRUE)', attrs => ['1.1'] );
    main::progressResult( $result->code() ? 1 : 0 );
    $ldap->unbind;
    return if ( $result->code() );
    return "" . $result->count;
}

sub countUsers {
    return $main::loaded{stats}{numAccts}
      if ( exists $main::loaded{stats}{numAccts} );

    my ( $ldap, $err ) = ldapBindMaster();
    return undef unless $ldap;

    main::progress("Searching LDAP for zimbra accounts...");
    my $result = $ldap->search(
        filter => "(objectclass=zimbraAccount)",
        attrs  => ['zimbraMailDeliveryAddress']
    );
    main::progressResult( $result->code() ? 1 : 0 );
    $ldap->unbind;
    return undef if ( $result->code() );

    my $count = $result->count;
    $main::loaded{stats}{numAccts} = $count
      if ( $count > 0 );
    return ( ( $count > 0 ) ? "$count" : undef );
}

# --- Password helpers ---

# Helper function to set LDAP passwords - consolidates repeated pattern
# $name: display name (e.g., "replication", "postfix")
# $flag: zmldappasswd flag (e.g., "-l", "-p", "-a", "-n")
# $configKey: config hash key for the password
# $localConfigKey: localconfig key for remote LDAP case
# $quotePassword: whether to quote the password (for post-LDAP-init calls)
sub setLdapPasswordHelper {
    my ( $name, $flag, $configKey, $localConfigKey, $quotePassword ) = @_;
    main::progress("Setting $name password...");
    if ( $main::config{LDAPHOST} eq $main::config{HOSTNAME} ) {
        my $pass = $quotePassword ? "'$main::config{$configKey}'" : $main::config{$configKey};
        main::runAsZextras("/opt/zextras/bin/zmldappasswd $flag $pass");
    }
    else {
        main::setLocalConfig( $localConfigKey, "$main::config{$configKey}" );
    }
    main::progress("done.\n");
}

# Helper to ask for LDAP password - consolidates 6 nearly identical functions
sub askLdapPasswordHelper {
    my ( $prompt, $configKey, $changedFlagRef, $checkLdapAvailable ) = @_;
    while (1) {
        my $new = main::askPassword( "Password for $prompt (min 6 characters):", $main::config{$configKey} );
        if ( length($new) >= 6 ) {
            if ( $main::config{$configKey} ne $new ) {
                $main::config{$configKey} = $new;
                $$changedFlagRef = 1;
            }
            ldapIsAvailable() if ( $checkLdapAvailable && $main::config{HOSTNAME} ne $main::config{LDAPHOST} );
            return;
        }
        print "Minimum length of 6 characters!\n";
    }
}

# --- Account helpers ---

# Helper to create a system account if it doesn't exist
sub createSystemAccountIfMissing {
    my ( $configKey, $description, $extraAttrs ) = @_;
    $extraAttrs //= "";
    $main::config{$configKey} = lc( $main::config{$configKey} );
    main::progress("Creating user $main::config{$configKey}...");
    my $acctId = getLdapAccountValue( "zimbraId", $main::config{$configKey} );
    if ( $acctId ne "" ) {
        main::progress("already exists.\n");
        return 0;
    }
    my $pass = main::genRandomPass();
    my $rc   = main::runAsZextras(
        "$main::ZMPROV ca $main::config{$configKey} \'$pass\' "
          . "amavisBypassSpamChecks TRUE zimbraAttachmentsIndexingEnabled FALSE "
          . "zimbraIsSystemResource TRUE zimbraIsSystemAccount TRUE zimbraHideInGal TRUE "
          . "zimbraMailQuota 0 $extraAttrs description \'$description\'"
    );
    main::progressResult($rc);
    return $rc;
}

# --- LDAP query helpers ---

# Ensure LDAP connection config is loaded and LDAP is running if needed.
# Returns 0 on success, 1 on failure to start LDAP.
sub ensureLdapForServerQuery {
    $main::config{zimbra_server_hostname} = main::getLocalConfig("zimbra_server_hostname")
      if ( $main::config{zimbra_server_hostname} eq "" );
    main::detail("DEBUG: zimbra_server_hostname=$main::config{zimbra_server_hostname}")
      if $main::options{d};

    $main::config{ldap_url} = main::getLocalConfig("ldap_url")
      if ( $main::config{ldap_url} eq "" );
    main::detail("DEBUG: ldap_url=$main::config{ldap_url}")
      if $main::options{d};

    if ( index( $main::config{ldap_url}, "/" . $main::config{zimbra_server_hostname} ) != -1 ) {
        main::detail("Server hostname found in ldap_url, checking LDAP status...");
        if ( startLdap() ) { return 1; }
    }
    else {
        main::detail("Server hostname not in ldap_url, not starting slapd.");
    }
    return 0;
}

# --- LDAP defaults ---

sub setLdapDefaults {

    return if exists $main::config{LDAPDEFAULTSLOADED};
    main::progress("Setting defaults from LDAP...");

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
            $main::config{$key} = getLdapServerValue( $ldapServerAttribs{$key} );
        }

        $main::config{zimbraReverseProxyLookupTarget} = getLdapServerValue("zimbraReverseProxyLookupTarget")
          if ( $main::config{zimbraReverseProxyLookupTarget} eq "" );

        if ( main::isEnabled("carbonio-mta") ) {
            my $tmpval = getLdapServerValue("zimbraMtaMyNetworks");
            $main::config{zimbraMtaMyNetworks} = $tmpval
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
        $main::config{PUBLICSERVICEHOSTNAME} = $publicServiceHostnameLdap;

        # set the flag to avoid overwriting zimbraPublicServiceHostname on ldap
        $main::publicServiceHostnameAlreadySet = 1;
    }

    $main::config{zimbraDefaultDomainName} = getLdapConfigValue("zimbraDefaultDomainName");
    if ( $main::config{zimbraDefaultDomainName} eq "" ) {
        $main::config{zimbraDefaultDomainName} = $main::config{CREATEDOMAIN};
    }
    else {
        $main::config{CREATEDOMAIN} = $main::config{zimbraDefaultDomainName};
        $main::config{CREATEADMIN}  = "zextras\@$main::config{CREATEDOMAIN}";
    }

    if ( $main::config{SMTPHOST} eq "" ) {
        my $smtphost = getLdapConfigValue("zimbraSmtpHostname");
        $smtphost =~ s/\n/ /g;
        $main::config{SMTPHOST} = $smtphost if ( $smtphost ne "localhost" );
    }

    $main::config{TRAINSASPAM} = getLdapConfigValue("zimbraSpamIsSpamAccount");
    if ( $main::config{TRAINSASPAM} eq "" ) {
        $main::config{TRAINSASPAM} = "spam." . lc( main::genRandomPass() ) . '@' . $main::config{CREATEDOMAIN};
    }
    $main::config{TRAINSAHAM} = getLdapConfigValue("zimbraSpamIsNotSpamAccount");
    if ( $main::config{TRAINSAHAM} eq "" ) {
        $main::config{TRAINSAHAM} = "ham." . lc( main::genRandomPass() ) . '@' . $main::config{CREATEDOMAIN};
    }
    $main::config{VIRUSQUARANTINE} = getLdapConfigValue("zimbraAmavisQuarantineAccount");
    if ( $main::config{VIRUSQUARANTINE} eq "" ) {
        $main::config{VIRUSQUARANTINE} = "virus-quarantine." . lc( main::genRandomPass() ) . '@' . $main::config{CREATEDOMAIN};
    }

    #
    # Load default COS
    #
    $main::config{USEKBSHORTCUTS}       = getLdapCOSValue("zimbraPrefUseKeyboardShortcuts");
    $main::config{zimbraPrefTimeZoneId} = getLdapCOSValue("zimbraPrefTimeZoneId");

    #
    # Load default domain values
    #
    my $galacct = getLdapDomainValue("zimbraGalAccountId");
    $main::config{ENABLEGALSYNCACCOUNTS} = ( ( $galacct eq "" ) ? "no" : "yes" );

    #
    # Set some sane defaults if values were missing in LDAP
    #
    $main::config{HTTPPORT}              = 80      if ( $main::config{HTTPPORT} eq 0 );
    $main::config{HTTPSPORT}             = 443     if ( $main::config{HTTPSPORT} eq 0 );
    $main::config{MODE}                  = "https" if ( $main::config{MODE} eq "" );
    $main::config{PROXYMODE}             = "https" if ( $main::config{PROXYMODE} eq "" );
    $main::config{REMOTEIMAPBINDPORT}    = 8143    if ( $main::config{REMOTEIMAPBINDPORT} eq 0 );
    $main::config{REMOTEIMAPSSLBINDPORT} = 8993    if ( $main::config{REMOTEIMAPSSLBINDPORT} eq 0 );

    if ( main::isInstalled("carbonio-proxy") && main::isEnabled("carbonio-proxy") ) {
        main::resolveMailPortPairCollisions(1) if ( $main::config{MAILPROXY} eq "TRUE" );
        if ( $main::config{HTTPPROXY} eq "TRUE" ) {
            # Add proxy component to a configured node
            $main::config{HTTPPROXYPORT}  = 80  if ( ( $main::config{HTTPPORT} == 80 || $main::config{HTTPPORT} == 0 ) && $main::config{HTTPPROXYPORT} == 0 );
            $main::config{HTTPSPROXYPORT} = 443 if ( ( $main::config{HTTPSPORT} == 443 || $main::config{HTTPSPORT} == 0 ) && $main::config{HTTPSPROXYPORT} == 0 );
            main::resolveHttpPortPairCollisions(1);
        }
    }
    else {
        main::resolveMailPortPairCollisions(0);
        main::resolveHttpPortPairCollisions(0);
    }

    #
    # debug output
    #
    if ( $main::options{d} ) {
        main::dumpConfig();
    }
    $main::config{LDAPDEFAULTSLOADED} = 1;
    main::progress("done.\n");
}

# --- LDAP availability checks ---

sub ldapIsAvailable {
    my $failedcheck = 0;
    if ( ( $main::config{LDAPHOST} eq $main::config{HOSTNAME} ) && !$main::ldapConfigured ) {
        main::detail("This is the LDAP master and LDAP has not been configured yet.");
        return 0;
    }

    # check zimbra ldap admin user binding to the master
    if ( $main::config{LDAPADMINPASS} eq "" || $main::config{LDAPPORT} eq "" || $main::config{LDAPHOST} eq "" ) {
        main::detail("LDAP configuration not complete.\n");
        return 0;
    }

    if ( checkLdapBind( $main::config{zimbra_ldap_userdn}, $main::config{LDAPADMINPASS} ) ) {
        main::detail("Could not bind to $main::config{LDAPHOST} as $main::config{zimbra_ldap_userdn}.\n");
        $main::config{LDAPADMINPASSSET} = "Not Verified";
        $failedcheck++;
    }
    else {
        main::detail("Verified $main::config{zimbra_ldap_userdn} on $main::config{LDAPHOST}.\n");
        $main::config{LDAPADMINPASSSET} = "set";
        main::setLocalConfig( "zimbra_ldap_password", $main::config{LDAPADMINPASS} );
        setLdapDefaults() if ( $main::config{LDAPHOST} ne $main::config{HOSTNAME} );
    }

    # check nginx user binding to the master
    if ( main::isInstalled("carbonio-proxy") ) {
        if ( $main::config{ldap_nginx_password} eq "" ) {
            main::detail("Nginx configuration not complete.\n");
            $failedcheck++;
        }
        my $binduser = "uid=zmnginx,cn=appaccts,$main::config{ldap_dit_base_dn_config}";
        if ( checkLdapBind( $binduser, $main::config{ldap_nginx_password} ) ) {
            main::detail("Could not bind to $main::config{LDAPHOST} as $binduser.\n");
            $main::config{LDAPNGINXPASSSET} = "Not Verified";
            $failedcheck++;
        }
        else {
            main::detail("Verified $binduser on $main::config{LDAPHOST}.\n");
            $main::config{LDAPNGINXPASSSET} = "set";
        }
    }

    # check postfix and amavis user binding to the master
    if ( main::isInstalled("carbonio-mta") ) {
        if ( $main::config{LDAPPOSTPASS} eq "" || $main::config{LDAPAMAVISPASS} eq "" ) {
            main::detail("MTA configuration not complete.\n");
            $failedcheck++;
        }
        my $binduser = "uid=zmpostfix,cn=appaccts,$main::config{ldap_dit_base_dn_config}";
        if ( checkLdapBind( $binduser, $main::config{LDAPPOSTPASS} ) ) {
            main::detail("Could not bind to $main::config{LDAPHOST} as $binduser.\n");
            $main::config{LDAPPOSTPASSSET} = "Not Verified";
            main::detail("Setting LDAPPOSTPASSSET to $main::config{LDAPPOSTPASSSET}.") if $main::options{d};
            $failedcheck++;
        }
        else {
            main::detail("Verified $binduser on $main::config{LDAPHOST}.\n");
            $main::config{LDAPPOSTPASSSET} = "set";
        }
        my $binduser2 = "uid=zmamavis,cn=appaccts,$main::config{ldap_dit_base_dn_config}";
        if ( checkLdapBind( $binduser2, $main::config{LDAPAMAVISPASS} ) ) {
            main::detail("Could not bind to $main::config{LDAPHOST} as $binduser2.\n");
            $main::config{LDAPAMAVISPASSSET} = "Not Verified";
            main::detail("Setting LDAPAMAVISPASSSET to $main::config{LDAPAMAVISPASSSET}.") if $main::options{d};
            $failedcheck++;
        }
        else {
            main::detail("Verified $binduser2 on $main::config{LDAPHOST}.\n");
            $main::config{LDAPAMAVISPASSSET} = "set";
        }
    }

    # check replication user binding to master
    if ( main::isInstalled("carbonio-directory-server") && $main::config{LDAPHOST} ne $main::config{HOSTNAME} ) {
        if ( $main::config{LDAPREPPASS} eq "" ) {
            main::detail("LDAP configuration not complete: replication password is not set.\n");
            $failedcheck++;
        }
        my $binduser = "uid=zmreplica,cn=admins,$main::config{ldap_dit_base_dn_config}";
        if ( checkLdapBind( $binduser, $main::config{LDAPREPPASS} ) ) {
            main::detail("Could not bind to $main::config{LDAPHOST} as $binduser.\n");
            $main::config{LDAPREPPASSSET} = "Not Verified";
            main::detail("Setting LDAPREPPASSSET to $main::config{LDAPREPPASSSET}.") if $main::options{d};
            $failedcheck++;
        }
        else {
            main::detail("Verified $binduser on $main::config{LDAPHOST}.\n");
            $main::config{LDAPREPPASSSET} = "set";
        }
        if ( checkLdapReplicationEnabled( $main::config{zimbra_ldap_userdn}, $main::config{LDAPADMINPASS} ) ) {
            main::detail("LDAP configuration not complete: unable to verify LDAP replication is enabled on $main::config{LDAPHOST}.\n");
            $failedcheck++;
        }
        else {
            main::detail("LDAP replication ability verified.\n");
        }
    }
    return ( $failedcheck > 0 ) ? 0 : 1;
}

sub checkLdapBind {
    my ( $binduser, $bindpass ) = @_;

    main::detail("Checking LDAP on $main::config{LDAPHOST}:$main::config{LDAPPORT}...");
    my $ldap;
    my $ldap_secure = ( ( $main::config{LDAPPORT} == "636" ) ? "s" : "" );
    my $ldap_url    = "ldap${ldap_secure}://$main::config{LDAPHOST}:$main::config{LDAPPORT}";
    unless ( $ldap = Net::LDAP->new($ldap_url) ) {
        main::detail("Failed: Unable to contact LDAP at $ldap_url: $!");
        return 1;
    }

    if ( $ldap_secure ne "s" && $main::config{zimbra_require_interprocess_security} ) {
        $main::starttls = 1;
        my $result = $ldap->start_tls( verify => 'none' );
        if ( $result->code() ) {
            main::detail("Unable to startTLS: $!\n");
            main::detail("Disabling the requirement for interprocess security.\n");
            $main::config{zimbra_require_interprocess_security} = 0;
            $main::config{ZIMBRA_REQ_SECURITY}                  = "no";
            $main::starttls                                     = 0;
        }
    }
    else {
        $main::starttls = 0;
    }
    my $result = $ldap->bind( $binduser, password => $bindpass );
    if ( $result->code() ) {
        main::detail("Unable to bind to $ldap_url with user $binduser.");
        return 1;
    }
    else {
        $ldap->unbind;
        main::detail("Verified LDAP running at $ldap_url.\n");
        if ($main::newinstall) {
            main::setLocalConfigBatch(
                ldap_url                             => $ldap_url,
                ldap_starttls_supported              => $main::starttls,
                zimbra_require_interprocess_security => $main::config{zimbra_require_interprocess_security},
                ssl_allow_untrusted_certs            => "true"
            );
        }
        return 0;
    }
}

sub checkLdapReplicationEnabled {
    my ( $binduser, $bindpass ) = @_;
    main::detail("Checking LDAP replication is enabled on $main::config{LDAPHOST}:$main::config{LDAPPORT}...");
    my $ldap;
    my $ldap_secure = ( ( $main::config{LDAPPORT} == "636" ) ? "s" : "" );
    my $ldap_url    = "ldap${ldap_secure}://$main::config{LDAPHOST}:$main::config{LDAPPORT}";
    unless ( $ldap = Net::LDAP->new($ldap_url) ) {
        main::detail("Failed: Unable to contact LDAP at $ldap_url: $!");
        return 1;
    }
    if ( $ldap_secure ne "s" && $main::starttls ) {
        my $result = $ldap->start_tls( verify => 'none' );
        if ( $result->code() ) {
            main::detail("Unable to startTLS: $!\n");
            main::detail("Disabling the requirement for interprocess security.\n");
            $main::config{zimbra_require_interprocess_security} = 0;
            $main::config{ZIMBRA_REQ_SECURITY}                  = "no";
            $main::starttls                                     = 0;
        }
    }
    my $result = $ldap->bind( $binduser, password => $bindpass );
    if ( $result->code() ) {
        main::detail("Unable to bind to $ldap_url with user $binduser.");
        return 1;
    }
    else {
        my $result = $ldap->search( base => "cn=accesslog", scope => "base", filter => "cn=accesslog", attrs => ['cn'] );
        if ( $result->code() ) {
            main::detail("Unable to find accesslog database on master.\n");
            if ( $main::config{LDAPREPLICATIONTYPE} eq "replica" ) {
                main::detail("Please run zmldapenablereplica on the master.\n");
            }
            elsif ( $main::config{LDAPREPLICATIONTYPE} eq "mmr" ) {
                main::detail("Please run zmldapenable-mmr on the master.\n");
            }
            return 1;
        }
        else {
            main::detail("Verified ability to query accesslog on master.\n");
        }
    }
    return 0;
}

# --- Config functions ---

sub updatePasswordsInLocalConfig {

    if ( main::isEnabled("carbonio-directory-server") ) {

        # On new install where we're the LDAP host and LDAP isn't configured yet,
        # skip password setting here - it will be done after LDAP is started in configSetupLdap
        if ( $main::newinstall && !$main::ldapConfigured && ( $main::config{LDAPHOST} eq $main::config{HOSTNAME} ) ) {
            main::detail("Skipping password update - LDAP not yet started, will be set after initialization.\n");
            return;
        }

        if ( $main::ldapConfigured && ( $main::ldapRootPassChanged || $main::ldapAdminPassChanged || $main::ldapRepChanged || $main::ldapPostChanged || $main::ldapAmavisChanged || $main::ldapNginxChanged ) ) {

            startLdap();

            if ($main::ldapRootPassChanged) {
                main::progress("Setting LDAP root password...");
                main::runAsZextras("/opt/zextras/bin/zmldappasswd -r $main::config{LDAPROOTPASS}");
                main::progress("done.\n");
            }
            setLdapPasswordHelper( "LDAP admin", "", "LDAPADMINPASS", "zimbra_ldap_password" )         if $main::ldapAdminPassChanged;
            setLdapPasswordHelper( "replication", "-l", "LDAPREPPASS", "ldap_replication_password" )  if $main::ldapRepChanged;
            setLdapPasswordHelper( "postfix", "-p", "LDAPPOSTPASS", "ldap_postfix_password" )         if $main::ldapPostChanged;
            setLdapPasswordHelper( "amavis", "-a", "LDAPAMAVISPASS", "ldap_amavis_password" )         if $main::ldapAmavisChanged;
            setLdapPasswordHelper( "nginx", "-n", "ldap_nginx_password", "ldap_nginx_password" )     if $main::ldapNginxChanged;
        }
        elsif ($main::ldapConfigured) {
            stopLdap();
            startLdap();
        }
    }
    else {
        # this sets the password for each component if they are enabled, use full in case of multiserver
        # especially when we add components to existing configured node
        if ( main::isEnabled("carbonio-mta") && ( $main::ldapPostChanged || $main::ldapAmavisChanged ) ) {
            setLdapPasswordHelper( "postfix", "-p", "LDAPPOSTPASS", "ldap_postfix_password" ) if $main::ldapPostChanged;
            setLdapPasswordHelper( "amavis", "-a", "LDAPAMAVISPASS", "ldap_amavis_password" ) if $main::ldapAmavisChanged;
        }

        if ( main::isEnabled("carbonio-proxy") && $main::ldapNginxChanged ) {
            setLdapPasswordHelper( "nginx", "-n", "ldap_nginx_password", "ldap_nginx_password" );
        }
    }
}

sub configSetupLdap {

    updatePasswordsInLocalConfig();

    #Check if skipping configSetupLdap on existing install is distructive
    if ( ( $main::configStatus{configSetupLdap} // "" ) eq "CONFIGURED" ) {
        main::detail("LDAP already configured, bypassing configuration.\n");
        main::configLog("configSetupLdap");
        return 0;
    }

    if ( !$main::ldapConfigured && main::isEnabled("carbonio-directory-server") && !-f "/opt/zextras/.enable_replica" && $main::newinstall && ( $main::config{LDAPHOST} eq $main::config{HOSTNAME} ) ) {
        main::progress("Initializing LDAP...");
        ldapinit->preLdapStart( $main::config{LDAPROOTPASS}, $main::config{LDAPADMINPASS} );
        if ( main::isSystemd() ) {
            system("systemctl start carbonio-openldap.service");
            waitForLdap(30);
        }
        else {
            main::runAsZextras("/opt/zextras/bin/ldap start");
        }

        if ( my $rc = ldapinit->postLdapStart() ) {
            main::progress("failed. ($rc)\n");
            main::failConfig();
        }
        else {
            main::progress("done.\n");
            # Set passwords after LDAP init (use quoted passwords for shell safety)
            setLdapPasswordHelper( "replication", "-l", "LDAPREPPASS", "ldap_replication_password", 1 ) if $main::ldapRepChanged;
            setLdapPasswordHelper( "postfix", "-p", "LDAPPOSTPASS", "ldap_postfix_password", 1 )        if $main::ldapPostChanged;
            setLdapPasswordHelper( "amavis", "-a", "LDAPAMAVISPASS", "ldap_amavis_password", 1 )        if $main::ldapAmavisChanged;
            setLdapPasswordHelper( "nginx", "-n", "ldap_nginx_password", "ldap_nginx_password", 1 )    if $main::ldapNginxChanged;
        }
        if ( $main::config{FORCEREPLICATION} eq "yes" ) {
            my $rc   = system("/opt/zextras/libexec/zmldapenablereplica");
            my $file = "/opt/zextras/.enable_replica";
            open( ER, ">>$file" );
            close ER;
        }
    }
    elsif ( main::isEnabled("carbonio-directory-server") ) {
        my $rc;
        if ($main::newinstall) {
            $rc = main::runAsZextras("/opt/zextras/libexec/zmldapapplyldif");
        }
        if ( !$main::newinstall ) {
            $rc = main::runAsZextras("/opt/zextras/libexec/zmldapupdateldif");
        }

        # enable replica for both new and upgrade installs if we are adding ldap
        if ( $main::config{LDAPHOST} ne $main::config{HOSTNAME} || -f "/opt/zextras/.enable_replica" ) {
            main::progress("Updating ldap_root_password and zimbra_ldap_password...");
            main::setLocalConfigBatch(
                ldap_root_password        => $main::config{LDAPROOTPASS},
                zimbra_ldap_password      => $main::config{LDAPADMINPASS},
                ldap_replication_password => $main::config{LDAPREPPASS}
            );
            if ( $main::newinstall && $main::config{LDAPREPLICATIONTYPE} eq "mmr" ) {
                setLdapPasswordHelper( "postfix", "-p", "LDAPPOSTPASS", "ldap_postfix_password", 1 )     if $main::ldapPostChanged;
                setLdapPasswordHelper( "amavis", "-a", "LDAPAMAVISPASS", "ldap_amavis_password", 1 )     if $main::ldapAmavisChanged;
                setLdapPasswordHelper( "nginx", "-n", "ldap_nginx_password", "ldap_nginx_password", 1 ) if $main::ldapNginxChanged;
            }
            main::progress("done.\n");
            main::progress("Enabling LDAP replication...");
            if ( !-f "/opt/zextras/.enable_replica" ) {
                if ( $main::newinstall && $main::config{LDAPREPLICATIONTYPE} eq "mmr" ) {
                    my $ldapMasterUrl = main::getLocalConfig("ldap_master_url");
                    my $proto = ( $main::config{LDAPPORT} == 636 ) ? "ldaps" : "ldap";
                    main::setLocalConfigBatch(
                        ldap_is_master => "true",
                        ldap_url       => "$proto://$main::config{HOSTNAME}:$main::config{LDAPPORT} $ldapMasterUrl"
                    );
                    $ldapMasterUrl .= "/" unless $ldapMasterUrl =~ /\/$/;
                    startLdap();
                    $rc = main::runAsZextras("/opt/zextras/libexec/zmldapenable-mmr -s $main::config{LDAPSERVERID} -m $ldapMasterUrl");
                }
                else {
                    $rc = system("/opt/zextras/libexec/zmldapenablereplica");
                }
                my $file = "/opt/zextras/.enable_replica";
                open( ER, ">>$file" );
                close ER;
            }
            if ( $rc == 0 ) {
                if ( !main::isEnabled("carbonio-appserver") ) {
                    $main::config{DOCREATEADMIN} = "no";
                }
                $main::config{DOCREATEDOMAIN} = "no";
                main::progress("done.\n");
                stopLdap();
                startLdap();
            }
            else {
                main::progress("failed.\n");
                main::progress("You will have to correct the problem and manually enable replication.\n");
                main::progress("Disabling LDAP on $main::config{HOSTNAME}...");
                my $rc = setLdapServerConfig( "-zimbraServiceEnabled", "directory-server" );
                main::progressResult($rc);
                stopLdap();
            }
        }
    }
    else {
        main::detail("Updating LDAP user passwords.\n");
        main::setLocalConfigBatch(
            ldap_root_password        => $main::config{LDAPROOTPASS},
            zimbra_ldap_password      => $main::config{LDAPADMINPASS},
            ldap_replication_password => $main::config{LDAPREPPASS},
            ldap_postfix_password     => $main::config{LDAPPOSTPASS},
            ldap_amavis_password      => $main::config{LDAPAMAVISPASS},
            ldap_nginx_password       => $main::config{ldap_nginx_password}
        );
    }

    main::configLog("configSetupLdap");
    return 0;
}

sub configLDAPSchemaVersion {
    return if ($main::haveSetLdapSchemaVersion);
    if ( main::isEnabled("carbonio-directory-server") ) {
        main::progress("Updating LDAP Schema version to '$main::ldapSchemaVersion'...");
        my $ec = setLdapGlobalConfig( 'zimbraLDAPSchemaVersion', $main::ldapSchemaVersion );
        if ( $ec != 0 ) {
            main::progress("failed.\n");
        }
        else {
            $main::haveSetLdapSchemaVersion = 1;
            main::progress("done.\n");
        }
    }
}

sub configCreateServerEntry {

    if ( ( $main::configStatus{configCreateServerEntry} // "" ) eq "CONFIGURED" ) {
        main::configLog("configCreateServerEntry");
        return 0;
    }

    main::progress("Creating server entry for $main::config{HOSTNAME}...");
    my $serverId = getLdapServerValue("zimbraId");
    if ( $serverId ne "" ) {
        main::progress("already exists.\n");
    }
    else {
        my $rc = main::runAsZextras("$main::ZMPROV cs $main::config{HOSTNAME}");
        main::progressResult($rc);
    }
    main::progress("Setting IP Mode...");
    my $rc = setLdapServerConfig( "zimbraIPMode", $main::config{zimbraIPMode} );
    main::progressResult($rc);
    $rc = main::runAsZextras("/opt/zextras/libexec/zmiptool >/dev/null 2>/dev/null");

    main::configLog("configCreateServerEntry");
}

sub configSetStoreDefaults {
    if ( main::isEnabled("carbonio-proxy") || $main::config{zimbraMailProxy} eq "TRUE" || $main::config{zimbraWebProxy} eq "TRUE" ) {
        $main::config{zimbraReverseProxyLookupTarget} = "TRUE";
    }

    # for mailstore split, set zimbraReverseProxyAvailableLookupTargets on service-only nodes
    if ( $main::newinstall && main::isStoreServiceNode() ) {
        my $adding = 0;
        main::progress("Checking current setting of ReverseProxyAvailableLookupTargets...\n");
        my $zrpALT = getLdapConfigValue("zimbraReverseProxyAvailableLookupTargets");
        if ( $zrpALT ne "" ) {
            $adding = 1;
        }
        else {
            main::progress("Querying LDAP for other mailstores...\n");

            # query LDAP to see if there are other mailstores.  If there are none, add this
            # new service node to zimbraReverseProxyAvailableLookupTargets.  Otherwise do not
            my $count = countReverseProxyLookupTargets();
            if ( !defined($count) || $count == 0 ) {
                $adding = 1;
            }
        }
        if ($adding) {
            main::progress("Adding $main::config{HOSTNAME} to ReverseProxyAvailableLookupTargets...\n");
            setLdapGlobalConfig( "+zimbraReverseProxyAvailableLookupTargets", $main::config{HOSTNAME} );
        }
    }
    $main::config{zimbraMtaAuthTarget} = "TRUE";
    if ( !main::isStoreServiceNode() ) {
        $main::config{zimbraMtaAuthTarget} = "FALSE";
    }
    if ( $main::newinstall && main::isStoreServiceNode() ) {
        setLdapGlobalConfig( "+zimbraReverseProxyUpstreamEwsServers", "$main::config{HOSTNAME}" );
    }

    setLdapServerConfig( "zimbraReverseProxyLookupTarget", $main::config{zimbraReverseProxyLookupTarget} );
    setLdapServerConfig( "zimbraMtaAuthTarget",            $main::config{zimbraMtaAuthTarget} );
    my $upstream = "-u";
    if ( $main::config{zimbra_require_interprocess_security} ) {
        $upstream = "-U";
    }
    if ( $main::newinstall && ( $main::config{zimbraWebProxy} eq "TRUE" || $main::config{zimbraMailProxy} eq "TRUE" ) ) {
        if ( $main::config{zimbraMailProxy} eq "TRUE" ) {
            my $rc = main::runAsZextras( "/opt/zextras/libexec/zmproxyconfig $upstream -m -e -o " . "-i $main::config{IMAPPORT}:$main::config{IMAPPROXYPORT}:$main::config{IMAPSSLPORT}:$main::config{IMAPSSLPROXYPORT} " . "-p $main::config{POPPORT}:$main::config{POPPROXYPORT}:$main::config{POPSSLPORT}:$main::config{POPSSLPROXYPORT} -H $main::config{HOSTNAME}" );
            if ( $rc != 0 ) {
                main::progress("WARNING: zmproxyconfig for mail proxy returned non-zero exit code: $rc.\n");
            }
        }
        if ( $main::config{zimbraWebProxy} eq "TRUE" ) {
            my $rc = main::runAsZextras( "/opt/zextras/libexec/zmproxyconfig $upstream -w -e -o " . "-x $main::config{PROXYMODE} " . "-a $main::config{HTTPPORT}:$main::config{HTTPPROXYPORT}:$main::config{HTTPSPORT}:$main::config{HTTPSPROXYPORT} -H $main::config{HOSTNAME}" );
            if ( $rc != 0 ) {
                main::progress("WARNING: zmproxyconfig for web proxy returned non-zero exit code: $rc.\n");
            }
        }
    }
}

sub configSetServicePorts {

    if ( ( $main::configStatus{configSetServicePorts} // "" ) eq "CONFIGURED" ) {
        main::configLog("configSetServicePorts");
        return 0;
    }

    main::progress("Setting service ports on $main::config{HOSTNAME}...");
    if ( $main::config{MAILPROXY} eq "FALSE" ) {
        if ( $main::config{IMAPPORT} == 7143 && $main::config{IMAPPROXYPORT} == $main::config{IMAPPORT} ) {
            $main::config{IMAPPROXYPORT} = 143;
        }
        if ( $main::config{IMAPSSLPORT} == 7993 && $main::config{IMAPSSLPROXYPORT} == $main::config{IMAPSSLPORT} ) {
            $main::config{IMAPSSLPROXYPORT} = 993;
        }
        if ( $main::config{POPPORT} == 7110 && $main::config{POPPROXYPORT} == $main::config{POPPORT} ) {
            $main::config{POPPROXYPORT} = 110;
        }
        if ( $main::config{POPSSLPORT} == 7995 && $main::config{POPSSLPROXYPORT} == $main::config{POPSSLPORT} ) {
            $main::config{POPSSLPORT} = 995;
        }
    }
    setLdapServerConfig( $main::config{HOSTNAME}, "zimbraImapBindPort", $main::config{IMAPPORT}, "zimbraImapSSLBindPort", $main::config{IMAPSSLPORT}, "zimbraImapProxyBindPort", $main::config{IMAPPROXYPORT}, "zimbraImapSSLProxyBindPort", $main::config{IMAPSSLPROXYPORT} );
    setLdapServerConfig( $main::config{HOSTNAME}, "zimbraPop3BindPort", $main::config{POPPORT},  "zimbraPop3SSLBindPort", $main::config{POPSSLPORT},  "zimbraPop3ProxyBindPort", $main::config{POPPROXYPORT},  "zimbraPop3SSLProxyBindPort", $main::config{POPSSLPROXYPORT} );
    if ( $main::config{HTTPPROXY} eq "FALSE" ) {
        if ( $main::config{HTTPPORT} == 8080 && $main::config{HTTPPROXYPORT} == $main::config{HTTPPORT} ) {
            $main::config{HTTPPROXYPORT} = 80;
        }
        if ( $main::config{HTTPSPORT} == 8443 && $main::config{HTTPSPROXYPORT} == $main::config{HTTPSPORT} ) {
            $main::config{HTTPSPROXYPORT} = 443;
        }
    }
    setLdapServerConfig( $main::config{HOSTNAME}, "zimbraMailPort", $main::config{HTTPPORT}, "zimbraMailSSLPort", $main::config{HTTPSPORT}, "zimbraMailProxyPort", $main::config{HTTPPROXYPORT}, "zimbraMailSSLProxyPort", $main::config{HTTPSPROXYPORT}, "zimbraMailMode", $main::config{MODE} );
    main::setLocalConfig( "zimbra_mail_service_port", $main::config{HTTPPORT} );

    main::progress("done.\n");
    main::configLog("configSetServicePorts");
}

sub configSetKeyboardShortcutsPref {
    if ( ( $main::configStatus{zimbraPrefUseKeyboardShortcuts} // "" ) eq "CONFIGURED" ) {
        main::configLog("zimbraPrefUseKeyboardShortcuts");
        return 0;
    }
    main::progress("Setting Keyboard Shortcut Preferences...");
    my $rc = setLdapCOSConfig( "zimbraPrefUseKeyboardShortcuts", $main::config{USEKBSHORTCUTS} );
    main::progressResult($rc);
    main::configLog("zimbraPrefUseKeyboardShortcuts");
}

sub configSetTimeZonePref {
    if ( ( $main::configStatus{zimbraPrefTimeZoneId} // "" ) eq "CONFIGURED" ) {
        main::configLog("zimbraPrefTimeZoneId");
        return 0;
    }
    if ( $main::config{LDAPHOST} eq $main::config{HOSTNAME} ) {
        main::progress("Setting TimeZone Preference...");
        my $rc = setLdapCOSConfig( "zimbraPrefTimeZoneId", $main::config{zimbraPrefTimeZoneId} );
        main::progressResult($rc);
    }
    main::configLog("zimbraPrefTimeZoneId");
}

sub setProxyBits {
    main::detail("Setting proxy configuration...\n");
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
    if ( main::isEnabled("carbonio-proxy") ) {
        if ( $main::config{STRICTSERVERNAMEENABLED} eq "yes" ) {
            main::progress("Enabling strict server name enforcement on $main::config{HOSTNAME}...");
            main::runAsZextras("$main::ZMPROV ms $main::config{HOSTNAME} zimbraReverseProxyStrictServerNameEnabled TRUE");
            main::progress("done.\n");
        }
        else {
            main::progress("Disabling strict server name enforcement on $main::config{HOSTNAME}...");
            main::runAsZextras("$main::ZMPROV ms $main::config{HOSTNAME} zimbraReverseProxyStrictServerNameEnabled FALSE");
            main::progress("done.\n");
        }
        if ( $main::config{MAILPROXY} eq "FALSE" && $main::config{HTTPPROXY} eq "FALSE" ) {
            $main::enabledPackages{"carbonio-proxy"} = "Disabled";
        }
        else {
            my $upstream = "-u";
            if ( $main::config{zimbra_require_interprocess_security} ) {
                $upstream = "-U";
            }
            if ( $main::config{MAILPROXY} eq "TRUE" ) {
                main::runAsZextras( "/opt/zextras/libexec/zmproxyconfig $upstream -m -e -o " . "-i $main::config{IMAPPORT}:$main::config{IMAPPROXYPORT}:$main::config{IMAPSSLPORT}:$main::config{IMAPSSLPROXYPORT} " . "-p $main::config{POPPORT}:$main::config{POPPROXYPORT}:$main::config{POPSSLPORT}:$main::config{POPSSLPROXYPORT} -H $main::config{HOSTNAME}" );
            }
            else {
                main::runAsZextras( "/opt/zextras/libexec/zmproxyconfig -m -d -o " . "-i $main::config{IMAPPORT}:$main::config{IMAPPROXYPORT}:$main::config{IMAPSSLPORT}:$main::config{IMAPSSLPROXYPORT} " . "-p $main::config{POPPORT}:$main::config{POPPROXYPORT}:$main::config{POPSSLPORT}:$main::config{POPSSLPROXYPORT} -H $main::config{HOSTNAME}" );
            }
            if ( $main::config{HTTPPROXY} eq "TRUE" ) {
                main::runAsZextras( "/opt/zextras/libexec/zmproxyconfig $upstream -w -e -o " . " -x $main::config{PROXYMODE} " . "-a $main::config{HTTPPORT}:$main::config{HTTPPROXYPORT}:$main::config{HTTPSPORT}:$main::config{HTTPSPROXYPORT} -H $main::config{HOSTNAME}" );
            }
            else {
                main::runAsZextras( "/opt/zextras/libexec/zmproxyconfig -w -d -o " . "-x $main::config{MODE} " . "-a $main::config{HTTPPORT}:$main::config{HTTPPROXYPORT}:$main::config{HTTPSPORT}:$main::config{HTTPSPROXYPORT} -H $main::config{HOSTNAME}" );
            }
        }
        if ( !( main::isEnabled("carbonio-appserver") ) ) {
            my @storetargets;
            main::detail("Running $main::ZMPROV garpu...");
            open( ZMPROV, "$main::ZMPROV garpu 2>/dev/null|" );
            chomp( @storetargets = <ZMPROV> );
            close(ZMPROV);
            if ( $storetargets[0] !~ /nginx-lookup/ ) {
                main::progress("WARNING: There is currently no mailstore to proxy. Proxy will restart once one becomes available.\n");
            }
        }
        if ( !( main::isEnabled("carbonio-memcached") ) ) {
            my @memcachetargets;
            main::detail("Running $main::ZMPROV gamcs...");
            open( ZMPROV, "$main::ZMPROV gamcs 2>/dev/null|" );
            chomp( @memcachetargets = <ZMPROV> );
            close(ZMPROV);
            if ( $memcachetargets[0] !~ /:11211/ ) {
                main::progress("WARNING: There are currently no memcached servers for the proxy. Proxy will start once one becomes available.\n");
            }
        }
        if ( ( !( $main::config{PUBLICSERVICEHOSTNAME} eq "" ) ) && ( !($main::publicServiceHostnameAlreadySet) ) ) {
            main::progress("Setting Public Service Hostname $main::config{PUBLICSERVICEHOSTNAME}...");
            main::runAsZextras("$main::ZMPROV mcf zimbraPublicServiceHostname $main::config{PUBLICSERVICEHOSTNAME}");
            main::progress("done.\n");
        }
    }
    else {
        main::runAsZextras( "/opt/zextras/libexec/zmproxyconfig -m -d -o " . "-i $main::config{IMAPPORT}:$main::config{IMAPPROXYPORT}:$main::config{IMAPSSLPORT}:$main::config{IMAPSSLPROXYPORT} " . "-p $main::config{POPPORT}:$main::config{POPPROXYPORT}:$main::config{POPSSLPORT}:$main::config{POPSSLPROXYPORT} -H $main::config{HOSTNAME}" );
        main::runAsZextras( "/opt/zextras/libexec/zmproxyconfig -w -d -o " . "-x $main::config{MODE} " . "-a $main::config{HTTPPORT}:$main::config{HTTPPROXYPORT}:$main::config{HTTPSPORT}:$main::config{HTTPSPROXYPORT} -H $main::config{HOSTNAME}" );
    }
}

sub configCreateDomain {

    if ( ( $main::configStatus{configCreateDomain} // "" ) eq "CONFIGURED" ) {
        main::configLog("configCreateDomain");
        return 0;
    }

    if ( !$main::ldapConfigured && main::isEnabled("carbonio-directory-server") ) {
        if ( $main::config{DOCREATEDOMAIN} eq "yes" ) {
            main::progress("Creating domain $main::config{CREATEDOMAIN}...");
            my $domainId = getLdapDomainValue("zimbraId");
            if ( $domainId ne "" ) {
                main::progress("already exists.\n");
            }
            else {
                my $rc = main::runAsZextras("$main::ZMPROV cd $main::config{CREATEDOMAIN}");
                main::progressResult($rc);
            }

            main::progress("Setting default domain name...");
            my $rc = setLdapGlobalConfig( "zimbraDefaultDomainName", $main::config{CREATEDOMAIN} );
            main::progressResult($rc);

            main::progress("Setting value of postfix myorigin...");
            $rc = setLdapGlobalConfig( "zimbraMtaMyOrigin", $main::config{CREATEDOMAIN} );
            main::progressResult($rc);
        }
    }
    if ( main::isEnabled("carbonio-appserver") ) {
        if ( $main::config{DOCREATEADMIN} eq "yes" ) {
            $main::config{CREATEADMIN} = lc( $main::config{CREATEADMIN} );
            my ( $u, $d ) = split( '@', $main::config{CREATEADMIN} );

            main::progress("Creating domain $d...");
            my $domainId = getLdapDomainValue( "zimbraId", $d );
            if ( $domainId ne "" ) {
                main::progress("already exists.\n");
            }
            else {
                my $rc = main::runAsZextras("$main::ZMPROV cd $d");
                main::progressResult($rc);
            }

            main::progress("Creating admin account $main::config{CREATEADMIN}...");
            my $acctId = getLdapAccountValue( "zimbraId", $main::config{CREATEADMIN} );
            if ( $acctId ne "" ) {
                main::progress("already exists.\n");
            }
            else {
                my $rc = main::runAsZextras( "$main::ZMPROV ca " . "$main::config{CREATEADMIN} \'$main::config{CREATEADMINPASS}\' " . "zimbraAdminConsoleUIComponents cartBlancheUI " . "description \'Administrative Account\' " . "displayName \'Carbonio Admin\' " . "zimbraIsAdminAccount TRUE" );
                main::progressResult($rc);
            }

            # no root/postmaster accounts on web-only nodes
            if ( main::isStoreServiceNode() ) {
                main::progress("Creating root alias...");
                my $rc = main::runAsZextras( "$main::ZMPROV aaa " . "$main::config{CREATEADMIN} root\@$main::config{CREATEDOMAIN}" );
                main::progressResult($rc);

                main::progress("Creating postmaster alias...");
                $rc = main::runAsZextras( "$main::ZMPROV aaa " . "$main::config{CREATEADMIN} postmaster\@$main::config{CREATEDOMAIN}" );
                main::progressResult($rc);
            }

            # set carbonioNotificationFrom & carbonioNotificationRecipients global config attributes
            main::progress("Setting infrastructure notification sender and recipients accounts...");
            my $rc = setLdapGlobalConfig( 'carbonioNotificationFrom', "$main::config{CREATEADMIN}", 'carbonioNotificationRecipients', "$main::config{CREATEADMIN}" );
            main::progressResult($rc);
        }

        if ( $main::config{DOTRAINSA} eq "yes" ) {
            createSystemAccountIfMissing( "TRAINSASPAM", "System account for spam training.", "" );
            createSystemAccountIfMissing( "TRAINSAHAM", "System account for Non-Spam (Ham) training.", "" );
            createSystemAccountIfMissing( "VIRUSQUARANTINE", "System account for Anti-virus quarantine.", "zimbraMailMessageLifetime 30d" );

            main::progress("Setting spam, training and anti-virus quarantine accounts...");
            my $rc = setLdapGlobalConfig( 'zimbraSpamIsSpamAccount', "$main::config{TRAINSASPAM}", 'zimbraSpamIsNotSpamAccount', "$main::config{TRAINSAHAM}", 'zimbraAmavisQuarantineAccount', "$main::config{VIRUSQUARANTINE}" );
            main::progressResult($rc);
        }
    }
    main::configLog("configCreateDomain");
}

sub configInitGALSyncAccts {

    if ( ( $main::configStatus{configInitGALSyncAccts} // "" ) eq "CONFIGURED" ) {
        main::configLog("configInitGALSyncAccts");
        return 0;
    }

    return 1
      unless ( main::isEnabled("carbonio-directory-server") && $main::config{LDAPHOST} eq $main::config{HOSTNAME} );

    #if ($main::config{ENABLEGALSYNCACCOUNTS} eq "yes") {
    #main::progress("Creating galsync accounts in all domains...");
    #my $rc = main::runAsZextras("zmjava com.zimbra.cs.account.ldap.upgrade.LdapUpgrade -b 14531 -v");
    #main::progress(($rc == 0) ? "done.\n" : "failed.\n");
    #main::configLog("configInitGALSyncAccts") if ($rc == 0);
    #}
}

sub configCreateDefaultDomainGALSyncAcct {

    if ( ( $main::configStatus{configCreateDefaultGALSyncAcct} // "" ) eq "CONFIGURED" ) {
        main::configLog("configCreateDefaultGALSyncAcct");
        return 0;
    }

    if ( main::isEnabled("carbonio-appserver") ) {
        main::progress("Creating galsync account for default domain...");
        my $_server  = main::getLocalConfig("zimbra_server_hostname");
        my $default_domain = ( ($main::newinstall) ? "$main::config{CREATEDOMAIN}" : "$main::config{zimbraDefaultDomainName}" );
        my $galsyncacct    = "galsync." . lc( main::genRandomPass() ) . '@' . $default_domain;
        my $rc             = main::runAsZextras("/opt/zextras/bin/zmgsautil createAccount -a $galsyncacct -n InternalGAL --domain $default_domain -s $_server -t zimbra -f _InternalGAL -p 1d");
        main::progressResult($rc);
        main::configLog("configCreateDefaultDomainGALSyncAcct") if ( $rc == 0 );
    }
}

sub configSetEnabledServices {

    foreach my $p ( keys %main::installedPackages ) {
        if ( $p eq "carbonio-core" ) {
            push( @main::installedServiceList, ( 'zimbraServiceInstalled', 'stats' ) );
            next;
        }
        $p =~ s/carbonio-//;
        if ( $p eq "appserver" ) { $p = "mailbox"; }

        # do not push antivirus if already exists, required to enable support for single & multi-node installs
        if ( $p eq "clamav" && !grep( /^antivirus$/, @main::installedServiceList ) ) { $p = "antivirus"; }

        # do not add clamav as service, it is known as antivirus
        if ( $p eq "clamav" ) { next; }
        push( @main::installedServiceList, ( 'zimbraServiceInstalled', "$p" ) );
    }

    foreach my $p ( keys %main::enabledPackages ) {
        if ( $p eq "carbonio-core" ) {
            push( @main::enabledServiceList, ( 'zimbraServiceEnabled', 'stats' ) );
            next;
        }
        if ( $main::enabledPackages{$p} eq "Enabled" ) {
            $p =~ s/carbonio-//;
            if ( $p eq "appserver" ) {
                $p = "mailbox";

                # Add carbonio-appserver webapps to service list
                if ( $main::installedWebapps{$main::serviceWebApp} eq "Enabled" ) {
                    push( @main::enabledServiceList, 'zimbraServiceEnabled', "$main::serviceWebApp" );
                }
            }

            # do not push antivirus if already exists, required to enable support for single & multi-node installs
            if ( $p eq "clamav" && !grep( /^antivirus$/, @main::enabledServiceList ) ) { $p = "antivirus"; }

            # do not add clamav as service, it is known as antivirus
            if ( $p eq "clamav" ) { next; }
            push( @main::enabledServiceList, 'zimbraServiceEnabled', "$p" );
        }
    }

    main::progress("Setting services on $main::config{HOSTNAME}...");

    # add service-discover as enabled service if it was in zimbraServiceEnabled before.
    # service-discover is special case which is not handled by regular logic, since it
    # has no explicit package mapping. we also do not add it to installedServiceList
    # for the same reason.
    if ( $main::prevEnabledServices{"service-discover"} && $main::prevEnabledServices{"service-discover"} eq "Enabled" ) {
        main::detail("Restoring service-discover serviceEnabled state from previous install.");
        push( @main::enabledServiceList, ( 'zimbraServiceEnabled', 'service-discover' ) );
    }

    setLdapServerConfig( $main::config{HOSTNAME}, @main::installedServiceList );
    setLdapServerConfig( $main::config{HOSTNAME}, @main::enabledServiceList );
    main::progress("done.\n");

    my $rc = main::runAsZextras("/opt/zextras/libexec/zmiptool >/dev/null 2>/dev/null");

    main::configLog("configSetEnabledServices");
}

sub addServerToHostPool {
    main::progress("Adding $main::config{HOSTNAME} to MailHostPool in default COS...");
    my $id = getLdapServerValue( "zimbraId", $main::config{HOSTNAME} );
    my $hp = getLdapCOSValue("zimbraMailHostPool");

    if ( $id eq "" ) {
        main::progress("failed. Could not find a server entry for $main::config{HOSTNAME}.\n");
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
    main::progressResult($rc);
}

1;
