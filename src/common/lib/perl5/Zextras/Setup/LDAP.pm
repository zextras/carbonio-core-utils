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

1;
