#!/usr/bin/perl
#
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

package Zextras::Setup::SSL;
use strict;
use warnings;
use Exporter 'import';

our @EXPORT = qw(configCASetup configSaveCA configCreateCert configSaveCert configInstallCert);

sub configCASetup {

    if ( ( $main::configStatus{configCASetup} // "" ) eq "CONFIGURED" && -d "/opt/zextras/ssl/carbonio/ca" ) {
        main::configLog("configCASetup");
        return 0;
    }

    if ( $main::config{LDAPHOST} ne $main::config{HOSTNAME} ) {
        main::progress("Updating ldap_root_password and zimbra_ldap_password...");
        main::setLocalConfigBatch(
            ldap_root_password   => $main::config{LDAPROOTPASS},
            zimbra_ldap_password => $main::config{LDAPADMINPASS}
        );
        main::progress("done.\n");
    }
    main::progress("Setting up CA...");
    if ( !$main::newinstall ) {
        if ( -f "/opt/zextras/conf/ca/ca.pem" ) {
            my $rc = main::runAsRoot("/opt/zextras/common/bin/openssl verify -purpose sslserver -CAfile /opt/zextras/conf/ca/ca.pem /opt/zextras/conf/ca/ca.pem | egrep \"^error 10\"");
            $main::needNewCert = "-new" if ( $rc == 0 );
        }
    }

    my $needNewCA = "";
    if ( main::isLdapMaster() ) {
        $needNewCA = "-new" if ( !-d "/opt/zextras/ssl/carbonio/ca" || $main::needNewCert eq "-new" );
    }

    $main::needNewCert = "-new" if ( !-d "/opt/zextras/ssl/carbonio/ca" );

    my $rc = main::runAsZextras("/opt/zextras/bin/zmcertmgr createca $needNewCA");
    main::progressResult( $rc, 1 );

    main::progress("Deploying CA to /opt/zextras/conf/ca ...");
    $rc = main::runAsZextras("/opt/zextras/bin/zmcertmgr deployca -localonly");
    main::progressResult( $rc, 1 );

    main::configLog("configCASetup");
}

sub configSaveCA {

    if ( ( $main::configStatus{configSaveCA} // "" ) eq "CONFIGURED" ) {
        main::configLog("configSaveCA");
        return 0;
    }
    main::progress("Saving CA in LDAP...");
    my $rc = main::runAsZextras("/opt/zextras/bin/zmcertmgr deployca");
    main::progressResult( $rc, 1 );
    main::configLog("configSaveCA");
}

sub configCreateCert {

    if ( ( $main::configStatus{configCreateCert} // "" ) eq "CONFIGURED" && -d "/opt/zextras/ssl/carbonio/server" ) {
        main::configLog("configCreateCert");
        return 0;
    }

    if ( !$main::newinstall ) {
        my $rc = main::runAsZextras("/opt/zextras/bin/zmcertmgr verifycrt comm > /dev/null 2>&1");
        if ( $rc != 0 ) {
            $rc = main::runAsZextras("/opt/zextras/bin/zmcertmgr verifycrt self > /dev/null 2>&1");
            if ( $rc != 0 ) {
                main::progress("WARNING: No valid SSL certificates were found.\n");
                main::progress("New self-signed certificates will be generated and installed.\n");
                $main::needNewCert   = "-new" if ( $rc != 0 );
                $main::ssl_cert_type = "self";
            }
        }
        else {
            $main::ssl_cert_type = "comm";
            $main::needNewCert   = "";
        }
    }

    my $rc;

    my $createCertFor = sub {
        my ( $component, $msg ) = @_;
        main::progress("$msg...");
        $rc = main::runAsZextras("/opt/zextras/bin/zmcertmgr createcrt $main::needNewCert");
        main::progressResult( $rc, 1 );
    };

    my @cert_components = (
        [ 'carbonio-appserver',        $main::config{mailboxd_keystore},    'appserver' ],
        [ 'carbonio-directory-server', '/opt/zextras/conf/slapd.crt', 'ldap' ],
        [ 'carbonio-mta',             '/opt/zextras/conf/smtpd.crt', 'mta' ],
        [ 'carbonio-proxy',           '/opt/zextras/conf/nginx.crt', 'proxy' ],
    );

    for my $comp (@cert_components) {
        my ( $package, $cert_file, $label ) = @$comp;
        next unless main::isInstalled($package);

        if ( $package eq "carbonio-appserver" && !-d "$main::config{mailboxd_directory}" ) {
            qx(mkdir -p $main::config{mailboxd_directory}/etc);
            qx(chown -R zextras:zextras $main::config{mailboxd_directory});
            qx(chmod 744 $main::config{mailboxd_directory}/etc);
        }

        if ( !-f "$cert_file" && !-f "/opt/zextras/ssl/carbonio/server/server.crt" ) {
            $createCertFor->( $label, "Creating $package SSL certificate" );
        }
        elsif ( $main::needNewCert ne "" && $main::ssl_cert_type eq "self" ) {
            $createCertFor->( $label, "Creating new $package SSL certificate" );
        }
    }

    main::configLog("configCreateCert");
}

sub configSaveCert {

    if ( ( $main::configStatus{configSaveCert} // "" ) eq "CONFIGURED" ) {
        main::configLog("configSaveCert");
        return 0;
    }
    if ( -f "/opt/zextras/ssl/carbonio/server/server.crt" ) {
        main::progress("Saving SSL Certificate in LDAP...");
        my $rc = main::runAsZextras("/opt/zextras/bin/zmcertmgr savecrt $main::ssl_cert_type");
        main::progressResult( $rc, 1 );
        main::configLog("configSaveCert");
    }
}

sub configInstallCert {
    my $rc;

    my @install_checks = (
        [ 'configInstallCertStore', 'carbonio-appserver',        [ $main::config{mailboxd_keystore} ],                                  'mailboxd' ],
        [ 'configInstallCertMTA',   'carbonio-mta',             [ '/opt/zextras/conf/smtpd.key', '/opt/zextras/conf/smtpd.crt' ], 'MTA' ],
        [ 'configInstallCertLDAP',  'carbonio-directory-server', [ '/opt/zextras/conf/slapd.key', '/opt/zextras/conf/slapd.crt' ], 'LDAP' ],
        [ 'configInstallCertProxy', 'carbonio-proxy',           [ '/opt/zextras/conf/nginx.key', '/opt/zextras/conf/nginx.crt' ], 'Proxy' ],
    );

    my %needInstall;
    for my $check (@install_checks) {
        my ( $config_key, $package, $check_files, $label ) = @$check;
        if ( ( $main::configStatus{$config_key} // "" ) eq "CONFIGURED" && $main::needNewCert eq "" ) {
            main::configLog($config_key);
        }
        elsif ( main::isInstalled($package) ) {
            my $files_exist = grep { -f $_ } @$check_files;
            if ( !$files_exist || $main::needNewCert ne "" ) {
                $needInstall{$config_key} = $label;
            }
            else {
                main::configLog($config_key);
            }
        }
    }

    if (%needInstall) {
        my @components = map { $needInstall{ $_->[0] } } grep { $needInstall{ $_->[0] } } @install_checks;
        main::progress( "Installing SSL certificates for: " . join( ", ", @components ) . "..." );

        $rc = main::runAsZextras("/opt/zextras/bin/zmcertmgr deploycrt $main::ssl_cert_type");
        main::progressResult( $rc, 1 );
        for my $check (@install_checks) {
            my ( $config_key, $package, $check_files, $label ) = @$check;
            next unless $needInstall{$config_key};
            if ( $label eq "LDAP" && $main::ldapConfigured ) {
                main::stopLdap();
                main::startLdap();
            }
            main::configLog($config_key);
        }
    }
}

1;
