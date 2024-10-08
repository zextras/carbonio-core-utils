#!/usr/bin/perl

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

# Testing in an *new* install like scenario:
# 1. Run these on a fresh install with LDAP *down*:
#   /opt/zextras/bin/zmcertmgr createca -new
#   /opt/zextras/bin/zmcertmgr deployca -localonly
#   /opt/zextras/bin/zmcertmgr createcrt -new
#   /opt/zextras/bin/zmcertmgr deploycrt self
#  - can cleanup/retest by removing files via:
#   rm -rf /opt/zextras/ssl/carbonio/*
# 2. Bring up LDAP and run these:
#   /opt/zextras/bin/zmcertmgr deployca
#   /opt/zextras/bin/zmcertmgr savecrt self

=head1 NAME

zmcertmgr - certificate management tool for Carbonio

=head1 SYNOPSIS

zmcertmgr <command> [options] [-help|-man] [-debug [#]]

  -help     displays a usage synopsis with information about options
  -man      displays the complete documentation

Where valid command/option combinations are:

  createca  [-new [-newkey]] [-keysize keysize] [-digest digest] [-subject subject]
  createcrt [-new] [-keysize keysize] [-digest digest] [-subject subject] [-days days] [-subjectAltNames host1,host2] [-allservers] [-noDefaultSubjectAltName]
  deployca  [-localonly]

  createcsr     <self|comm> [-new] [-keysize keysize] [-digest digest] [-subject subject] [-subjectAltNames host1,host2] [-noDefaultSubjectAltName]
  deploycrt   <<self>|<comm [certfile ca_chain_file]>> [-allservers] [-localonly] [[-deploy $services] ...]
  getcrt        <self|comm> [-allservers]
  savecrt       <self|comm> [-allservers]
  viewcsr       <self|comm> [csr_file]
  viewstagedcrt <self|comm> [certfile]
  verifycrt     <self|comm> [[[priv_key] [certfile]] [ca_chain_file]]

  verifycrtchain <ca_chain_file> <certfile>
  verifycrtkey   <priv_key>      <certfile>

  viewdeployedcrt    [all|ldap|mailboxd|mta|proxy]
  checkcrtexpiration [all|ldap|mailboxd|mta|proxy] [-days days]
  addcacert <certfile>
  migrate

 <certfile> <csr_file> <priv_key> are stored by "type" as follows:
   self       /opt/zextras/ssl/carbonio/server/server.{crt,csr,key}
   commercial /opt/zextras/ssl/carbonio/commercial/commercial.{crt,csr,key}

=head1 OPTIONS

=head2 Shared Options

=over 4

=item B<-allservers>

The effect of this option varies depending on the command.  Reference
a specific command to determine the purpose of this argument.

=item B<-days> I<days>

The number of days to certify a certificate for, except when used with
the B<checkcrtexpiration> command.  Default is 1825 days (~5 years).
For B<checkcrtexpiration> a default of 30 days is used.

=item B<-digest> I<algorithm>

The digest algorithm to be used.  Default is sha256.  The following
are valid: ripemd160,sha,sha1,sha224,sha256,sha384,sha512.

=item B<-keysize> I<keysize>

The RSA keysize in bits, for example "-keysize 4096".  Minimum keysize
is 2048.  Default keysize is 2048.

=item B<-localonly>

Avoids updating any certificate related settings in LDAP.

=item B<-new>

Force the generation of a new CA/Cert/CSR, overwriting existing data.

For B<createca>, the additional argument of B<-newkey> can be used to
force the creation of a new private key for the CA.  If the B<-newkey>
option is used on an existing install, it will break the established
trust of the existing CA.  Once the existing CA is replaced by a new
CA, via B<deployca>, TLS communications will fail due to the broken
trust relationship between existing certificates and the replaced CA.
A temporary workaround to this situation is to set
B<ssl_allow_untrusted_certs>=I<true> via B<zmlocalconfig>.

=item B<-noDefaultSubjectAltName>

Disable the (default) inclusion of the current zmhostname in the
subjectAltNames of a Cert/CSR.

=item B<services>

=item B<-deploy> I<services>

The set of services to be used for a request. The service names can be
specified as comma separate values or the B<-deploy> argument can be
used multiple times.

Valid services are 'all' or any of: ldap,mailboxd,mta,proxy.

=item B<-subject> I<subject>

The X.500 distinguished name (DN). The default is:

 CA:
  /O=CA/OU=Zextras Carbonio/CN=`zmhostname`
 Server:
       /OU=Zextras Carbonio/CN=`zmhostname`

This argument is passed as the '-subj' argument to I<openssl req> and
thus must be formatted as /type0=value0/type1=value1/type2=...,
characters may be escaped by \ (backslash), no spaces are skipped.

Commonly used attributes include:

  String X.500 AttributeType
  ------ -------------------
  C      countryName
  ST     stateOrProvinceName
  L      localityName
  O      organizationName
  OU     organizationalUnitName
  CN     commonName

For example:

  /C=US/ST=NC/L=Mayberry/O=Sales/OU=Example, Inc./CN=www.example.com

Note: the DN of the CA (issuer) must be different than the DN of the
server (subject) to avoid MS windows based clients from throwing a SSL
error similar to, "This certificate has invalid digital signature."

=item B<-subjectAltNames> I<subjectAltNames>

Additional host names that may use the certificate other than the one
listed in the subject.  The altername names can be specified as comma
separate values or the B<-subjectAltNames> can be used multiple times.

=item B<-debug [#]>

Enable verbose output. Verbosity can be increased by specifying an
optional (integer) debug level.  Often useful for troubleshooting.

=item B<-help>

Display a usage synopsis with information about options and exit.

=item B<-man>

Display the complete documentation and exit.

=back

=head2 Self-Signed Certificate Options

=over 4

=item B<createca>

Generates a Certificate Authority (CA).

=item B<deployca>

Deploys a Certificate Authority (CA).

=item B<createcrt>

Creates a self-signed certificate based on a CSR generated using
B<createcsr>.  By default the certificate subjectAltNames contains the
current zmhostname unless the B<-noDefaultSubjectAltName> argument is
used.

For B<createcrt>, the use of B<-allservers> will set the CR
SubjectAltNames to contain the names of all servers in the Carbonio
deployment (zmprov gas).

=back

=head2 Self-Signed and Commercial Certificate Options

=over 4

=item B<addcacert>

Appends an otherwise untrusted ssl certificate to the cacerts file.
This is primarily for allowance of untrusted ssl certificates in
external data sources.

=item B<checkcrtexpiration>

Check if certificate(s) expire within B<-days> I<days>.

=item B<createcsr>

Creates a certificate signing request (CSR) for either a self or
commercially signed certificate authority.  By default the CSR
subjectAltNames contains the current zmhostname unless the
B<-noDefaultSubjectAltName> argument is used.

=item B<getcrt>

=item B<savecrt>

For B<getcrt> and B<savecrt>, the use of B<-allservers> causes the
configuration keys to be get/set as a global (getConfig/modifyConfig)
configuration settings (zimbraSSLCertificate and zimbraSSLPrivateKey)
instead of as a per-server setting (getServer/modifyServer).

=item B<deploycrt>

Deploys a certificate.

For B<deploycrt>, the use of B<-allservers> will cause zmcertmgr to
iterate through all servers in the Carbonio deployment (zmprov gas, minus
the initiating zmcertmgr host).  On each server, the following two
commands are run:

  $ zmcertmgr getcrt $type -allservers; zmcertmgr deploycrt $type

Certificates are installed from:

  self - /opt/zextras/ssl/carbonio/server
  comm - /opt/zextras/ssl/carbonio/commercial

Note: if B<-allservers> does not work, there may be problems with SSH
authorized keys in the environment.

=item B<viewcsr>

Shows a certificate signing request (CSR).

=item B<verifycrt>

Combines B<verifycrtkey> and B<verifycrtchain> verification (see below).

=item B<verifycrtkey>

Compares private key and certificate modulus digests.

=item B<verifycrtchain>

Verifies a certificate chain.

=item B<viewdeployedcrt>

Shows a deployed certificate on the local server.

=item B<viewstagedcrt>

Shows a staged certificate. A staged certificate is placed in a
staging file, where all files that will be deployed with the
certificate are kept. You can use the staging area to verify that you
are ready to deploy a certificate.

=item B<migrate>

=back

=head1 EXAMPLES

=head2 Single-Node Self-Signed Certificate

=over 4

=item 1.

Begin by generating a new Certificate Authority (CA).

 $ zmcertmgr createca -new

=item 2.

Then generate a certificate signed by the CA that expires in 365 days.

 $ zmcertmgr createcrt -new -days 365

=item 3.

Deploy the certificate.

 $ zmcertmgr deploycrt self

=item 4.

Deploy the CA.

 $ zmcertmgr deployca

=item 5.

To finish, verify the certificate was deployed to all the services.

 $ zmcertmgr viewdeployedcrt

=back

=head2 Multi-Node Self-Signed Certificate

=over 4

=item 1.

Begin by generating a new Certificate Authority (CA).

 $ zmcertmgr createca -new
 $ zmcertmgr deployca

=item 2.

Then generate a certificate, signed by the CA, that expires in 1825
days with either wild-card or subject altnames.

 $ zmcertmgr createcrt -new -days 1825 -subjectAltNames "*.example.com"
 $ zmcertmgr createcrt -new -days 1825 -subject "/C=US/ST=CA/O=Example/CN=*.example.com"
 $ zmcertmgr createcrt -new -days 1825 -subjectAltNames "host1.example.com,host2.example.com"

=item 3.

Deploy the certificate to all nodes in the deployment.

 $ zmcertmgr deploycrt self -allservers

=item 4.

To finish, verify the certificate was deployed.

 $ zmcertmgr viewdeployedcrt

=back

=head1 SEE ALSO

=over 4

=item RFC 5280

L<https://tools.ietf.org/html/rfc5280> - Internet X.509 Public Key
Infrastructure Certificate and Certificate Revocation List (CRL)
Profile

=item RFC 4514

L<https://tools.ietf.org/html/rfc4514> - LDAP String Representation of
Distinguished Names

=back

=head1 CAVEATS

=cut

use lib qw(/opt/zextras/common/lib/perl5 /opt/zextras/zimbramon/lib/);

# main
{
    use strict;
    use warnings;
    use Carp ();
    use File::Basename qw(basename);
    use IO::Handle ();
    use Pod::Usage qw(pod2usage);

    STDOUT->autoflush(1);
    my $prog = basename($0);
    my $opt  = Opts->new($prog);

    # make sure we are not running as root anymore
    if ( $< == 0 ) {
        warn("$prog: ERROR: no longer runs as root!\n");
        exit(1);
    }

    my $cmd  = $opt->data("command");
    my $cmgr = CertMgr->new( $opt->data )
      or pod2usage( -exitval => 1, -verbose => 0 );

    umask(0027);

    warn("DEBUG: $cmd #ARGV[$#ARGV] ARGV(@ARGV)\n") if $cmgr->Debug > 3;

    print( "validation days: ", $cmgr->Days, "\n" )
      if ( $opt->{days} and $cmd ne "checkcrtexpiration" );

    unshift( @ARGV, $cmgr->Type ) if $cmgr->Type;
    my $rc = eval { $cmgr->$cmd(@ARGV); };
    chomp($@);
    die("$prog: ERROR $cmd(@ARGV) failed:\n $@\n") if $@;

    # method rc is non-zero on success -> exit(0) is success
    exit( $rc ? 0 : 1 );
}

# supporting packages
{

    package CertMgr;

    use strict;
    use warnings;

    use Carp ();
    use Cwd  ();

    use File::Basename ();
    use File::Copy     ();
    use File::Find     ();
    use File::Path     ();
    use File::Spec     ();
    use File::stat     ();

    use POSIX ();

    #use LocalConfig (); # inline

    sub _defaultDays    { return "1825"; }
    sub _defaultDaysExp { return "30"; }

    sub _defaultDigest {
        return $_[0]->lc->get("ssl_default_digest") || "sha256";
    }

    sub _defaultKeysize { return "2048"; }

    sub _defaultSubject {
        my ($self) = @_;
        my $svr    = $self->Localconfig->get("zimbra_server_hostname");
        my $o      = $self->Command eq "createca" ? "/O=CA" : "";
        return "$o/OU=Zextras Carbonio/CN=$svr";
    }

    sub new {
        my ($class) = shift;
        Carp::confess("new: invalid arguments\n") if ( @_ % 2 );

        # set Debug as early as possible!
        my %args    = @_;
        my %default = (
            Debug                 => $args{debug} || 0,
            Defaultsubjectaltname => 1,
            Keysize               => $class->_defaultKeysize,
        );

        my $self = bless( {%default}, ref($class) || $class );
        my @args = @_;

        for ( my $i = 0 ; $i < $#args ; $i += 2 ) {
            my ( $key, $val ) = ( $args[$i], $args[ $i + 1 ] );
            Carp::confess("new: invalid argument '$key'")
              if ( !$key or $key =~ /[A-Z]/ );
            $key = ucfirst($key);
            my $rc = eval {
                warn( "DEBUG: ", ref $self, "->$key",
                    ref $val ? "[@$val]" : "($val)", "\n" )
                  if $self->{Debug};
                $self->$key($val);
            };
            if ($@) {
                chomp($@);
                die("new: $key($val) failed: $@\n");
            }
            if ( !defined $rc ) {
                my @einfo =
                    ( $key =~ /^(?:Days|Digest|Keysize)$/ )
                  ? ()
                  : ("new: $key($val) failed\n");
                return $self->error(@einfo);
            }
        }

        # localconfig
        if ( !$self->Localconfig ) {
            my $rc = eval { $self->Localconfig( LocalConfig->new ); };
            die( "new: " . ( $@ || "unable to get localconfig" ) )
              unless $rc;
        }

        # Days: default depends upon operation being performed!
        if ( !$self->Days ) {
            my $daymethod = "_defaultDays";
            $daymethod .= "Exp" if ( $self->Command eq "checkcrtexpiration" );
            $self->Days( $self->$daymethod );
        }

        $self->Digest( $self->_defaultDigest ) if !$self->Digest;

        # hard coded "options"
        my $home = $self->Home("/opt/zextras");
        my $ozcb = "$home/common/bin";
        my $jbin = -x "$home/java/bin" ? "$home/java/bin" : $ozcb;
        $self->Java("$jbin/java");
        $self->Keytool("$jbin/keytool");
        $self->Openssl(
            -x "$ozcb/openssl"
            ? "$ozcb/openssl"
            : "$home/openssl/bin/openssl"
        );
        $self->Owner("zextras");

        $self->Randfile( $self->Home . "/ssl/.rnd" );
        $self->Zmprov( $self->Home . "/bin/zmprov" );

        return $self;
    }

    sub error {
        my $self = shift;
        print( "ERROR: ", @_ ) if @_;
        return undef;
    }

    sub runCacertsKeytool {
        my ( $self, @args ) = @_;
        return $self->run(
            $self->Keytool, @args,
            "-keystore",    $self->sslFiles("cacerts"),
            "-storepass",   $self->lc->get("mailboxd_truststore_password"),
            "2>&1",
        );
    }

    sub runMailboxKeytool {
        my ( $self, @args ) = @_;
        return $self->run(
            $self->Keytool, @args,
            "-keystore",    $self->sslFiles("keystore"),
            "-storepass",   $self->lc->get("mailboxd_keystore_password"),
            "2>&1",
        );
    }

    sub run {
        my ( $self, @command ) = @_;
        if ( @command > 1 ) {
            foreach (@command) {
                next if ( $_ eq "2>&1" );           # allow
                next if ( $_ eq ">/dev/null" );     # allow
                next if ( $_ eq "2>/dev/null" );    # allow
                if ( $_ =~ /[\'\`\?\*\$\\]/ ) {
                    $_ = quotemeta;
                }
                elsif ( $_ =~ /\s/ ) {
                    $_ = qq('$_');
                }
            }
        }

        my $cmd = join( " ", @command );
        warn("DEBUG: run command: $cmd\n") if $self->Debug > 1;
        my @r = qx($cmd);
        warn( "DEBUG: run(rc=$?) results(#=",
            scalar @r, ")", @r ? ":\n@r" : "", "\n" )
          if $self->Debug > 2;
        return wantarray ? @r : "@r";
    }

    sub getFromConcatData {
        my ( $self, $concatdata ) = @_;
        return undef unless $concatdata;

        open( my $ifh, "<", \$concatdata )
          or Carp::confess(
            "getFromConcatData: read concatenated cert data failed: $!\n");

        # recreate comm_ca_crt from the concatenated commercial cert
        my ( $incert, $count, $certdata ) = ( 0, 0, "" );
        my @cert;

        while ( my $l = <$ifh> ) {
            $l =~ s/\r?\n?$/\n/;
            $incert = ++$count if ( $l =~ /BEGIN CERTIFICATE/ );
            $certdata .= $l    if ($incert);
            if ( $l =~ /END CERTIFICATE/ ) {
                $incert = 0;
                push( @cert, $certdata );
                $certdata = "";
            }
        }
        return @cert;
    }

    # createca
    #   [-new [-newkey]] [-keysize keysize] [-digest digest] [-subject subject]
    # -new allow the scripts to overwrite the existing ca
    # -newkey allow the scripts to replace an existing ca key (can break trust)
    # -subjectAltNames / $subject_alt_names not allowed for createca
    # Notes:
    # - a self signed CA is only created on an LDAP master
    # - CA may be deployed to any node (and can become stale over time)
    sub createca {
        my ($self) = @_;
        warn("DEBUG: createca\n") if $self->Debug;

        # desired: allow '-new' to create a CA on a ldap master only, however:
        # - when bootstrapping a new install ldap_is_master is false
        # - so test ldap_host eq zimbra_server_hostname to allow -new
        my $ismaster = lc( $self->lc->get("ldap_is_master") || "" );
        if ( $self->New and $ismaster eq "false" ) {
            my $hostname = lc( $self->lc->get("zimbra_server_hostname") || "" );
            my $ldaphost = lc( $self->lc->get("ldap_host")              || "" );
            return $self->error("'-new' is only allowed on an ldap master\n")
              if ( $hostname ne $ldaphost );
        }

        $self->initSSLDirs or return undef;

        my $file = $self->sslFiles("ssl_conf_ca");
        if ( $self->New or !-f $file ) {
            $self->createConf( $file, $self->lc->get("zimbra_server_hostname"),
                $self->Subjectaltnames );
        }

        my %files = (
            "ca_key" => {
                loc  => "global",
                desc => "CA private key",
                key  => "zimbraCertAuthorityKeySelfSigned",
            },
            "ca_crt" => {
                loc  => "global",
                desc => "CA cert",
                key  => "zimbraCertAuthorityCertSelfSigned",
            },
            "comm_ca_crt" => {
                loc    => $self->lc->get("ldap_host"),
                desc   => "Commercial CA cert",
                key    => "zimbraSSLCertificate",
                concat => 1,
            },
        );

        # reuse an existing CA key unless -newkey is used to preserve trust
        # - check !$self->Newkey as local CA could be stale in MMR
        if ( !$self->Newkey ) {
            foreach my $key ( sort keys %files ) {
                my $file = $self->sslFiles($key);
                my $dat  = $files{$key};
                if ( $key ne "ca_key" and $self->New ) {
                    warn("DEBUG: createca skipping $dat->{desc}\n")
                      if $self->Debug;
                    next;
                }
                if ( -s $file ) {
                    print("** Using $dat->{desc} in '$file'\n");
                    next;
                }

                print("** Retrieving $dat->{desc} from LDAP... ");
                my $k = $self->getConfKey( $dat->{key}, $dat->{loc} );
                print( defined($k) ? "ok" : "failed", "\n" );
                next unless ($k);

                # deal with concatenated data if necessary
                if ( $dat->{concat} ) {
                    my @cert = $self->getFromConcatData($k);
                    shift @cert;    # skip the first cert
                    $k = join( "", @cert );
                    next unless ($k);
                }

                print("** Creating '$file'\n");
                open( my $ofh, ">", $file )
                  or Carp::confess("createca: open '$file' failed: $!\n");
                print {$ofh} $k;
            }
        }

        # reuse existing key when possible
        # - new key if Newkey or (New and no existing keyfile)
        $file = $self->sslFiles("ca_key");
        if ( $self->Newkey ) {
            return $self->docreateca(1);
        }
        elsif ( $self->New ) {
            return $self->docreateca( !-s $file );
        }
        else {
            return $self->_is_private_key($file);
        }
    }

    # an internal method
    sub docreateca {
        my ( $self, $newkey ) = @_;
        warn("DEBUG: docreateca\n") if $self->Debug;

        my $fconf = $self->sslFiles("ssl_conf_ca");
        if ( !-f $fconf ) {
            $self->createConf( $fconf, $self->lc->get("zimbra_server_hostname"),
                $self->Subjectaltnames );
        }

        $self->createCASerial or return undef;

        my $keyf = $self->sslFiles("ca_key");
        my $crtf = $self->sslFiles("ca_crt");
        my @keya = $newkey ? ( "-newkey", "rsa:" . $self->Keysize ) : ();
        push( @keya, $newkey ? "-keyout" : "-key", $keyf );

        # TBD: capture/process stderr?
        printf( "** Creating CA with %sprivate key $keyf\n",
            $newkey ? "new " : "existing " );
        my @out = $self->run(
            $self->Openssl, qw(req -batch -nodes),
            "-new",         "-" . $self->Digest,
            "-subj",        $self->Subject,
            "-days",        $self->Days,
            "-config",      $fconf,
            "-out",         $crtf,
            @keya,          qw(-extensions v3_ca -x509),
        );

        return $self->error( "openssl req failed(", $? >> 8, "):\n", @out )
          if ( $? != 0 );
        return 1;
    }

    sub _is_private_key {
        my ( $self, $file ) = @_;
        return $self->error("createca: empty key '$file'\n")
          unless ( -s $file );
        open( my $ifh, "<", $file )
          or return $self->error("createca: read '$file' failed: $!\n");
        my $ispriv = 0;
        while ( my $l = <$ifh> ) {
            if ( $l =~ /PRIVATE KEY/ ) {
                $ispriv = 1;
                last;
            }
        }
        return $ispriv;
    }

    sub createCASerial {
        my ($self) = @_;
        warn("DEBUG: createCASerial\n") if $self->Debug;

        $self->initSSLDirs or return undef;

        my $ser  = time();
        my $file = $self->sslFiles("ca_srl");
        open( my $ofh, ">", $file )
          or Carp::confess("createCASerial: open '$file' failed: $!\n");
        print {$ofh} "$ser\n";
    }

    # createcrt [-new] [-days days] [-keysize keysize] [-digest digest]
    #   [-subject subject] [-subjectAltNames host1,host2] -allservers
    #   [-noDefaultSubjectAltName]
    sub createcrt {
        my ($self) = @_;
        warn("DEBUG: createcrt\n") if $self->Debug;

        # OLD tool call order: init -> createCASerial -> backup
        $self->backupSSLDirs  or return undef;
        $self->initSSLDirs    or return undef;
        $self->createCASerial or return undef;

        # BUG?: this happens in other places like createcsr too...
        # OLD tool always rewrote the config so we do too
        my $file = $self->sslFiles("ssl_conf_cert");
        $self->createConf( $file, $self->defAltName, $self->Subjectaltnames );

        # do not recreate valid self-signed certs (e.g. on upgrade?)
        my $crtf = $self->sslFiles("self_crt");
        if ( -s $crtf and !$self->New ) {
            if ( $self->verifycrt("self") ) {
                print("** $crtf already exists.\n");
                return 1;
            }
        }

        # try and grab the cert from ldap
        if ( !$self->New ) {
            $self->getcrt("self") or return undef;
            if ( -s $crtf and $self->verifycrt("self") ) {
                print("** $crtf downloaded from ldap.\n");
                return 1;
            }
        }

        if ( $self->Allservers ) {
            chomp( my @altnames = $self->run( $self->Zmprov, qw(-m -l gas) ) );
            my $new   = $self->New;
            my @aname = $self->Subjectaltnames;
            warn("DEBUG: setting New to TRUE\n") if ( !$new and $self->Debug );
            warn("DEBUG: changing Subjectaltnames(@aname) to (@altnames)\n")
              if ( !@aname and $self->Debug );
            $self->New(1);
            $self->Subjectaltnames(@altnames);
        }

        my $csrf = $self->sslFiles("self_csr");
        if ( !-s $csrf or $self->New ) {
            $self->createcsr("self");
        }

        my $cadir = $self->sslDirs("ca_directory");
        $file = $cadir . "/index.txt.attr";
        if ( -f $file ) {
            warn("DEBUG: removing '$file'\n") if $self->Debug;
            unlink($file);
        }

        print("** Signing cert request $csrf\n");
        $file = "$cadir/index.txt";
        if ( -s $file or !-e $file ) {
            open( my $ofh, ">", $file )
              or Carp::confess("createcrt: create empty '$file' failed: $!\n");
            close($ofh);
        }

        my @out = $self->run(
            $self->Openssl,         qw(ca -batch -notext),
            "-policy",              "policy_anything",
            "-days",                $self->Days,
            "-md",                  $self->Digest,
            "-config",              $self->sslFiles("ssl_conf_cert"),
            "-in",                  $self->sslFiles("self_csr"),
            "-out",                 $self->sslFiles("self_crt"),
            "-cert",                $self->sslFiles("ca_crt"),
            "-keyfile",             $self->sslFiles("ca_key"),
            "-extfile",             $self->sslFiles("ssl_conf_cert"),
            qw(-extensions v3_req), "2>&1"
        );

        return ( $? == 0 )
          ? 1
          : $self->error( "openssl ca failed(", $? >> 8, "):\n", @out );
    }

    # createcsr <self|comm> [-new] [-keys #] [-dig dig] [-subj subj]
    #   [-subjectAltName h1,h2] [-noDefaultSubjectAltName]
    sub createcsr {
        my ( $self, $type ) = ( shift, @_ );
        Carp::confess("createcsr: no type argument specified\n")
          unless ($type);
        warn("DEBUG: createcsr(@_)\n") if $self->Debug;

        print("** Generating a server CSR of type '$type' for download\n");
        my $csrf = $self->sslFiles( $type . "_csr" );

        return $self->error(
            "Certificate Signing Request already exists: $csrf\n")
          if ( -f $csrf and !$self->New );

        my $file = $self->sslFiles("ssl_conf_cert");
        $self->createConf( $file, $self->defAltName, $self->Subjectaltnames );

        $self->backupSSLDirs or return undef;
        $self->initSSLDirs   or return undef;

        # COMPAT: do not force a new CA and ignore errors if ldap is down
        my $onew = $self->New;
        $self->New(0);
        $self->createca;
        $self->New($onew);

        # when ldap is down saveConfKey fails but we ignore that
        $self->createServerCertReq($type);

        return 1;
    }

    sub createServerCertReq {
        my ( $self, $type ) = ( shift, @_ );
        Carp::confess("createServerCertReq: no type argument specified\n")
          unless ($type);
        warn("DEBUG: createServerCertReq(@_)\n") if $self->Debug;

        my $keyf = $self->sslFiles( $type . "_key" );    # private key
        my $csrf = $self->sslFiles( $type . "_csr" );    # CSR

        my $file = $self->sslFiles("ssl_conf_cert");
        $self->createConf( $file, $self->defAltName, $self->Subjectaltnames );

        my $info =
          join( " ", "keysize=" . $self->Keysize, "digest=" . $self->Digest );
        print("** Creating server cert request $csrf with $info\n");
        my @out = $self->run(
            $self->Openssl, qw(req -batch -nodes),
            "-new",         "-" . $self->Digest,
            "-subj",        $self->Subject,
            "-config",      $file,
            "-out",         $csrf,
            "-newkey",      "rsa:" . $self->Keysize,
            "-keyout",      $keyf,
            "2>&1",
        );
        my $rc = $?;

        return $self->error( "openssl req failed(", $rc >> 8, "):\n", @out )
          if ( $rc != 0 );

        return $self->saveConfKey( "zimbraSSLPrivateKey", "server", $keyf );
    }

    sub installCA {
        my ($self) = @_;
        warn("DEBUG: installCA\n") if $self->Debug;

        my $caconfd = $self->sslDirs("ca_conf_dir");
        die("CA config dir '$caconfd': $!\n")
          unless ( -d $caconfd );

        my @remove;
        opendir( my $dh, $caconfd )
          or Carp::confess("installCA: opendir '$caconfd' failed: $!\n");
        while ( my $fn = readdir($dh) ) {
            next if ( $fn =~ /^\./ );
            my $name = File::Spec->catfile( $caconfd, $fn );
            push( @remove, $name )
              if ( -f $name or -l $name );
        }
        closedir($dh);

        if (@remove) {
            my $tot = scalar @remove;
            print("** Cleaning up $tot files from '$caconfd'\n");
            foreach my $f (@remove) {
                print("** Removing $f\n");
                return $self->error("unlinking '$f' failed\n")
                  unless unlink($f);
            }
        }

        # copy to conf_ca_key and conf_ca_crt
        # - set mask to create world readable files (after key handling)
        my $omask = umask;
        print("** Copying CA to $caconfd\n");
        my $err = 0;
        foreach my $fkey (qw(ca_key ca_crt)) {
            my $oldf = $self->sslFiles($fkey);
            my $newf = $self->sslFiles( "conf_" . $fkey );
            if ( -s $oldf ) {
                $self->_copy( $oldf, $newf )
                  or $err++;
            }
            umask(0022);    # open up mask after handling the key
        }

        my $file = $self->sslFiles("conf_ca_crt");
        if ( !$err and -s $file ) {
            $self->makeCAHashLink($file) or $err++;
        }
        else {
            warn("DEBUG: CA '$file' does not exist or is empty\n")
              if $self->Debug;
        }

        # break concatenated PEM into parts: name.pem -> name_#.pem
        my $ifile = $self->sslFiles("comm_ca_crt");
        if ( !$err and -s $ifile ) {
            my ( $name, $idir, $ext ) =
              File::Basename::fileparse( $ifile, '\.[^.]*$' );
            my $odir = $caconfd;
            my $i    = 0;
            my @cert = $self->getFromConcatData( $self->_slurp($ifile) );
            foreach my $cert (@cert) {
                $i++;
                my $ofile = File::Spec->catfile( $odir, $name . "_$i" . $ext );
                print("** Creating $ofile\n");
                if ( open( my $ofh, ">", $ofile ) ) {
                    print {$ofh} $cert;
                    close($ofh);
                    $self->makeCAHashLink($ofile)
                      or $err++;
                }
                else {
                    $self->error("installCA: open '$ofile' failed: $!\n");
                    $err++;
                }
            }
        }
        umask($omask);    # reset umask
        return $err ? undef : 1;
    }

    # deployCA [-localonly]
    sub deployca {
        my ($self) = @_;
        warn("DEBUG: deployca\n") if $self->Debug;

        $self->initSSLDirs or return undef;

        my $crtf = $self->sslFiles("ca_crt");
        my $keyf = $self->sslFiles("ca_key");

        my $ismaster = lc( $self->lc->get("ldap_is_master") || "" );
        if ( !$self->Localonly and $ismaster eq "true" ) {
            $self->saveConfKey( "zimbraCertAuthorityCertSelfSigned",
                "global", $crtf )
              or return undef;
            $self->saveConfKey( "zimbraCertAuthorityKeySelfSigned",
                "global", $keyf )
              or return undef;
        }

        # LDAP TLS negotiation fails if we addcacerts first!
        $self->addcacert( $crtf, "my_ca" )
          or return undef;

        return $self->installCA;
    }

    # TBD: rename _ca_crt to _ca_chain?
    # see also ZimbraAdminExt/CertificateMgr/.../cert/InstallCert.java
    # deploycrt <self> {-allservers}
    # deploycrt <comm> [certfile ca_chain_file]
    # BUG?: OLD code would default to self if !$type
    sub deploycrt {
        my ( $self, $type, $crtf, $ca_pem ) = ( shift, @_ );
        warn("DEBUG: deploycrt(@_)\n") if $self->Debug;
        $self->_checkType($type) or return undef;
        if ( $type eq "self" ) {
            die("certfile argument is not allowed for type '$type'\n")
              if defined($crtf);
            die("ca_chain_file argument is not allowed for type '$type'\n")
              if defined($ca_pem);
        }

        $self->initSSLDirs or return undef;

        $crtf ||= $self->sslFiles( $type . "_crt" );     # cert / cli_comm_crt
        my $keyf = $self->sslFiles( $type . "_key" );    # private key

        if ( $type eq "self" ) {
            if ( !-s $crtf ) {
                $self->createcrt or return undef;
            }
        }
        else {                                           # "comm"
            if ( @_ > 1 ) {
                die("certfile and ca_chain_file must both be specified\n")
                  unless ( defined($crtf) and defined($ca_pem) );

                $self->_fixNewline( $crtf, $ca_pem ) or return undef;

                # just in case we are working on commercial.crt directly
                $self->_keepFirstCert($crtf) or return undef;
            }
            else {
                $self->getcrt($type) or return undef;

                # PEM format (was old cli_ca_chain)
                $ca_pem ||= $self->sslFiles( $type . "_ca_crt" );
            }
            $self->_checkFiles( $keyf, $crtf, $ca_pem ) or return undef;

            $self->verifycrt( $type, $keyf, $crtf, $ca_pem )
              or return undef;

            my $dest = $self->sslFiles( $type . "_crt" );
            if ( @_ > 1 and $crtf ne $dest ) {
                $self->_copy( $crtf, $dest )
                  or return undef;
                $crtf = $dest;
            }

            $dest = $self->sslFiles( $type . "_ca_crt" );
            if ( @_ > 1 and $ca_pem ne $dest ) {
                $self->_copy( $ca_pem, $dest )
                  or return undef;
            }

            $self->_append( $ca_pem, $crtf )
              or return undef;
            $self->addcacert($dest)
              or return undef;
            $ca_pem = $dest;
        }

        # COMPAT: ignore savecrt errors
        my $err      = 0;
        my $ismaster = lc( $self->lc->get("ldap_is_master") || "" );
        if ( !$self->Localonly and $ismaster eq "true" ) {
            $self->savecrt($type) or $err++;
        }

        # ldap_crt, ldap_key, mta_crt, mta_key, ...
        if ( $self->Deploy ) {
            my %svc = map { $self->_getServiceInfo($_) } $self->Deploy;
            foreach my $name ( sort keys %svc ) {

                if ( $name eq "mailboxd" ) {
                    if ( !$self->lc->get("mailboxd_server") ) {
                        warn("DEBUG: deploycrt: skip non $name server)\n")
                          if $self->Debug;
                    }
                    else {
                        $self->createkeystore($type)
                          or return undef;
                    }
                }
                else {
                    my $dcrt = $svc{$name};
                    my $dkey = $self->sslFiles( $name . "_key" );
                    print(
"** Installing $name certificate '$dcrt' and key '$dkey'\n"
                    );
                    $self->_copy( $crtf, $dcrt )
                      or return undef;
                    $self->_copy( $keyf, $dkey )
                      or return undef;
                }
            }
            print("** NOTE: restart services to use the new certificates.\n");
        }
        $self->installCA
          or return undef;

        if ( $self->Allservers ) {
            chomp( my @allsvrs = $self->run( $self->Zmprov, qw(-m -l gas) ) );
            my $myname = $self->lc->get("zimbra_server_hostname");
            foreach my $svr ( sort @allsvrs ) {
                $svr = lc($svr);
                next if $svr eq $myname;
                my $zmrc = "/opt/zextras/libexec/zmrc $svr";
                my $cmd  = "zmcertmgr getcrt $type -allservers";
                my @out  = $self->run(qq(echo "HOST:$svr $cmd" | $zmrc));

                # COMPAT: try next host on error
                if ( $? != 0 ) {
                    my $rc = $? >> 8;
                    $self->error( "zmrc: $cmd failed($rc):\n", @out );
                    $err++;
                    next;
                }

                $cmd = "zmcertmgr deploycrt $type";
                @out = $self->run(qq(echo "HOST:$svr $cmd" | $zmrc));
                if ( $? != 0 ) {
                    my $rc = $? >> 8;
                    $self->error( "zmrc: $cmd failed($rc):\n", @out );
                    $err++;
                }
            }
        }
        return $err ? undef : 1;
    }

    # server crt file should have only a single certificate
    sub _keepFirstCert {
        my ( $self, $file ) = ( shift, @_ );

        open( my $fh, "<", $file )
          or return $self->error("open input '$file' failed: $!\n");

        my $found = 0;
        while (<$fh>) {
            /^-----BEGIN CERTIFICATE-----\s*$/ and ++$found;
            if ( $found > 1 ) {
                close($fh);
                last;
            }
        }
        return 1 unless ( $found > 1 );

        # perlfaq5: use -i from within a program
        print("** Keeping first certificate in '$file'\n");
        local ( $^I, @ARGV ) = ( '.orig', $file );
        my $match = 0;
        while (<>) {
            print unless $match;
            /^-----END CERTIFICATE-----\s*$/ and ++$match;
            close ARGV if eof;
        }
        return 1;
    }

    # fix any dos newlines and ensure the last line has a newline
    sub _fixNewline {
        my ( $self, @files ) = ( shift, @_ );

        warn("DEBUG: Checking line endings: @files\n") if $self->Debug;
        foreach my $f (@files) {
            open( my $fh, "<", $f )
              or return $self->error("open input '$f' failed: $!\n");

            my $fixit = 0;
            while (<$fh>) {
                /\015\012$/ and ++$fixit and last;
                !/\012$/    and ++$fixit and last;
            }
            close($fh);
            next unless $fixit;

            # perlfaq5: use -i from within a program
            print("** Fixing newlines in '$f'\n");
            {
                local ( $^I, @ARGV ) = ( '.bak', $f );
                while (<>) {
                    s/\015?\012?$/\012/;
                    print;
                    close ARGV if eof;
                }
            }
        }
        return 1;
    }

    sub _append {
        my ( $self, $from, $to ) = @_;
        print("** Appending ca chain '$from' to '$to'\n");
        my @fs = stat($from)
          or return $self->error("stat '$from' failed: $!\n");
        my @ts = stat($to)
          or return $self->error("stat '$to' failed: $!\n");

        return $self->error("'$from' and '$to' are identical\n")
          if ( $fs[0] == $ts[0] && $fs[1] == $ts[1] );

        open( my $ifh, "<", $from )
          or return $self->error("open input '$to' failed: $!\n");
        open( my $ofh, ">>", $to )
          or return $self->error("open output '$to' failed: $!\n");

        while ( my $l = <$ifh> ) {
            $l =~ s/\015?\012?$/\012/;
            print {$ofh} $l;
        }
        close($ifh);
        close($ofh);
        return 1;
    }

    # if copy fails and $! is not set, the files are the same
    sub _copy {
        my ( $self, $from, $to ) = @_;
        print("** Copying '$from' to '$to'\n");
        my $rc = File::Copy::copy( $from, $to );
        return $self->error("copy '$from' to '$to' failed: $!\n")
          if ( !$rc and $! );
        warn("DEBUG: rc($rc) copy($from,$to)\n") if ( $self->Debug and !$rc );
        return 1;
    }

    # Speed up OpenSSL cert lookups via hashes (of the cert subject
    # and serial number). OpenSSL opens symlinks having the same hash
    # code until it finds the cert avoiding scanning all certs.
    sub makeCAHashLink {
        my ( $self, $file ) = @_;
        Carp::confess("makeCAHashLink: no file argument specified\n")
          unless ($file);

        my @out =
          $self->run( $self->Openssl, "x509", "-hash", "-noout", "-in", $file,
            "2>&1" );

        return $self->error( "openssl x509 -hash failed(", $? >> 8, "):\n",
            @out )
          if ( $? != 0 or @out != 1 );

        my $odir = Cwd::cwd();
        my ( $fname, $fdir ) = File::Basename::fileparse($file);

        chdir($fdir) or die("chdir($fdir) failed: $!\n");
        my $ext = 0;
        chomp( my $hash = $out[0] );
        while ( -e $hash . ".$ext" ) {
            ++$ext;
        }
        my $lname = $hash . "." . $ext;
        print("** Creating CA hash symlink '$lname' -> '$fname'\n");

        my $rc = symlink( $fname, $lname );
        chdir($odir) or die("chdir($odir) failed: $!\n");
        return $self->error("create symlink '$lname' -> '$fname' failed\n")
          unless ($rc);
        return 1;
    }

    sub _slurp {
        my ( $self, $file ) = @_;
        return do { local ( @ARGV, $/ ) = $file; <> };
    }

    # loadconfigkey $key [$file] global|server|$zimbra_server
    sub getConfKey {
        my ( $self, $key, $loc ) = @_;

        my @args;
        if ( $loc eq "global" ) {
            push( @args, "getConfig" );
        }
        else {
            $loc = $self->lc->get("zimbra_server_hostname")
              if ( $loc eq "server" );
            push( @args, "getServer", $loc );
        }

        warn("DEBUG: getting '$key' via zmprov @args\n") if $self->Debug;
        my @err = $self->Debug ? () : "2>/dev/null";
        my @out = $self->run( $self->Zmprov, qw(-m -l), @args, $key, @err );
        return undef unless ( $? == 0 );

        my $val = "";
        foreach my $line (@out) {
            $line =~ s/^$key: //;
            $val .= $line;
        }
        return $val;
    }

    sub saveConfKey {
        my ( $self, $key, $loc, $file ) = @_;
        $self->_checkFiles($file) or return undef;

        my @args;
        if ( $loc eq "global" ) {
            push( @args, "modifyConfig" );
        }
        else {
            $loc = $self->lc->get("zimbra_server_hostname")
              if ( $loc eq "server" );
            push( @args, "modifyServer", $loc );
        }

        print("** Saving config key '$key' via zmprov @args...");
        my $content = $self->_slurp($file);
        my @err     = $self->Debug ? () : "2>/dev/null";
        my @out =
          $self->run( $self->Zmprov, qw(-m -l), @args, $key, $content, @err );
        my $rc = $? >> 8;
        print( $rc == 0 ? "ok" : "failed (rc=$rc)", "\n" );
        return $rc == 0 ? 1 : undef;
    }

    # saveCertToLdap <self|comm> [-allservers]
    sub savecrt {
        my ( $self, $type ) = ( shift, @_ );
        warn("DEBUG: savecrt(@_)\n") if $self->Debug;
        $self->_checkType($type) or return undef;

        my $keyf = $self->sslFiles( $type . "_key" );
        my $crtf = $self->sslFiles( $type . "_crt" );
        my $loc  = $self->Allservers ? "global" : "server";

        # COMPAT: old zmcertmgr ignored errors...
        $self->saveConfKey( "zimbraSSLCertificate", $loc, $crtf )
          or return undef;
        $self->saveConfKey( "zimbraSSLPrivateKey", $loc, $keyf )
          or return undef;

        return 1;
    }

    # getCertFromLdap <self|comm> [-allservers]
    sub getcrt {
        my ( $self, $type ) = ( shift, @_ );
        warn("DEBUG: getcrt(@_)\n") if $self->Debug;
        $self->_checkType($type) or return undef;

        my $keyf = $self->sslFiles( $type . "_key" );    # private key
        my $crtf = $self->sslFiles( $type . "_crt" );    # certificate

        my $scope     = $self->Allservers ? "global" : "server";
        my %file_data = (
            $crtf => $self->getConfKey( "zimbraSSLCertificate", $scope ),
            $keyf => $self->getConfKey( "zimbraSSLPrivateKey",  $scope ),
        );

        # COMPAT: old version did not recreate an existing ca_pem
        # recreate the commercial ca_crt from the concatenated cert in ldap
        if ( $type eq "comm" and $file_data{$crtf} ) {
            my $ca_pem = $self->sslFiles( $type . "_ca_crt" );    # PEM format
            my @cert   = $self->getFromConcatData( $file_data{$crtf} );
            shift @cert;    # skip the first cert
            $file_data{$ca_pem} = join( "", @cert );
        }

        foreach my $file ( sort keys %file_data ) {
            if ( -f $file ) {
                warn("DEBUG: removing '$file'\n") if $self->Debug;
                unlink($file);
            }
            my $data = $file_data{$file};
            if ($data) {
                print("** Creating $file\n");
                open( my $ofh, ">", $file )
                  or Carp::confess("getcrt: open '$file' failed: $!\n");
                print {$ofh} $data;
            }
        }
        return 1;
    }

    sub _checkFiles {
        my ( $self, @files ) = @_;
        my $err = 0;
        foreach my $file (@files) {
            if ( !-r $file ) {
                $self->error("Can't read file '$file'\n");
                $err++;
            }
        }
        return $err ? undef : scalar @files;
    }

    sub _checkType {
        my ( $self, $type ) = @_;
        return $self->error("no type argument specified\n")
          unless ( defined $type );
        return ( $type =~ /^(?:self|comm)$/ )
          ? $type
          : $self->error("invalid type '$type' !~ self|comm\n");
    }

    # verifycrt <self|comm> [[[priv_key] [certfile]] [ca_chain_file]]
    sub verifycrt {
        my ( $self, $type, $keyf, $crtf, $ca_pem ) = ( shift, @_ );
        warn("DEBUG: verifycrt(@_)\n") if $self->Debug;
        $self->_checkType($type) or return undef;

        $keyf   ||= $self->sslFiles( $type . "_key" );    # private key
        $crtf   ||= $self->sslFiles( $type . "_crt" );    # certificate
        $ca_pem ||= $self->sslFiles(
            ( $type eq "comm" ? "${type}_" : "" ) . "ca_crt"    # PEM format
        );

        my $rc = $self->verifycrtkey( $keyf, $crtf );
        return undef unless $rc;

        # check validity of the cert
        return $self->verifycrtchain( $ca_pem, $crtf );
    }

    sub verifycrtchain {
        my ( $self, $cafile, $crtf ) = ( shift, @_ );

        my $usage = "verifycrtchain <ca_chain_file> <certfile>";
        die("$usage: missing 'ca_chain_file' argument\n") unless ($cafile);
        die("$usage: missing 'certfile' argument\n")      unless ($crtf);
        warn("DEBUG: verifycrtchain(@_)\n") if $self->Debug;

        print("** Verifying '$crtf' against '$cafile'\n");
        $self->_checkFiles(@_) or return undef;

        my @out =
          $self->run( $self->Openssl, qw(verify -purpose sslserver -CAfile),
            $cafile, $crtf, "2>&1" );
        chomp(@out);
        if ( $out[0] and $out[0] eq "$crtf: OK" ) {
            print("Valid certificate chain: @out\n");
            return 1;
        }
        else {
            $self->error( "Unable to validate certificate chain",
                ( @out ? ( ": ", join( "\n", @out ) ) : "." ), "\n" );
            return undef;
        }
    }

    sub verifycrtkey {
        my ( $self, $keyf, $crtf ) = ( shift, @_ );

        my $usage = "verifycrtkey <priv_key> <certfile>";
        die("$usage: missing 'priv_key' argument\n") unless ($keyf);
        die("$usage: missing 'certfile' argument\n") unless ($crtf);
        warn("DEBUG: verifycrtkey(@_)\n") if $self->Debug;

        print("** Verifying '$crtf' against '$keyf'\n");
        $self->_checkFiles(@_) or return undef;

        my $ssl = $self->Openssl;
        my $keydg =
          $self->run("$ssl pkey -pubout -in '$keyf' | $ssl sha256");
        my $crtdg =
          $self->run("$ssl x509 -noout -pubkey -in '$crtf' | $ssl sha256");

        # set @err unless hashes match
        my $info = "Certificate '$crtf' and private key '$keyf'";
        my @err =
            ( $keydg and $crtdg and $keydg eq $crtdg )
          ? ()
          : ("do not");
        $info = join( " ", $info, @err, "match.\n" );

        return @err ? $self->error($info) : print($info);
    }

    # NOTE: reversed args (ORIG: $cfile, csr|crt)
    # getSubjectAltNames( crt|csr, $cfile )
    sub getSubjectAltNames {
        my ( $self, $rtype, $cfile ) = ( shift, @_ );
        warn("DEBUG: getSubjectAltNames(@_)\n") if $self->Debug;

        $rtype = "" unless ( defined $rtype );
        Carp::confess("invalid request type '$rtype (should be: crt|csr)'\n")
          unless ( $rtype =~ /^(?:crt|csr)$/ );

        $self->_checkFiles($cfile) or return undef;

        my $req = $rtype eq "crt" ? "x509" : "req";
        my @out =
          $self->run( $self->Openssl, $req, "-in", $cfile, "-text", "2>&1" );
        if ( $? != 0 ) {
            $self->error( "openssl $req failed(", $? >> 8, "):\n", @out );
            return undef;
        }

        my ( $names, $match ) = ( "", 0 );
        foreach my $line (@out) {
            unless ($match) {
                $match++ if ( $line =~ /Subject Alternative Name/ );
                next;
            }
            chomp($line);
            $line =~ s/^\s*//;
            $line =~ s/DNS://g;
            $names = $line;
            last;
        }
        print("SubjectAltName=$names\n");
        return 1;
    }

    # viewCsrOrCrt( crt|csr, $cfile, [$info] )
    sub viewCsrOrCrt {
        my ( $self, $rtype, $file, $info ) = ( shift, @_ );

        $info ||= "";
        $rtype = "" unless ( defined $rtype );
        Carp::confess("invalid request type '$rtype (should be: crt|csr)'\n")
          unless ( $rtype =~ /^(?:crt|csr)$/ );

        $self->_checkFiles($file) or return undef;

        my %args = (
            "csr" => { cmd => "req",  opt => [qw(-subject)] },
            "crt" => { cmd => "x509", opt => [qw(-dates -subject -issuer)] },
        );
        my ( $cmd, $opt ) = @{ $args{$rtype} }{qw(cmd opt)};

        my @out =
          $self->run( $self->Openssl, $cmd, "-in", $file, @$opt, "-noout" );

        my $err;
        if ( $? != 0 ) {
            $self->error( "openssl $cmd on '$file' failed(", $? >> 8, ")\n" );
            $err++;
        }
        print( "- ", $info, $file, "\n", @out );

        $err++ unless !$err && $self->getSubjectAltNames( $rtype, $file );
        return ( $err ? undef : 1 );
    }

    # viewcsr <self|comm> [csrffile]
    sub viewcsr {
        my ( $self, $type, $csrf ) = ( shift, @_ );
        warn("DEBUG: viewcsr(@_)\n") if $self->Debug;
        $self->_checkType($type) or return undef;
        $csrf ||= $self->sslFiles( $type . "_csr" );
        return $self->viewCsrOrCrt( "csr", $csrf );
    }

    # viewstagedcrt <self|comm> [certfile]
    sub viewstagedcrt {
        my ( $self, $type, $crtf ) = ( shift, @_ );
        warn("DEBUG: viewstagedcrt(@_)\n") if $self->Debug;
        $self->_checkType($type) or return undef;
        $crtf ||= $self->sslFiles( $type . "_crt" );
        return $self->viewCsrOrCrt( "crt", $crtf );
    }

    sub viewdeployedcrt {
        my ( $self, $sname ) = ( shift, @_ );

        my $usage = "viewdeployedcrt [all|ldap|mailboxd|mta|proxy]";
        warn("DEBUG: viewdeployedcrt(@_)\n") if $self->Debug;

        if ($sname) {
            die("$usage: unknown service '$sname'\n")
              unless $self->_isValidService($sname);
        }

        my %svc = $self->_getServiceInfo($sname);
        my $err = 0;

        foreach my $name ( sort keys %svc ) {
            my $crtf = $svc{$name};

            if ( $name eq "mailboxd" ) {
                my $ks = $self->sslFiles("keystore");
                if ( !$self->lc->get("mailboxd_server") ) {
                    warn("NOTE: possibly stale keystore: $ks\n") if ( -f $ks );
                    warn("DEBUG: viewdeployedcrt: skip non $name server\n")
                      if $self->Debug;
                    next unless ( -f $crtf );
                }
                elsif ( -f $ks ) {
                    unless ( $self->_keystoreToPEM ) {
                        $err++;
                        next;
                    }
                }
            }

            # BUG? ORIG code use ERROR:...
            unless ( -f $crtf ) {
                print("NOTE: $name: file '$crtf' does not exist.\n");
                next;
            }
            $err++ unless $self->viewCsrOrCrt( "crt", $crtf, "$name: " );
        }
        return $err ? undef : 1;
    }

    sub _getServiceInfo {
        my ( $self, $sname, $nofiles ) = @_;
        $sname ||= "all";

        # ldap => ldap_crt, ...
        my %svc;
        foreach my $s (qw(ldap mailboxd mta proxy)) {
            $svc{$s} = $nofiles ? 1 : $self->sslFiles( $s . "_crt" );
        }
        return ( $sname eq "all" ) ? %svc : ( $sname => $svc{$sname} );
    }

    sub _isValidService {
        my ( $self, $sname ) = @_;
        Carp::confess("_isValidService: no service argument specified\n")
          unless ($sname);
        return $self->_getServiceInfo( $sname, "nofiles" ) ? 1 : undef;
    }

    sub _keystoreToPEM {
        my ($self) = @_;
        my $store  = $self->sslFiles("keystore");
        my $derf   = $self->sslFiles("mbs_der");
        my $crtf   = $self->sslFiles("mailboxd_crt");
        my $name   = "mailboxd";
        my $msvr   = $self->lc->get("mailboxd_server")
          or Carp::confess("error: local config 'mailboxd_server' not set");

        my @out =
          $self->runMailboxKeytool( "-export", "-file", $derf,
            "-alias", $msvr, );
        if ( $? != 0 or !-f $derf ) {
            $self->error( "$name: export to '$derf' failed(",
                $? >> 8, "):\n", @out );
            return undef;
        }

        @out = $self->run(
            $self->Openssl, "x509", "-inform", "DER",
            "-outform",     "PEM",  "-in",     $derf,
            "-out",         $crtf
        );
        if ( $? != 0 or !-f $crtf ) {
            $self->error( "$name: convert to '$crtf' failed(",
                $? >> 8, "):\n", @out );
            return undef;
        }
        return 1;
    }

    # checkcrtexpiration [-days 30] $service
    sub checkcrtexpiration {
        my ( $self, $sname ) = ( shift, @_ );

        my $usage = "checkcrtexpiration [all|ldap|mailboxd|mta|proxy]";
        warn("DEBUG: checkcrtexpiration(@_)\n") if $self->Debug;

        if ($sname) {
            die("$usage: unknown service '$sname'\n")
              unless $self->_isValidService($sname);
        }

        my %svc  = $self->_getServiceInfo($sname);
        my $err  = 0;
        my $days = $self->Days;
        my $sec  = $days * 24 * 60 * 60;
        my $tagl =
          length( [ sort { length $b <=> length $a } keys %svc ]->[0] ) + 1;

        foreach my $name ( sort keys %svc ) {
            my $crtf = $svc{$name};

            if ( $name eq "mailboxd" ) {
                my $ks = $self->sslFiles("keystore");
                if ( !$self->lc->get("mailboxd_server") ) {
                    warn("NOTE: possibly stale keystore: $ks\n") if ( -f $ks );
                    warn("DEBUG: checkcrtexpiration: skip non $name server\n")
                      if $self->Debug;
                    next unless ( -f $crtf );
                }
                elsif ( -f $ks ) {
                    unless ( $self->_keystoreToPEM ) {
                        $err++;
                        next;
                    }
                }
            }

            # BUG? ORIG code use ERROR:...
            unless ( -f $crtf ) {
                print("NOTE: $name: file '$crtf' does not exist.\n");
                next;
            }

            my @cmd = ( $self->Openssl, "x509", "-in", $crtf, "-noout" );

            # rc(0) not expiring; rc(1) expired/expiring
            my $msg;
            my $dinfo = "$days days";
            my ( $rc, @end );
            foreach my $t ( 0, $sec ) {
                chomp( @end = $self->run( @cmd, "-enddate" ) );

                $self->run( @cmd, "-checkend", $t );
                $rc = $? >> 8;
                if ( $t == 0 ) {
                    if ( $rc == 1 ) {
                        $msg = "EXPIRED!" && $err++;
                        last;
                    }
                }
                else {
                    $err++ if ( $rc != 0 );
                    if ( $rc == 1 ) {
                        $msg = "EXPIRES within $dinfo!";
                    }
                    elsif ( $rc == 0 ) {
                        $msg = "expires outside of $dinfo (OK)";
                    }
                    else {
                        $msg = "(ERROR) openssl x509 returned $rc\n";
                    }
                }
            }
            printf( "%-${tagl}s @end '$crtf' $msg\n", "$name:" )
              if ( $rc or -t STDIN );
        }
        return $err ? undef : 1;
    }

    # createkeystore <self|comm>
    sub createkeystore {
        my ( $self, $type ) = ( shift, @_ );
        warn("DEBUG: createkeystore(@_)\n") if $self->Debug;
        $self->_checkType($type) or return undef;

        my $keyf = $self->sslFiles( $type . "_key" );
        my $crtf = $self->sslFiles( $type . "_crt" );
        $self->_checkFiles( $keyf, $crtf ) or return undef;

        # clean up any previous settings first
        my $keystore = $self->sslFiles("keystore");
        my $server   = $self->lc->get("mailboxd_server");
        $server ||= $self->lc->get("zimbra_server_hostname");

        my @out;
        my @cmd = ( "-delete", "-alias", $server );
        if ( -f $keystore ) {
            @out = $self->runMailboxKeytool(@cmd);
            if ( $? != 0 and !grep { /does not exist/ } @out ) {
                $self->error( "mailboxd keytool(@cmd) returned non-zero(",
                    $? >> 8, "):\n", @out );
            }
        }

        # loading keys and certificates via PKCS12
        # - store both private key and certificate in the keystore
        my $pkcsf = $self->sslFiles("pkcs");
        my $kpass = $self->lc->get("mailboxd_keystore_password");
        print("** Creating file '$pkcsf'\n");
        @out = $self->run(
            $self->Openssl, "pkcs12", "-propquery", "-fips", "-inkey", $keyf,
            "-in",          $crtf,    "-name",  $server,
            "-export",      "-out",   $pkcsf,   "-passout",
            "pass:$kpass",  "2>&1"
        );
        if ( $? != 0 or !-s $pkcsf ) {
            $self->error( "openssl pkcs12 export to '$pkcsf' failed(",
                $? >> 8, "):\n", @out );
            return undef;
        }

        print("** Creating keystore '$keystore'\n");
        my $cpath =
"/opt/zextras/lib/ext/com_zimbra_cert_manager/com_zimbra_cert_manager.jar";
        my $class = "com.zimbra.cert.MyPKCS12Import";

        @out = $self->run(
            $self->Java, "-classpath", $cpath, $class,
            $pkcsf,      $keystore,    $kpass, $kpass,
            "2>&1",
        );
        if ( $? != 0 or !-s $keystore ) {
            $self->error( "$class to '$pkcsf' returned non-zero(",
                $? >> 8, "):\n", @out );
            return undef;
        }

        return 1;
    }

    sub addcacert {
        my ( $self, $crtf, $alias ) = ( shift, @_ );
        Carp::confess("addcacert: no certfile argument specified\n")
          unless ($crtf);
        warn("DEBUG: addcacert(@_)\n") if $self->Debug;
        $self->_checkFiles($crtf) or return undef;

        $alias ||= "zcs-user-" . File::Basename::fileparse( $crtf, '\.[^.]*$' );

        my $cacf = $self->sslFiles("cacerts");
        print("** Importing cert '$crtf' as '$alias' into cacerts '$cacf'\n");

        my @cmd = ( "-delete", "-alias", $alias );
        my @out = $self->runCacertsKeytool(@cmd);
        if ( $? != 0 and !grep { /does not exist/ } @out ) {
            $self->error( "cacerts keytool(@cmd) returned non-zero(",
                $? >> 8, "):\n", @out );
        }

        @cmd = ( "-import", "-alias", $alias, "-noprompt", "-file", $crtf );
        @out = $self->runCacertsKeytool(@cmd);
        if ( $? != 0 ) {
            $self->error( "cacerts keytool(@cmd) returned non-zero(",
                $? >> 8, "):\n", @out );
            return undef;
        }

        print("** NOTE: restart mailboxd to use the imported certificate.\n");
        return 1;
    }

    sub migrate {
        my ($self) = @_;

        my $olddir = "/opt/zextras/ssl/ssl";
        my $curdir = $self->sslDirs("ssl_directory");
        unless ( -d $olddir ) {
            print("** No '$olddir' directory. Nothing to migrate.\n");
            return;
        }

        $self->initSSLDirs or return undef;

        my $prev_ca_dir   = "$olddir/ca";
        my $prev_cert_dir = "$olddir/server";

        print("** Migrating ssl certs from '$olddir' to '$curdir'\n");
        my %prev = (
            ca_crt   => "$prev_ca_dir/ca.pem",
            ca_csr   => "$prev_ca_dir/ca.csr",
            ca_key   => "$prev_ca_dir/ca.key",
            ca_srl   => "$prev_ca_dir/ca.srl",
            self_crt => "$prev_cert_dir/server.crt",
            self_csr => "$prev_cert_dir/server.csr",
            self_key => "$prev_cert_dir/server.key",
            comm_crt => "$prev_cert_dir/mailboxd.crt",
            comm_csr => "$prev_cert_dir/mailboxd.csr",
        );

        foreach my $key ( sort keys %prev ) {
            my ( $oldf, $newf ) = ( $prev{$key}, $self->sslFiles($key) );
            if ( -f $oldf ) {
                $self->_copy( $oldf, $newf )
                  or return undef;
            }
        }
        return 1;
    }

    sub createConf {
        my ( $self, $ofile, @altnames ) = @_;
        warn("DEBUG: createConf '$ofile' altnames: @altnames\n")
          if $self->Debug;

        # memoize-ish to avoid recreating the same config over and over
        return 1 if $self->{__createConf} and $self->{__createConf} eq "@_";
        $self->{__createConf} = "@_";

        # return in order from caller w/o dups, should we sort?
        my $svrname = $self->lc->get("zimbra_server_hostname");
        my ( @names, %seen );

        foreach my $name (@altnames) {
            my $lcname = lc($name);
            next if ( $seen{$lcname}++ > 0 );
            push( @names, $name );
        }

        my @san =
          @names
          ? ( "subjectAltName = " . join( ",", map( "DNS:$_", @names ) ) )
          : ();
        my @subst = (
            [ '@@HOSTNAME@@'           => $svrname ],
            [ '@@ssl_default_digest@@' => $self->Digest ],
            [ '@@SUBJECT_ALT_NAMES@@'  => join( ",", @san ) ],
        );

        my $ifile = $self->sslFiles("ssl_conf_in");

        # Creating/Recreating...
        print( "** ", ( -f $ofile ? "Rec" : "C" ), "reating $ofile\n" );
        open( my $ifh, "<", $ifile )
          or Carp::confess("createConf: open '$ifile' failed: $!\n");
        open( my $ofh, ">", $ofile )
          or Carp::confess("createConf: open '$ofile' failed: $!\n");

        while ( my $line = <$ifh> ) {
            map( $line =~ s/$_->[0]/$_->[1]/, @subst );
            print( $ofh $line );
        }
        return 1;
    }

    sub backupSSLDirs {
        my ($self) = @_;
        if ( $self->{__skipbackup}++ ) {    # only do this once
            warn("DEBUG: skipping backupSSLDirs\n") if $self->Debug;
            return 2;
        }

        my $dir = $self->sslDirs("ssl_directory");
        warn("DEBUG: backupSSLDirs($dir)\n") if $self->Debug;

        if ( -d $dir ) {
            my $ts   = POSIX::strftime( "%Y%m%d%H%M%S", localtime(time) );
            my $dest = $dir . "." . $ts;
            my $dpar = File::Basename::dirname($dest);
            unless ( -w $dpar ) {
                $self->error(
"backup directory '$dpar' not writable, check owner/perms?\n"
                );
                return undef;
            }

            # look for unreadable files like:
            #   /opt/zextras/ssl/carbonio/ca/{ca.srl,index.txt*,newcerts/*.pem}
            my @noread;
            File::Find::find(
                sub { push( @noread, $File::Find::name ) unless -r; }, $dir );
            if (@noread) {
                $self->error("backup unable to read files: @noread\n");
                return undef;
            }

            print("** Backup $dir to $dest\n");
            system( "cp", "-pr", $dir, $dest );
            if ( $? != 0 ) {
                $self->error( "backup '$dir' to '$dest' returned non-zero(",
                    $? >> 8, ")\n" );
                return undef;
            }
        }
        return 1;
    }

    sub _checkStat {
        my ( $self, $etag, $item, $zn, $zu ) = @_;
        return $self->error("$etag: no write permission for '$item'\n")
          unless ( -w $item );

        my $stat = File::stat::stat($item);
        return $self->error("$etag: stat '$item' failed: $!\n")
          unless ($stat);

        # only "warn" about wrong ownership
        my $ou = $stat->uid;
        unless ( $ou == $zu ) {
            my $on = getpwuid($ou);
            $self->error(
                "$etag: owner '$on' != '$zn' ($ou!=$zu) for '$item'\n");
        }
        return 1;
    }

    # create all necessary directories
    sub initSSLDirs {
        my ($self) = @_;
        if ( $self->{__skipinit}++ ) {    # only do this once
            warn("DEBUG: skipping initSSLDirs\n") if $self->Debug;
            return 2;
        }
        warn("DEBUG: initSSLDirs\n") if $self->Debug;

        my @dirs = sort values %{ $self->sslDirs };
        push( @dirs, $self->sslDirs("ca_directory") . "/newcerts" );

        # zextras username and uid
        my $zn = $self->Owner;
        my $zu = ( getpwnam($zn) )[2];
        my ( $err, $etag ) = ( 0, "initSSLDirs" );

        my $caconfd = $self->sslDirs("ca_conf_dir");
        foreach my $dir (@dirs) {
            my $e = 0;
            if ( -d $dir ) {
                $self->_checkStat( $etag, $dir, $zn, $zu )
                  or $e++;
            }
            else {
                print("** Creating directory '$dir'\n");
                unless ( File::Path::make_path($dir) ) {
                    $self->error("$etag: mkdir '$dir' failed: $!\n");
                    $e++;
                }
            }

            # special case conf/ca permissions to be world r-x
            if ( !$e and $dir eq $caconfd ) {
                unless ( chmod( 0755, $dir ) ) {
                    $self->error("$etag: chmod(0755) '$dir' failed: $!\n");
                    $e++;
                }
            }
            $err += $e;
        }

        # BUG?: do anything special with index.txt?
        my @files =
          ( $self->Randfile, $self->sslDirs("ca_directory") . "/index.txt", );

        # if cacerts or keystore exist, ensure they are writable
        my @fextra = $self->Command =~ /^deploy/ ? qw(cacerts keystore) : ();
        foreach my $key (@fextra) {
            push( @files, $self->sslFiles($key) ) if -f $self->sslFiles($key);
        }
        foreach my $file (@files) {
            if ( -f $file ) {
                $self->_checkStat( $etag, $file, $zn, $zu )
                  or $err++;
                next;
            }
            print("** Touching file '$file'\n");
            unless ( open( my $ofh, ">>", $file ) ) {
                warn("$etag: touch '$file' failed: $!\n");
                $err++;
            }
        }

        return $err ? undef : 1;
    }

    sub confDir { return $_[0]->Home . "/conf"; }

    sub sslDirs {
        my ( $self, @dirs ) = @_;
        Carp::croak("only one dir arg allowed\n") if ( @dirs > 1 );

        if ( !$self->{sslDirs} ) {
            my $based = $self->Home . "/ssl/carbonio";
            my $confd = $self->confDir;

            $self->{sslDirs} = {
                ca_conf_dir         => "$confd/ca",    # deployed ca
                ca_directory        => "$based/ca",    # zimbra_ca_directory
                comm_cert_directory =>
                  "$based/commercial",    # zimbra_comm_cert_directory
                self_cert_directory =>
                  "$based/server",        # zimbra_self_cert_directory
                ssl_directory => $based,  # zimbra_ssl_directory
            };
        }

        Carp::confess("sslDirs: no match for key '@dirs'\n")
          if ( @dirs == 1 and !$self->{sslDirs}->{ $dirs[0] } );

        return @dirs ? @{ $self->{sslDirs} }{@dirs} : $self->{sslDirs};
    }

    sub sslFiles {
        my ( $self, @files ) = @_;
        if ( !$self->{sslFiles} ) {
            my $etcdir  = $self->Home . "/mailboxd/etc";
            my $confdir = $self->confDir;
            my $confcad = $self->sslDirs("ca_conf_dir");
            my $cadir   = $self->sslDirs("ca_directory");
            my $commdir = $self->sslDirs("comm_cert_directory");
            my $selfdir = $self->sslDirs("self_cert_directory");
            my $ssldir  = $self->sslDirs("ssl_directory");

            $self->{sslFiles} = {

                self_crt => $selfdir . "/server.crt",    # self_server_crt
                self_csr => $selfdir . "/server.csr",    # self_server_csr
                self_key => $selfdir . "/server.key",    # self_server_key

                # OLD:  was hardcoded
                pkcs => $ssldir . "/jetty.pkcs12",

                # OLD: comm_ => commercial_*
                comm_ca_crt => $commdir . "/commercial_ca.crt",
                comm_crt    => $commdir . "/commercial.crt",
                comm_csr    => $commdir . "/commercial.csr",
                comm_key    => $commdir . "/commercial.key",

                mbs_der      => $etcdir . "/mailboxd.der",    # ~ service_dir
                mailboxd_crt => $etcdir . "/mailboxd.pem",    # ~ service_crt

                # OLD: zimbra_*
                ca_crt      => $cadir . "/ca.pem",
                ca_csr      => $cadir . "/ca.csr",
                ca_key      => $cadir . "/ca.key",
                ca_srl      => $cadir . "/ca.srl",
                ssl_conf_ca => $cadir . "/zmssl.cnf",

                # OLD: in_ssl_conf and zimbra_cert_ssl_conf
                ssl_conf_in   => $confdir . "/zmssl.cnf.in",
                ssl_conf_cert => $confdir . "/zmssl.cnf",
                ldap_crt      => $confdir . "/slapd.crt",
                ldap_key      => $confdir . "/slapd.key",
                mta_crt       => $confdir . "/smtpd.crt",
                mta_key       => $confdir . "/smtpd.key",
                proxy_crt     => $confdir . "/nginx.crt",
                proxy_key     => $confdir . "/nginx.key",

                cacerts        => $self->lc->get("mailboxd_truststore"),
                keystore       => $self->lc->get("mailboxd_keystore"),

                # deployed CA
                conf_ca_crt => "$confcad/ca.pem",
                conf_ca_key => "$confcad/ca.key",
            };
        }

        Carp::confess("sslFiles: no match for key '@files'\n")
          if ( @files == 1 and !$self->{sslFiles}->{ $files[0] } );

        return @files ? @{ $self->{sslFiles} }{@files} : $self->{sslFiles};
    }

    # digest - now fatal if invalid
    sub validDigest {
        my ( $self, $dig ) = @_;
        if ( $dig !~ /^(?:ripemd160|sha(?:|1|224|256|384|512))/ ) {
            $dig |= "";
            return $self->error("unknown digest method '$dig'\n");
        }
        return $dig;
    }

    # check executables
    sub verifyExe {
        my ( $self, $exe ) = @_;
        Carp::confess("unable to find/run '$exe'\n")
          unless ( -x $exe );
    }

    sub Debug {
        my ( $self, $val ) = @_;
        if ( @_ > 1 ) {
            die("Debug '$val' must be numeric (>=0)\n")
              unless ( defined $val and $val =~ /^\d+$/ );
            $self->{Debug} = $val;
        }
        $self->{Debug};
    }

    sub Home {
        my ( $self, $dir ) = @_;
        if ( @_ > 1 ) {
            Carp::confess("Home '$dir' does not exist\n")
              unless ( defined $dir and -d $dir );
            $self->{Home} = $dir;
        }
        $self->{Home};
    }

    sub Java {
        my ( $self, $exe ) = @_;
        if ( @_ > 1 and $self->verifyExe($exe) ) {
            $self->{Java} = $exe;
            my $jhome = $exe;
            $jhome =~ s,/bin/java\.?\w*$,,;
            $ENV{JAVA_HOME} = $jhome;
        }
        $self->{Java};
    }

    sub Keytool {
        my ( $self, $exe ) = @_;
        $self->{Keytool} = $exe if ( @_ > 1 and $self->verifyExe($exe) );
        $self->{Keytool};
    }

    sub Openssl {
        my ( $self, $exe ) = @_;
        $self->{Openssl} = $exe if ( @_ > 1 and $self->verifyExe($exe) );
        $self->{Openssl};
    }

    sub Zmprov {
        my ( $self, $exe ) = @_;
        $self->{Zmprov} = $exe if ( @_ > 1 and $self->verifyExe($exe) );
        $self->{Zmprov};
    }

    # avoid "unable to write 'random state' errors from openssl
    sub Randfile {
        my ( $self, $file ) = @_;
        if ( @_ > 1 ) {
            $ENV{RANDFILE} = $self->{Randfile} = $file;
        }
        $self->{Randfile};
    }

    sub Digest {
        my ( $self, $dig ) = @_;
        if ( @_ > 1 ) {
            return undef unless $self->validDigest($dig);
            $self->{Digest} = $dig;
        }
        $self->{Digest};
    }

    sub Allservers {
        ( @_ > 1 ) ? $_[0]->{Allservers} = $_[1] : $_[0]->{Allservers};
    }

    sub Command {
        ( @_ > 1 ) ? $_[0]->{Command} = $_[1] : $_[0]->{Command};
    }

    # validation_days
    sub Days {
        my ( $self, $days ) = @_;
        if ( @_ > 1 ) {
            return $self->error("invalid days '$days': must be > 0\n")
              unless ( $days and $days > 0 );
            $self->{Days} = $days;
        }
        $self->{Days};
    }

    sub Deploy {
        my ( $self, @svcs ) = @_;
        if ( @_ > 1 ) {
            my @tmp = map( ref($_) ? @$_ : $_, @svcs );
            foreach my $sname (@tmp) {
                return $self->error("deploy: unknown service '$sname'\n")
                  unless $self->_isValidService($sname);
            }
            $self->{Deploy} = \@tmp;
        }
        return @{ $self->{Deploy} || ["all"] };
    }

    sub Keysize {
        my ( $self, $size ) = @_;
        if ( @_ > 1 ) {
            return $self->error("invalid keysize '$size': must be >= 2048\n")
              unless ( $size and $size >= 2048 );
            $self->{Keysize} = $size;
        }
        $self->{Keysize};
    }

    sub lc { shift->Localconfig(@_); }

    sub Localconfig {
        ( @_ > 1 ) ? $_[0]->{Localconfig} = $_[1] : $_[0]->{Localconfig};
    }

    sub Localonly {
        ( @_ > 1 ) ? $_[0]->{Localonly} = $_[1] : $_[0]->{Localonly};
    }

    sub New {
        ( @_ > 1 ) ? $_[0]->{New} = $_[1] : $_[0]->{New};
    }

    sub Newkey {
        ( @_ > 1 ) ? $_[0]->{Newkey} = $_[1] : $_[0]->{Newkey};
    }

    sub Owner {
        ( @_ > 1 ) ? $_[0]->{Owner} = $_[1] : $_[0]->{Owner};
    }

    sub Subject {
        my ( $self, $subj ) = @_;
        $self->{Subject} = $subj if ( @_ > 1 );
        defined $self->{Subject} ? $self->{Subject} : $self->_defaultSubject;
    }

    # do not force zmhostname in SAN when using -noDefaultSubjectAltName
    sub defAltName {
        my ($self) = @_;
        return $self->Defaultsubjectaltname
          ? ( $self->lc->get("zimbra_server_hostname") )
          : ();
    }

    sub Defaultsubjectaltname {
        ( @_ > 1 )
          ? $_[0]->{Defaultsubjectaltname} = $_[1]
          : $_[0]->{Defaultsubjectaltname};
    }

    sub Subjectaltnames {
        my ( $self, @names ) = @_;
        if ( @_ > 1 ) {
            my @tmp = map( ref($_) ? @$_ : $_, @names );
            $self->{Subjectaltnames} = \@tmp;
        }
        return @{ $self->{Subjectaltnames} || [] };
    }

    sub Type {
        ( @_ > 1 ) ? $_[0]->{Type} = $_[1] : $_[0]->{Type};
    }
}

{

    package Opts;

    use strict;
    use warnings;
    use Carp ();
    use Getopt::Long qw(GetOptions);
    use Pod::Usage qw(pod2usage);

    sub new {
        my ($class) = shift;
        my $self = bless( {}, ref($class) || $class );
        $self->{_data} = $self->_process_options(@_);
        return $self;
    }

    sub data {
        my ( $self, $key ) = @_;
        if ($key) {
            return $self->{_data}->{$key} if $self->{_data};
            return undef;
        }
        return %{ $self->{_data} || {} };
    }

    sub _process_options {
        my ( $self, $prog ) = @_;
        my ( %opt, @err );

        # BUGS?
        # - getcrt and savecrt: default to "comm" like old version!

        # need_type - undef (user must specify) or default (self or comm)
        # opts      - (sub)command line options
        # xargs     - arrayref w/list of number of extra args allowed
        # xinfo     - useful error info about the extra args allowed
        my @create_opts = qw(new keysize=i digest=s subject=s);
        my $services    = "[all|ldap|mailboxd|mta|proxy]";

        my %commands = (

            #TESTING "createkeystore" => { need_type => undef, },
            "addcacert" => {
                xargs => [1],
                xinfo => "<certfile>",
            },
            "createca" =>
              { opts => [ @create_opts, 'newkey', 'subjectaltnames=s@' ] },
            "checkcrtexpiration" => {
                opts  => ['days=i'],
                xargs => [ 0, 1 ],
                xinfo => $services,
            },

            # COMPAT: createcsr: OLD default type="self" via fall through
            "createcsr" => {
                need_type => undef,
                opts      => [
                    @create_opts, 'subjectaltnames=s@',
                    'defaultsubjectaltname!'
                ],
            },
            "createcrt" => {
                opts => [
                    @create_opts, 'subjectaltnames=s@',
                    'days=i',     'allservers',
                    'defaultsubjectaltname!'
                ]
            },
            "deployca" => { opts => ['localonly'], },

            # COMPAT: deploycrt: OLD default type="self" via fall through
            "deploycrt" => {
                need_type => undef,
                opts      => [ 'allservers', 'deploy=s@', 'localonly' ],
                xargs     => [ 0, 2 ],
                xinfo     =>
"<<self>|<comm [certfile ca_chain_file]>> [-localonly] [-allservers] [[-deploy $services] ...]",
            },

            # COMPAT: getcrt: OLD default type="comm" via fall through
            "getcrt" => {
                need_type => undef,
                opts      => ['allservers'],
            },

            # COMPAT: savecrt: OLD default type="comm" via fall through
            "savecrt" => {
                need_type => undef,
                opts      => ['allservers'],
            },
            "verifycrt" => {
                need_type => undef,
                xargs     => [ 0 .. 3 ],
                xinfo     => "[[[priv_key] [certfile]] [ca_chain_file]]",
            },
            "verifycrtchain" =>
              { xargs => [2], xinfo => "<ca_chain_file> <certfile>" },
            "verifycrtkey" =>
              { xargs => [2], xinfo => "<priv_key> <certfile>" },
            "viewcsr" =>
              { need_type => undef, xargs => [ 0, 1 ], xinfo => "<csr_file>" },
            "viewstagedcrt" =>
              { need_type => undef, xargs => [ 0, 1 ], xinfo => "<crt_file>" },
            "viewdeployedcrt" => {
                xargs => [ 0, 1 ],
                xinfo => $services,
            },
            "migrate" => {},
        );

        # COMPAT: viewcrt == viewstagedcrt
        $commands{viewcrt} = $commands{viewstagedcrt};

        # first arg is the "command"
        my ( $cmd, $opts, $xargs, $xinfo ) = ( "", [], [0], "" );
        if ( !@ARGV or $ARGV[0] =~ /^-/ ) {
            push( @err, "a command must be specified" );
        }
        elsif ( exists $commands{ $ARGV[0] } ) {
            $cmd   = $opt{command} = shift @ARGV;
            $opts  = $commands{$cmd}->{opts}  if ( $commands{$cmd}->{opts} );
            $xargs = $commands{$cmd}->{xargs} if ( $commands{$cmd}->{xargs} );
            $xinfo = $commands{$cmd}->{xinfo} if ( $commands{$cmd}->{xinfo} );

            # some commands require a second 'type' arg of 'self' or 'comm'
            if ( exists $commands{$cmd}->{need_type} ) {
                my $deftype = $commands{$cmd}->{need_type};
                if ( @ARGV and $ARGV[0] =~ /^(?:self|comm)$/ ) {
                    $opt{type} = shift @ARGV;
                }
                elsif ( $deftype and $deftype =~ /^(?:self|comm)$/ ) {
                    $opt{type} = $deftype;
                }
                else {
                    push( @err,
                        "$cmd: type 'self' or 'comm' must be specified" );
                }
            }
        }

        # else could push( @err, "unknown command '$ARGV[0]'" );
        my $rc = GetOptions( \%opt, @$opts, "help", "man", "debug:1" );
        pod2usage( -exitval => 0, -verbose => 1 ) if ( $opt{help} );
        pod2usage( -exitval => 0, -verbose => 2 ) if ( $opt{man} );
        pod2usage( -exitval => 1, -verbose => 0 ) if ( !$rc );

        unless ( grep { $_ eq scalar @ARGV } @$xargs ) {
            warn("DEBUG: xargs(@$xargs) #ARGV($#ARGV)\n") if $opt{debug};
            push( @err, "$cmd $xinfo" )                   if $xinfo;
            push( @err, "unexpected argument(s): @ARGV" ) if @ARGV;
        }

        push( @err, "$cmd: -newkey can only be used with -new" )
          if ( $opt{newkey} and !$opt{new} );

        pod2usage(
            -verbose => 1,
            -message => join( "\n", map( "$prog: $_", @err ) )
        ) if (@err);

        # turn any CSV names into separate values
        if ( $opt{deploy} ) {
            my @tmp = map split( /\s*,\s*/, $_ ), @{ $opt{deploy} };
            $opt{deploy} = \@tmp;
        }
        if ( $opt{subjectaltnames} ) {
            my @tmp = map split( /\s*,\s*/, $_ ), @{ $opt{subjectaltnames} };
            $opt{subjectaltnames} = \@tmp;
        }

        return \%opt;
    }
}

{

    package LocalConfig;

    use strict;
    use warnings;
    use Carp ();

    sub new {
        my ( $class, @attrs ) = @_;

        my $lc = "/opt/zextras/bin/zmlocalconfig";
        die("unable to execute '$lc': $!\n") unless ( -x $lc );

        my @cmd = ( $lc, qw(-s -q -m shell) );
        open( my $fh, "-|", @cmd )
          or die("open localconfig failed: $!\n");

        my $self = bless( {}, ref($class) || $class );
        my %conf;
        @conf{@attrs} = undef if (@attrs);

        while (<$fh>) {
            chomp;
            my ( $key, $val ) = split( /=/, $_, 2 );
            $val =~ s/';$//;
            $val =~ s/^'//;
            if (@attrs) {
                $conf{$key} = $val if ( exists $conf{$key} );
            }
            else {
                $conf{$key} = $val;
            }
        }
        Carp::confess("error: no data returned from local config")
          unless ( keys %conf );
        $self->{_data} = \%conf;
        return $self;
    }

    # an empty/undefined value is ok/expected for localconfig
    sub get {
        my ( $self, @attrs ) = @_;

        my @vals;
        foreach my $attr (@attrs) {
            my $val = $self->{_data}->{$attr};
            push( @vals, $val );
        }

        return $vals[0] if ( @attrs == 1 );
        return wantarray ? @vals : \@vals;
    }
}