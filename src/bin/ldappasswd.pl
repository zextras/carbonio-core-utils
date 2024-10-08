#!/usr/bin/perl

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

use strict;
use lib "/opt/zextras/common/lib/perl5";
use Zextras::Util::Common;
use File::Path;
use Getopt::Std;
use Net::LDAP;
use Net::LDAP::LDIF;
use Net::LDAP::Entry;
use Net::LDAP::Extension::SetPassword;
use Crypt::SaltedHash;
use MIME::Base64;

our %options = ();
our %loaded  = ();
our %saved   = ();

my $cur_rootdn_passwd       = getLocalConfig("ldap_root_password");
my $ldap_starttls_supported = getLocalConfig("ldap_starttls_supported");
my $zimbra_tmp_directory    = getLocalConfig("zimbra_tmp_directory");
my $isLdapMaster            = getLocalConfig("ldap_is_master");

chomp($isLdapMaster);
if ( lc($isLdapMaster) eq "true" ) {
    $isLdapMaster = 1;
}
else {
    $isLdapMaster = 0;
}

if ( !-d $zimbra_tmp_directory ) {
    File::Path::mkpath("$zimbra_tmp_directory");
}

getopts( 'arcblnph', \%options ) or die "Unable to set options\n";

if ( $options{h} ) {
    usage();
    exit 1;
}

if ( $options{r} +
    $options{p} +
    $options{l} +
    $options{n} +
    $options{a} +
    $options{b} > 1 )
{
    usage();
    exit 1;
}

if ( $options{c} && !$options{l} ) {
    usage();
    exit 1;
}

if ( $options{c} && $isLdapMaster ) {
    usage();
    exit 1;
}

if ( $#ARGV == -1 ) {
    usage();
    exit 1;
}

my $password = $ARGV[0];

# Get the SHA password.
my $ctx = Crypt::SaltedHash->new( algorithm => 'SHA-512', salt_len => '8' );
$ctx->add("$password");
my $ssha_password = $ctx->generate;

# Get the LDAP Master
my $ldap_master = getLocalConfig("ldap_master_url");

my @masters    = split( / /, $ldap_master );
my $master_ref = \@masters;
my $ldap;

print "Updating local config and LDAP\n";
if ( !$options{r} && !$options{c} ) {
    $ldap = Net::LDAP->new($master_ref) or die "$@";
}
else {
    $ldap = Net::LDAP->new(
        'ldapi://%2frun%2fcarbonio%2frun%2fldapi/')
      or die "$@";
}

if ( !$options{r} && !$options{c} ) {
    if ($ldap_starttls_supported) {
        my $mesg = $ldap->start_tls(
            verify => 'require',
            capath => "/opt/zextras/conf/ca",
        ) or die "start_tls: $@";
        $mesg->code && die "TLS: " . $mesg->error . "\n";
    }
}

if ( $options{r} ) {
    setLocalConfig( "ldap_root_password", "$password" );
    my $mesg = $ldap->bind( "cn=config", password => "$password" );
    if ( $mesg->code ) {
        $mesg = $ldap->bind( "cn=config", password => "$cur_rootdn_passwd" );
        my $entry = Net::LDAP::Entry->new;
        $entry->changetype("modify");
        $entry->dn('olcDatabase={0}config,cn=config');
        $entry->replace( olcRootPW => "$ssha_password", );
        $entry->update($ldap);
    }
}
elsif ( $options{l} ) {
    setLocalConfig( "ldap_replication_password", "$password" );
    my $mesg = $ldap->bind( 'uid=zmreplica,cn=admins,cn=zimbra',
        password => "$password" );
    if ( $mesg->code ) {
        $mesg = $ldap->bind( "cn=config", password => "$cur_rootdn_passwd" );
        if ( !$options{c} ) {
            $mesg = $ldap->set_password(
                user      => "uid=zmreplica,cn=admins,cn=zimbra",
                newpasswd => $password
            );
        }
    }
    if ( !$options{c} ) {
        my $infile  = "/opt/zextras/conf/carbonio.ldif";
        my $outfile = "$zimbra_tmp_directory/carbonio.ldif.$$";
        my $ldifin = Net::LDAP::LDIF->new( "$infile", "r", onerror => 'undef' );
        my $ldifout =
          Net::LDAP::LDIF->new( "$outfile", "w", onerror => 'undef' );
        my $entry;
        while ( not $ldifin->eof() ) {
            $entry = $ldifin->read_entry();
            if ( $ldifin->error() ) {
                print "Error msg: ",    $ldifin->error(),       "\n";
                print "Error lines:\n", $ldifin->error_lines(), "\n";
            }
            else {
                if ( $entry->dn() eq "uid=zmreplica,cn=admins,cn=zimbra" ) {
                    $entry->replace( userPassword => "$ssha_password", );
                }
                $ldifout->write($entry);
            }
        }
        $ldifin->done();
        $ldifout->done();
        if ( -s $outfile ) {
            my $rc = 0xffff & system("/bin/mv -f $infile $infile.bak");
            if ( $rc != 0 ) {
                print "Warning: Failed to backup $infile\n";
            }
            $rc = 0xffff & system("/bin/mv -f $outfile $infile");
            if ( $rc != 0 ) {
                print
"Failed to move $outfile to $infile\nRestoring old configuration\n";
                $rc = 0xffff & system("/bin/mv -f $infile.bak $infile");
                if ( $rc != 0 ) {
                    print "Failed to restore backup\n";
                }
            }
            else {
                system("rm -f $infile.bak");
            }
        }
    }
    $mesg = $ldap->search(
        base   => "olcDatabase={2}mdb,cn=config",
        filter => "(olcSyncrepl=*)",
        attrs  => ['olcSyncrepl']
    );
    my $size = $mesg->count;
    if ( $size > 0 ) {
        my $entry = $mesg->entry(0);
        my $attr  = $entry->get_value("olcSyncrepl");
        my ( $attr1, $attr2 );
        ( $attr, $attr1 )  = split( /credentials=/, $attr, 2 );
        ( $attr1, $attr2 ) = split( /filter=/, $attr1, 2 );
        $attr  = $attr . "credentials=";
        $attr2 = " filter=" . $attr2;
        $attr1 = "$password";
        $attr  = $attr . $attr1 . $attr2;
        $mesg  = $ldap->modify(
            $entry->dn,
            replace => {
                olcSyncrepl => "$attr",
            }
        );
    }
}
elsif ( $options{p} ) {
    setLocalConfig( "ldap_postfix_password", "$password" );
    my $mesg = $ldap->bind( 'uid=zmpostfix,cn=appaccts,cn=zimbra',
        password => "$password" );
    if ( $mesg->code ) {
        $mesg = $ldap->bind( "cn=config", password => "$cur_rootdn_passwd" );
        $mesg = $ldap->set_password(
            user      => "uid=zmpostfix,cn=appaccts,cn=zimbra",
            newpasswd => $password
        );
    }
    my $infile  = "/opt/zextras/conf/carbonio.ldif";
    my $outfile = "$zimbra_tmp_directory/carbonio.ldif.$$";
    my $ldifin  = Net::LDAP::LDIF->new( "$infile",  "r", onerror => 'undef' );
    my $ldifout = Net::LDAP::LDIF->new( "$outfile", "w", onerror => 'undef' );
    my $entry;
    while ( not $ldifin->eof() ) {
        $entry = $ldifin->read_entry();
        if ( $ldifin->error() ) {
            print "Error msg: ",    $ldifin->error(),       "\n";
            print "Error lines:\n", $ldifin->error_lines(), "\n";
        }
        else {
            if ( $entry->dn() eq "uid=zmpostfix,cn=appaccts,cn=zimbra" ) {
                $entry->replace( userPassword => "$ssha_password", );
            }
            $ldifout->write($entry);
        }
    }
    $ldifin->done();
    $ldifout->done();
    if ( -s $outfile ) {
        my $rc = 0xffff & system("/bin/mv -f $infile $infile.bak");
        if ( $rc != 0 ) {
            print "Warning: Failed to backup $infile\n";
        }
        $rc = 0xffff & system("/bin/mv -f $outfile $infile");
        if ( $rc != 0 ) {
            print
"Failed to move $outfile to $infile\nRestoring old configuration\n";
            $rc = 0xffff & system("/bin/mv -f $infile.bak $infile");
            if ( $rc != 0 ) {
                print "Failed to restore backup\n";
            }
        }
        else {
            system("rm -f $infile.bak");
        }
    }
}
elsif ( $options{a} ) {
    setLocalConfig( "ldap_amavis_password", "$password" );
    my $mesg = $ldap->bind( 'uid=zmamavis,cn=appaccts,cn=zimbra',
        password => "$password" );
    if ( $mesg->code ) {
        $mesg = $ldap->bind( "cn=config", password => "$cur_rootdn_passwd" );
        $mesg = $ldap->set_password(
            user      => "uid=zmamavis,cn=appaccts,cn=zimbra",
            newpasswd => $password
        );
    }
    my $infile  = "/opt/zextras/conf/carbonio.ldif";
    my $outfile = "$zimbra_tmp_directory/carbonio.ldif.$$";
    my $ldifin  = Net::LDAP::LDIF->new( "$infile",  "r", onerror => 'undef' );
    my $ldifout = Net::LDAP::LDIF->new( "$outfile", "w", onerror => 'undef' );
    my $entry;
    while ( not $ldifin->eof() ) {
        $entry = $ldifin->read_entry();
        if ( $ldifin->error() ) {
            print "Error msg: ",    $ldifin->error(),       "\n";
            print "Error lines:\n", $ldifin->error_lines(), "\n";
        }
        else {
            if ( $entry->dn() eq "uid=zmamavis,cn=appaccts,cn=zimbra" ) {
                $entry->replace( userPassword => "$ssha_password", );
            }
            $ldifout->write($entry);
        }
    }
    $ldifin->done();
    $ldifout->done();
    if ( -s $outfile ) {
        my $rc = 0xffff & system("/bin/mv -f $infile $infile.bak");
        if ( $rc != 0 ) {
            print "Warning: Failed to backup $infile\n";
        }
        $rc = 0xffff & system("/bin/mv -f $outfile $infile");
        if ( $rc != 0 ) {
            print
"Failed to move $outfile to $infile\nRestoring old configuration\n";
            $rc = 0xffff & system("/bin/mv -f $infile.bak $infile");
            if ( $rc != 0 ) {
                print "Failed to restore backup\n";
            }
        }
        else {
            system("rm -f $infile.bak");
        }
    }
}
elsif ( $options{n} ) {
    setLocalConfig( "ldap_nginx_password", "$password" );
    my $mesg = $ldap->bind( 'uid=zmnginx,cn=appaccts,cn=zimbra',
        password => "$password" );
    if ( $mesg->code ) {
        $mesg = $ldap->bind( "cn=config", password => "$cur_rootdn_passwd" );
        $mesg = $ldap->set_password(
            user      => "uid=zmnginx,cn=appaccts,cn=zimbra",
            newpasswd => $password
        );
    }
    my $infile  = "/opt/zextras/conf/carbonio.ldif";
    my $outfile = "$zimbra_tmp_directory/carbonio.ldif.$$";
    my $ldifin  = Net::LDAP::LDIF->new( "$infile",  "r", onerror => 'undef' );
    my $ldifout = Net::LDAP::LDIF->new( "$outfile", "w", onerror => 'undef' );
    my $entry;
    while ( not $ldifin->eof() ) {
        $entry = $ldifin->read_entry();
        if ( $ldifin->error() ) {
            print "Error msg: ",    $ldifin->error(),       "\n";
            print "Error lines:\n", $ldifin->error_lines(), "\n";
        }
        else {
            if ( $entry->dn() eq "uid=zmnginx,cn=appaccts,cn=zimbra" ) {
                $entry->replace( userPassword => "$ssha_password", );
            }
            $ldifout->write($entry);
        }
    }
    $ldifin->done();
    $ldifout->done();
    if ( -s $outfile ) {
        my $rc = 0xffff & system("/bin/mv -f $infile $infile.bak");
        if ( $rc != 0 ) {
            print "Warning: Failed to backup $infile\n";
        }
        $rc = 0xffff & system("/bin/mv -f $outfile $infile");
        if ( $rc != 0 ) {
            print
"Failed to move $outfile to $infile\nRestoring old configuration\n";
            $rc = 0xffff & system("/bin/mv -f $infile.bak $infile");
            if ( $rc != 0 ) {
                print "Failed to restore backup\n";
            }
        }
        else {
            system("rm -f $infile.bak");
        }
    }
}
elsif ( $options{b} ) {
    setLocalConfig( "ldap_bes_searcher_password", "$password" );
    my $mesg = $ldap->bind( 'uid=zmbes-searcher,cn=appaccts,cn=zimbra',
        password => "$password" );
    if ( $mesg->code ) {
        $mesg = $ldap->bind( "cn=config", password => "$cur_rootdn_passwd" );
        $mesg = $ldap->set_password(
            user      => "uid=zmbes-searcher,cn=appaccts,cn=zimbra",
            newpasswd => $password
        );
    }
    my $infile  = "/opt/zextras/conf/carbonio.ldif";
    my $outfile = "$zimbra_tmp_directory/carbonio.ldif.$$";
    my $ldifin  = Net::LDAP::LDIF->new( "$infile",  "r", onerror => 'undef' );
    my $ldifout = Net::LDAP::LDIF->new( "$outfile", "w", onerror => 'undef' );
    my $entry;
    while ( not $ldifin->eof() ) {
        $entry = $ldifin->read_entry();
        if ( $ldifin->error() ) {
            print "Error msg: ",    $ldifin->error(),       "\n";
            print "Error lines:\n", $ldifin->error_lines(), "\n";
        }
        else {
            if ( $entry->dn() eq "uid=zmbes-searcher,cn=appaccts,cn=zimbra" ) {
                $entry->replace( userPassword => "$ssha_password", );
            }
            $ldifout->write($entry);
        }
    }
    $ldifin->done();
    $ldifout->done();
    if ( -s $outfile ) {
        my $rc = 0xffff & system("/bin/mv -f $infile $infile.bak");
        if ( $rc != 0 ) {
            print "Warning: Failed to backup $infile\n";
        }
        $rc = 0xffff & system("/bin/mv -f $outfile $infile");
        if ( $rc != 0 ) {
            print
"Failed to move $outfile to $infile\nRestoring old configuration\n";
            $rc = 0xffff & system("/bin/mv -f $infile.bak $infile");
            if ( $rc != 0 ) {
                print "Failed to restore backup\n";
            }
        }
        else {
            system("rm -f $infile.bak");
        }
    }
}
else {
    my $zimbra_ldap_userdn = getLocalConfig("zimbra_ldap_userdn");
    setLocalConfig( "zimbra_ldap_password", "$password" );
    my $mesg = $ldap->bind( "$zimbra_ldap_userdn", password => "$password" );
    if ( $mesg->code ) {
        $mesg = $ldap->bind( "cn=config", password => "$cur_rootdn_passwd" );
        $mesg = $ldap->set_password(
            user      => "$zimbra_ldap_userdn",
            newpasswd => $password
        );
    }
    my $infile  = "/opt/zextras/conf/carbonio.ldif";
    my $outfile = "$zimbra_tmp_directory/carbonio.ldif.$$";
    my $ldifin  = Net::LDAP::LDIF->new( "$infile",  "r", onerror => 'undef' );
    my $ldifout = Net::LDAP::LDIF->new( "$outfile", "w", onerror => 'undef' );
    my $entry;
    while ( not $ldifin->eof() ) {
        $entry = $ldifin->read_entry();
        if ( $ldifin->error() ) {
            print "Error msg: ",    $ldifin->error(),       "\n";
            print "Error lines:\n", $ldifin->error_lines(), "\n";
        }
        else {
            if ( $entry->dn() eq "$zimbra_ldap_userdn" ) {
                $entry->replace( userPassword => "$ssha_password", );
            }
            $ldifout->write($entry);
        }
    }
    $ldifin->done();
    $ldifout->done();
    if ( -s $outfile ) {
        my $rc = 0xffff & system("/bin/mv -f $infile $infile.bak");
        if ( $rc != 0 ) {
            print "Warning: Failed to backup $infile\n";
        }
        $rc = 0xffff & system("/bin/mv -f $outfile $infile");
        if ( $rc != 0 ) {
            print
"Failed to move $outfile to $infile\nRestoring old configuration\n";
            $rc = 0xffff & system("/bin/mv -f $infile.bak $infile");
            if ( $rc != 0 ) {
                print "Failed to restore backup\n";
            }
        }
        else {
            system("rm -f $infile.bak");
        }
    }
}
$ldap->unbind();
$ldap->disconnect();

#
# Usage.
#
sub usage() {

    print "Usage: $0 [-h] [-r] [-p] [[-c]-l] newpassword\n";
    print "\t-h: display this help message\n";
    print "\t-a: change ldap_amavis_password\n";
    print "\t-b: change ldap_bes_searcher_password\n";
    print "\t-l: change ldap_replication_password\n";
    print "\t-c: Update ldap_replication_password on replica. Requires -l\n";
    print "\t-n: change ldap_nginx_password\n";
    print "\t-p: change ldap_postfix_password\n";
    print "\t-r: change ldap_root_passwd\n";
    print "\tOnly one of a, l, n, p, or r may be specified\n";
    print "\tWithout options zimbra_ldap_password is changed\n\n";
    print "\tOption -c requires -l and must be run on a replica after\n";
    print "\tchanging the password on the master (using -l by itself).\n\n";
    exit 1;

}

sub setLocalConfig {
    my $key = shift;
    my $val = shift;

    if ( exists $main::saved{lc}{$key} && $main::saved{lc}{$key} eq $val ) {
        return;
    }
    $main::saved{lc}{$key} = $val;
    qx(/opt/zextras/bin/zmlocalconfig -f -e ${key}=\'${val}\' 2> /dev/null);
}

sub getLocalConfig {
    my $key = shift;

    return $main::loaded{lc}{$key}
      if ( exists $main::loaded{lc}{$key} );

    my $val =
      qx(/opt/zextras/bin/zmlocalconfig -x -s -m nokey ${key} 2> /dev/null);
    chomp $val;
    $main::loaded{lc}{$key} = $val;
    return $val;
}