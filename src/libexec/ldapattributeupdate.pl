#!/usr/bin/perl
#
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only
#

=begin
About this script:
    → start LDAP
    → bind ldap
    → get the value of zimbraLDAPSchemaVersion from LDAP
    → iterate through what we call ldap_attribute_update_dir containing updated JSON files
    → sort update files in ascending order
    → compare timestamp from update filename with zimbraLDAPSchemaVersion. if it’s greater, that
    means we need to apply updates from this update file
    → iterate through the entries from the update file, process each entry’s attribute from
    the LDIF file, apply the update to the LDAP server for only those entries that require
    changes
    → update the zimbraLDAPSchemaVersion in LDAP with the last applied update file’s name
    → unbind ldap
    → exit
=cut

use strict;
use lib "/opt/zextras/common/lib/perl5";
use Zextras::Util::Common;
use Zextras::Util::Systemd;
use File::Path;
use Net::LDAP;
use Net::LDAP::LDIF;
use Net::LDAP::Entry;
use JSON::PP;
use File::Basename;
use experimental 'smartmatch';

my $source_config_dir = "/opt/zextras/common/etc/openldap";
my $ldap_attribute_update_dir = "$source_config_dir/zimbra/updates/attrs";
my $ldap_root_password = getLocalConfig("ldap_root_password");
my $ldap_master_url = getLocalConfig("ldap_master_url");
my $ldap_is_master = getLocalConfig("ldap_is_master");
my $ldap_starttls_supported = getLocalConfig("ldap_starttls_supported");
my $zimbra_tmp_directory = getLocalConfig("zimbra_tmp_directory");

my $id = getpwuid($<);
chomp $id;
if ( $id ne "root" ) {
    print STDERR "Error: must be run as root user\n";
    exit(1);
}

if (lc($ldap_is_master) ne "true") {
    exit(0);
}

if (!-d $zimbra_tmp_directory) {
    File::Path::mkpath("$zimbra_tmp_directory");
}

if ( isSystemd() ) {
    system("systemctl start carbonio-openldap.service");
    sleep 5;
}
else {
    system("/opt/zextras/bin/ldap start");
}

my @masters = split(/ /, $ldap_master_url);
my $master_ref = \@masters;
my $ldap = Net::LDAP->new($master_ref) or die "$@";

# startTLS Operation if available
my $mesg;
if ($ldap_master_url !~ /^ldaps/i) {
    if ($ldap_starttls_supported) {
        $mesg = $ldap->start_tls(
            verify => 'none',
            capath => "/opt/zextras/conf/ca",
        ) or die "start_tls: $@";
        $mesg->code && die "TLS: " . $mesg->error . "\n";
    }
}

# bind ldap or exit with error on failure fail
$mesg = $ldap->bind("cn=config", password => "$ldap_root_password");
if ($mesg->code()) {
    print "Unable to bind: $!";
    exit(0);
}

# get zimbraLDAPSchemaVersion from LDAP server
my $zimbra_ldap_schema_version;
my $last_applied_update_version;
my $result = $ldap->search(base => 'cn=zimbra', filter => '(zimbraLDAPSchemaVersion=*)', attrs => [ 'zimbraLDAPSchemaVersion' ]);
if ( $result->count > 0 ) {
    my $entry = $result->entry(0);
    $zimbra_ldap_schema_version = $entry->get_value('zimbraLDAPSchemaVersion');
    $last_applied_update_version = $zimbra_ldap_schema_version;
    &print_separater("-", "40");
    print "Installed LDAP Schema Version: $zimbra_ldap_schema_version \n";
}
else {
    print "Unable to get zimbraLDAPSchemaVersion from LDAP.\n";
    $ldap->unbind;
    exit(0);
}

# read updates folder and prepare each file for update;
if (-d "$ldap_attribute_update_dir") {
    opendir(DIR, "$ldap_attribute_update_dir") or die "Cannot opendir $ldap_attribute_update_dir: $!\n";
    my @update_files =  sort { $a <=> $b } readdir(DIR);
    while ( my $file = shift @update_files ) {
        next unless (-f "$ldap_attribute_update_dir/$file");
        next unless ($file =~ m/json/);
        my $infile = "$ldap_attribute_update_dir/$file";
        &prepare_update_file($infile);
    }
    closedir DIR;
    &print_separater("-", "80");
}
else {
    print "LDAP Schema/Attributes update directory($ldap_attribute_update_dir) not found.\nUnable to process LDAP updates.\n";
    $ldap->unbind;
    exit(0);
}

=begin print_separater
    print_separater($char<string>, $length<int>);
Prints $char $length times prepended by a new line;
=cut
sub print_separater(){
    my ($char, $length) = @_;
    print $char x $length;
    print "\n";
}

=begin getLocalConfig
    getLocalConfig($key<string>);
Returns value of key from localconfig, using zmlocalconfig util.
=cut
sub getLocalConfig {
    my $key = shift;

    return $main::loaded{lc}{$key}
        if (exists $main::loaded{lc}{$key});

    my $val = qx(/opt/zextras/bin/zmlocalconfig -x -s -m nokey ${key} 2> /dev/null);
    chomp $val;
    $main::loaded{lc}{$key} = $val;
    return $val;
}

=begin update_zimbra_ldap_schema_version
    update_zimbra_ldap_schema_version($last_applied_update_version<string>);
update the value of zimbraLDAPSchemaVersion in LDAP
=cut
sub update_zimbra_ldap_schema_version(){
    my ($last_updated_timestamp) = @_;
    if( $zimbra_ldap_schema_version ne $last_updated_timestamp ) {
        my $result = $ldap->search(base => 'cn=zimbra', filter => '(zimbraLDAPSchemaVersion=*)', attrs => [ 'zimbraLDAPSchemaVersion' ]);
        if ( $result->count > 0 ) {
            my $entry = $result->entry(0);
            if( $entry ){
                $entry->replace( zimbraLDAPSchemaVersion => $last_updated_timestamp );
            }
            my $msg = $entry->update( $ldap );
            if ( $msg->code() ) {
                print "Error msg: ", $entry->dn(), " ", $msg->error(), "\n";
            }
        }
        print "LDAP schema upgraded to version $last_updated_timestamp \n";
    }
}

=begin prepare_update_file
    prepare_update_file($filename<string>);
Prepare each update files for updating.
=cut
sub prepare_update_file(){
    my ($infile) = @_;
    # start, process only eligible update files ;
    my $infile_base_name = basename($infile);
    (my $timestamp_from_file = $infile_base_name) =~ s/\.[^.]+$//;
    chomp $timestamp_from_file;
    &print_separater("-", "80");
    if ($timestamp_from_file > $zimbra_ldap_schema_version) {
        open(FH, '<', $infile) or die "Cannot open file $infile for reading: $!\n";
        my $raw_json = join '', <FH>;
        my $json = new JSON::PP;
        eval {
            my $json_decoded = $json->decode($raw_json);
            print "Initializing updates from ", $timestamp_from_file, ".json\n";

            # read each entry and call the relative modify method for the ldif that we want to update.
            foreach my $entry_name (keys %$json_decoded) {
                my @attributes;
                print "  Processing Entry: ", $entry_name, "\n";
                for my $attribute (@{$json_decoded->{$entry_name}}) {
                    push(@attributes, $attribute);
                }
                &apply_update($timestamp_from_file, $entry_name, \@attributes);
            }
            1;
        } or do {
            my $e = $@;
            print "Skipping: $timestamp_from_file.json\n    Reason: $e\n";
        };
    }
    else {
        print "Skipping: $timestamp_from_file.json\n    Reason: not eligible for this update.\n";
    }
    close(FH);
    # end, process only eligible update files;
}


=begin apply_update
    apply_update($timestamp_from_file<string>, $entry_name<string>, @attributes<array>);
Updates the attributes in the entry.
=cut
sub apply_update {
    my ($timestamp_from_file, $entry_name, @attributes) = @_;
    my $infile = "$source_config_dir/zimbra/$entry_name.ldif";
    if ($entry_name eq "mimehandlers") {
        if (-f "/opt/zextras/conf/ldap/$entry_name.ldif") {
            $infile = "/opt/zextras/conf/ldap/$entry_name.ldif";
        }
    }
    my $ldifin = Net::LDAP::LDIF->new("$infile", "r", onerror => 'undef');
    while (not $ldifin->eof()) {
        my $entry = $ldifin->read_entry();
        if ($ldifin->error()) {
            print "Error msg: ", $ldifin->error(), "\n";
            print "Error lines:\n", $ldifin->error_lines(), "\n";
        }
        elsif ($entry) {
            $entry->changetype("modify");
            my $updated = 0;
            foreach my $attr ($entry->attributes()) {
                my $ref = $entry->get_value($attr, asref => 1);
                if ($attr ~~ @attributes) {
                    $updated++;
                    print "     Updating attribute:  $attr => @$ref\n";
                    $entry->replace($attr => [ @$ref ]);
                }
            }
            my $msg = $entry->update($ldap);
            if ($msg->code()) {
                print "Error msg: ", $entry->dn(), " ", $msg->error(), "\n";
            }else{
                if ( $updated > 0 ){
                    $last_applied_update_version = $timestamp_from_file;
                }
            }
        }
    }
}

&update_zimbra_ldap_schema_version($last_applied_update_version);
$ldap->unbind;
exit(0);
