#!/usr/bin/perl

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

use strict;
use lib qw(/opt/zextras/common/lib/perl5 /opt/zextras/zimbramon/lib);
use Zimbra::Mon::Logger;

use FileHandle;
use IPC::Open3;
use Time::Local;
use Mail::Mailer;
use Getopt::Long;
use File::Find;

my %options = ();
my $report  = [];
my $dbCheck = '';
my $status  = 0;
unless ( GetOptions( "mailReport" => \$options{m}, "optimize" => \$options{o}, "repair" => \$options{r}, "verbose" => \$options{v}, "debug" => \$options{d}, "help" => \$options{h} ) ) { usage(); }

#unless ( getopts( 'mdhrv', \%options ) ) { usage(); }
usage() if ( $options{h} );
my $debug   = $options{d} ? 1 : 0;
my $verbose = $options{v} ? 1 : 0;
$verbose = 1 if $debug;

if ( $verbose && $options{m} ) {
    print STDERR "Options -m and -v are mutually exclusive\n";
    &usage();
}

my $check_disabled = getLocalConfig("zmdbintegrityreport_disabled");
exit 0 if ( lc($check_disabled) eq "true" );

addToReport("Generating report\n") if $debug;
$status = ( checkDbs() ? 1 : 0 );
if ( $options{m} ) {
    sendEmailReport($report);
}
else {
    print @$report;
}

exit $status;

#-------------
# Subroutines
#-------------

sub usage {
    print STDERR "Usage: $0 [-m] [-o] [-r] [-v] [-h]\n";
    print STDERR "-m emails report to admin account, otherwise report is presented on stdout\n";
    print STDERR "-o attempt auto optimization of tables\n";
    print STDERR "-r attempt auto repair of tables\n";
    print STDERR "-v verbose output\n";
    print STDERR "-h help\n";

    exit(1);
}

sub checkDbs() {
    my $mysql_root_passwd = getLocalConfig("mysql_root_password");
    my $mysql_socket      = "/run/carbonio/mysql.sock";
    my $mysql_mycnf       = getLocalConfig("mysql_mycnf") || "/opt/zextras/conf/my.cnf";

    prepareDataDirectoryForChecks($mysql_mycnf);

    my $cmd;
    if ( -x "/opt/zextras/mysql/bin/mysqlcheck" ) {
        $cmd = "/opt/zextras/mysql/bin/mysqlcheck";
    }
    elsif ( -x "/opt/zextras/common/bin/mysqlcheck" ) {
        $cmd = "/opt/zextras/common/bin/mysqlcheck";
    }
    else {
        print "ERROR: Unable to find mysqlcheck.\n";
        exit 1;
    }
    $cmd .= " --defaults-file=${mysql_mycnf}";
    $cmd .= " -S /run/carbonio/mysql.sock";
    $cmd .= " -A";
    $cmd .= " -C" unless $options{o};
    $cmd .= " -s" unless $debug;
    $cmd .= " -u root";
    $cmd .= " --auto-repair" if $options{r};
    $cmd .= " --optimize"    if $options{o};

    unless ( open( CMD, "$cmd --password=${mysql_root_passwd} |" ) ) {
        addToReport("can't run $cmd: $!\n");
        if ( !$options{m} ) {
            return 1;
        }
        return undef;
    }
    my @output = <CMD>;
    if ( $options{o} ) {
        for ( my $i = $#output ; $i >= 0 ; $i-- ) {
            local $_ = $output[$i];
            if (/note     : Table does not support optimize/) {
                splice( @output, $i - 1, 2 );
                $i -= 1;
            }
        }
    }
    for ( my $i = 0 ; $i <= $#output ; ++$i ) {
        local $_ = $output[$i];
        if (/mysql.general_log/) {
            my $nextLine = $output[ $i + 1 ];
            if ( $nextLine =~ /Error    : You can't use locks with log tables./ ) {
                splice( @output, $i, 2 );
            }
        }
    }
    for ( my $i = 0 ; $i <= $#output ; ++$i ) {
        local $_ = $output[$i];
        if (/mysql.slow_log/) {
            my $nextLine = $output[ $i + 1 ];
            if ( $nextLine =~ /Error    : You can't use locks with log tables./ ) {
                splice( @output, $i, 2 );
            }
        }
    }
    if ( scalar @output != 0 ) {
        addToReport("Database errors found.\n");
        addToReport("$cmd --password=XXXXXXXX\n");
        addToReport("@output");
        if ( !$options{m} ) {
            return 1;
        }
    }
    else {
        addToReport("No errors found\n") if $verbose;
    }
    unless ( close(CMD) ) {
        addToReport("command failed $!\n");
        if ( !$options{m} ) {
            return 1;
        }
        return undef;
    }
    return;
}

sub getLocalConfig {
    my $key = shift;
    if ( defined( $ENV{zmsetvars} ) ) {
        return $ENV{$key};
    }
    open CONF, "/opt/zextras/bin/zmlocalconfig -s -q -m shell |" or die "Can't open local config: $!";
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

# Retrieves 'datadir' value from passed MySQL configuration file (my.cnf).
# If the configuration file doesn't exist, it uses the default 'datadir'.
#
# Perform cleanup in the 'datadir' removing empty directories
# MySql interprets any directory under 'datadir' to be a database.
#
# See: https://dev.mysql.com/doc/refman/8.2/en/data-directory.html
sub prepareDataDirectoryForChecks {
    my $my_cnf = shift;

    open my $fh, '<', $my_cnf;
    my ($datadir) = map { /^\s*datadir\s*=\s*(\S+)/i ? $1 : () } <$fh>;
    close $fh if $fh;

    $datadir //= '/opt/zextras/db/data';

    finddepth( sub { rmdir }, $datadir );
}

sub sendEmailReport {
    my $msg = shift;

    my $from_address = getLocalConfig("smtp_source");
    my $to_address   = getLocalConfig("smtp_destination");
    my $server       = getLocalConfig("zimbra_server_hostname");
    my $smtphost     = getLdapConfigValue("zimbraSmtpHostname") || "localhost";
    my $smtpport     = getLdapConfigValue("zimbraSmtpPort")     || "25";
    my $subject      = "Database Integrity check report for $server";
    return                                                      if ( scalar @$msg == 0 );
    print "Sending daily report to $to_address via $smtphost\n" if $debug;
    eval {
        my $mailer = Mail::Mailer->new( "smtp", Server => $smtphost, Port => $smtpport );
        $mailer->open(
            {
                From    => $from_address,
                To      => $to_address,
                Subject => $subject,
            }
        ) or warn "ERROR: Can't open: $!\n";
        print $mailer $msg;
        $mailer->close();
    };
    if ($@) {
        logError("Failed to email report: $@\n");
    }
    else {
        print "Email report sent to $to_address\n" if $debug;
    }
}

sub addToReport {
    my ($line) = @_;
    push( @$report, $line );
}

sub logError {
    my $msg = shift;
    if ( $options{m} && !$options{d} ) {
        my $dt = qx(date "+%Y-%m-%d %H:%M:%S");
        chomp($dt);
        Zimbra::Mon::Logger::Log( "err", "$dt, zmdailyreport: $msg" );
    }
    else {
        print STDERR $msg;
    }
    return;
}

sub getLdapConfigValue {
    my $attrib = shift;

    return (undef) unless ($attrib);

    my $val = getLdapServerConfigValue($attrib);
    print "Server: $val\n"                   if $debug;
    $val = getLdapGlobalConfigValue($attrib) if ( $val eq "" );
    print "Global: $val\n"                   if $debug;
    return $val;
}

sub getLdapServerConfigValue {
    my $attrib = shift;

    return (undef) unless ($attrib);
    my $server = getLocalConfig("zimbra_server_hostname");

    # could consider redirecting STDERR to /dev/null
    open( CONF, "/opt/zextras/bin/zmprov -l gs $server '$attrib' |" )
      or die("Open global config failed: $!");

    my ( $key, $val );
    while (<CONF>) {
        chomp;
        next if (/^#/);
        ( $key, $val ) = split( /:\s*/, $_, 2 );

        # for now just assume a single value/attribute is requested
        last if ($val);
    }
    return $val;
}

sub getLdapGlobalConfigValue {
    my $attrib = shift;
    my ( $val, $err );
    my ( $rfh, $wfh, $efh, $cmd, $rc );
    $rfh = new FileHandle;
    $wfh = new FileHandle;
    $efh = new FileHandle;
    $cmd = "/opt/zextras/bin/zmprov -l gcf $attrib";
    my $pid = open3( $wfh, $rfh, $efh, $cmd );

    unless ( defined($pid) ) {
        return undef;
    }
    close $wfh;
    chomp( $val = ( split( /\s+/, <$rfh> ) )[-1] );
    chomp( $err = join "", <$efh> );
    waitpid( $pid, 0 );
    if ( $? == -1 ) {

        # failed to execute
        return undef;
    }
    elsif ( $? & 127 ) {

        # died with signal
        return undef;
    }
    else {
        $rc = $? >> 8;
        return undef if ( $rc != 0 );
    }

    return $val;
}
