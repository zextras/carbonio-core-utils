#!/usr/bin/perl

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

use lib "/opt/zextras/common/lib/perl5";
use strict;
use warnings;
use DBI;
use Zextras::Mon::Stat;
use Zextras::Mon::Logger;
use Date::Parse;
use Fcntl qw(SEEK_SET);

my $logger_directory = $Zextras::Mon::Stat::LC{'logger_data_directory'};
my %hostmap;

use vars qw($logger_directory $log_file);

# Exit if software-only node.
exit(0) unless ( -f '/opt/zextras/conf/localconfig.xml' );

my $pid_file   = "/run/carbonio/zmlogprocess.pid";
my $state_file = "/opt/zextras/log/zmlogprocess.state";
$logger_directory = getLocalConfig("logger_data_directory");
$log_file         = '/var/log/carbonio.log';

# Regexes for Postfix Queue IDs

# Short Format character: ASCII uppercase A-F range plus ASCII digits
my $SF_QID_CHAR = qr{[A-F0-9]};

# Long Format time portion character:  ASCII digits and ASCII uppercase/lowercase consonants
my $LF_QID_TIME_CHAR = qr{[0-9BCDFGHJKLMNPQRSTVWXYZ]}i;

# Long Format inode number portion character: ASCII digits and ASCII uppercase/lowercase consonants minus "z"
my $LF_QID_INODE_CHAR = qr{[0-9BCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxy]};

my $REGEX_POSTFIX_QID = qr{(?:${SF_QID_CHAR}{6,}+|${LF_QID_TIME_CHAR}{10,}z${LF_QID_INODE_CHAR}++)};

sub gethostmap() {
    my $dbh = DBI->connect( "dbi:SQLite:dbname=$logger_directory/logger.sqlitedb", "", "" );
    my $sth = $dbh->prepare(
        q{
        SELECT dns_hostname, zm_hostname from hosts
    }
    );
    $sth->execute;
    die $sth->err if $sth->err;
    my $data = $sth->fetchall_arrayref( {} );
    my %hash;
    foreach my $row (@$data) {
        $hash{ $row->{'dns_hostname'} } = $row->{'zm_hostname'};
    }
    %hostmap = %hash;
}

sub listMTA() {
    open( MTALIST, "/opt/zextras/bin/zmprov gas mta |" ) || die $!;
    my @mtas = <MTALIST>;
    chomp(@mtas);
    close(MTALIST);
    @mtas;
}

sub checkPID {

    # try to avoid multiple instances
    if ( -f ${pid_file} ) {
        open PID, "$pid_file";
        my $p = <PID>;
        close PID;
        if ( $p eq "" ) {
            unlink($pid_file);
            return;
        }
        if ( kill( 0, $p ) ) {
            warn("$0 already running with pid $p\n");
            exit;
        }
    }
}

sub checkState() {
    my $state = -1;
    if ( !-f $state_file ) {
        updateState();
        warn("$state_file not found, updated");
        exit;
    }
    else {
        my $mtime = ( stat(_) )[9];
        my $size  = ( stat($log_file) )[7];
        my $now   = time();
        my $delta = $now - $mtime;
        if ( $delta > 60 * 30 ) {    # 30 minute time, cron happens every 5 minutes
            warn("$state_file is stale, $delta seconds old, skipping cycle");
            updateState();
            exit;
        }

        open( STATE, "<$state_file" ) || die $!;
        $state = <STATE>;
        close(STATE);

        $state = 0 if ( $size < $state );
    }
    $state;
}

sub updateState() {
    my $size = ( stat($log_file) )[7];
    open( STATE, ">$state_file" ) || die $!;
    print STATE $size;
    close(STATE);
    $size;
}

sub updatePID {
    open PID, "> $pid_file";
    print PID $$;
    close PID;
}

sub getLocalConfig {
    my $key = shift;
    if ( defined( $ENV{zmsetvars} ) ) {
        return $ENV{$key};
    }
    open CONF, "/opt/zextras/bin/zmlocalconfig -q -x -s -m shell |"
      or die "Can't open local config: $!";
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

sub init_counters($) {
    my $data = shift @_;
    my @mtas = listMTA();

    my @counters = qw(clam_events sendmail_events filter_count filter_virus filter_spam filter_misc mta_count mta_volume mta_delay);
    foreach my $mta (@mtas) {
        foreach my $counter (@counters) {
            counter_increment( $data, $mta, $counter );
        }
    }
}

sub counter_increment($$$) {
    my ( $data, $host, $counter ) = @_;
    counter_add( $data, $host, $counter, 1 );
}

sub counter_add($$$$) {
    my ( $data, $host, $counter, $amount ) = @_;
    $host          = $hostmap{$host} if exists $hostmap{$host};
    $data->{$host} = {}              if ( !exists $data->{$host} );

    # start at -1 because we +1 in init_counters
    $data->{$host}->{$counter} = -1 if ( !exists $data->{$host}->{$counter} );
    $data->{$host}->{$counter} += $amount;
}

sub counter_qid_add($$$$) {
    my ( $data, $host, $qid, $date ) = @_;
    my $tstamp = str2time($date);

    $host                             = $hostmap{$host} if exists $hostmap{$host};
    $data->{$host}                    = {}              if !exists $data->{$host};
    $data->{$host}->{$qid}            = {}              if !exists $data->{$host}->{$qid};
    $data->{$host}->{$qid}->{'first'} = $tstamp         if !exists $data->{$host}->{$qid}->{'first'};
    $data->{$host}->{$qid}->{'last'}  = $tstamp;
}

sub counter_qid_avg($$) {
    my ( $data, $host ) = @_;

    $host = $hostmap{$host} if exists $hostmap{$host};
    return 0                if !exists $data->{$host};

    my $hdata = $data->{$host};

    my $avg   = 0;
    my $count = 0;

    foreach my $qid ( keys %$hdata ) {
        my $delta = $hdata->{$qid}->{'last'} - $hdata->{$qid}->{'first'};

        $avg = ( ( $avg * $count ) + $delta ) / ( $count + 1 );

        $count++;
    }

    return $avg;
}

sub run() {
    checkPID();
    updatePID();
    gethostmap();
    my $offset = checkState();
    my $state  = updateState();
    open( LOG, "<$log_file" ) || die $!;

    my $logregex = qr/(^.{15}) ((\d+\.\d+\.\d+\.\d+) \S+|(\S+)) ([^[]+)(\[(\d+)\])?: (.*)$/o;
    my %host_data;
    my %host_qid_data;    # hostname -> { qid -> { first, last } }
    init_counters( \%host_data );
    my %seen_qid;
    seek( LOG, $offset, SEEK_SET );
    while (<LOG>) {
        my $pos = tell(LOG);
        last if ( $pos >= $state );

        my ( $log_date, $host, $ip, $name, $app, undef, $pid, $msg ) = ( $_ =~ m/$logregex/ );
        next if ( !defined($log_date) );    # skip incomplete lines

        $host = ( ( defined($ip) && $ip ne "" ) ? $ip : $name );

        if ( $app eq 'clamd' ) {
            counter_increment( \%host_data, $host, 'clam_events' );
        }
        elsif ( $app eq 'sendmail' ) {
            counter_increment( \%host_data, $host, 'sendmail_events' );
        }
        elsif ( $app eq 'amavis' ) {
            if ( $msg =~ /\(\S+\) (Passed|Blocked) (\w+)/ ) {
                my $disp   = $1;
                my $reason = $2;
                counter_increment( \%host_data, $host, 'filter_count' );
                if ( $disp eq 'Passed' ) {
                }
                elsif ( $disp eq 'Blocked' ) {
                    if ( $reason =~ /INFECTED/ ) {
                        counter_increment( \%host_data, $host, 'filter_virus' );
                    }
                    elsif ( $reason =~ /SPAM/ ) {
                        counter_increment( \%host_data, $host, 'filter_spam' );
                    }
                    else {
                        counter_increment( \%host_data, $host, 'filter_misc' );
                    }
                }
            }
        }
        elsif ( $app =~ /^postfix/o ) {
            if ( $msg =~ /^(${REGEX_POSTFIX_QID}):/o ) {
                my $qid = $1;
                counter_qid_add( \%host_qid_data, $host, $qid, $log_date );
                counter_increment( \%host_data, $host, 'mta_count' )
                  if ( !exists $seen_qid{$qid} );
                $seen_qid{$qid} = 1;
                counter_add( \%host_data, $host, 'mta_volume', $1 )
                  if ( $msg =~ /, size=(\d+),/ );
            }
        }
    }
    close(LOG);
    foreach my $host ( keys %host_data ) {
        my $delay = counter_qid_avg( \%host_qid_data, $host );
        my $hdata = $host_data{$host};
        $hdata->{'mta_delay'} = $delay;

        my @columns = keys %$hdata;
        my $columns = join( ',', @columns );
        my @data;
        foreach my $c (@columns) {
            push( @data, $hdata->{$c} );
        }
        my $data = join( ',', @data );
        Zextras::Mon::Logger::LogStats( "info", "MTA: $host: ${columns}:: $data" );
    }

    unlink($pid_file);
}

run();
