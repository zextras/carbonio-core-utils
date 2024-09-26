#!/usr/bin/perl

# AUTHOR: Keshav Bhatt
# DESC  : collects statisics data for postfix and pipe it to the $STATS_FILE in $STATS_DIR directory
#         * checks mail queue for
#           - corrupt
#           - incoming
#           - deferred
#           - active
#           - hold
#           - queue count (all)
#           - kbyte size of mails in queue (all)
#         * postfix_last_extraction_timestamp

use strict;
use warnings;

use IO::File;
use File::Path qw(make_path);
use JSON::PP;

#=====================================VARIABLES=====================================

my $STAT = "postfix";
my $STAT_PREFIX = "postfix_queue_stat_";
my $STAT_PREFIX_COMPLEX = "postfix_queue_stat";
my $STATS_DIR = "/opt/zextras/zmstat/prometheus";
my $STATS_FILE = "postfix.prom";
my $LOG_BUFFER = "";


#================================HELPERS SUBROUTINES=================================
#appends the stats to $LOG_BUFFER
sub append_log_buffer {
    my ($data) = @_;
    $LOG_BUFFER .= $data;
}

#ensure dir exists
sub ensure_dir_exists {
    my ($dir) = @_;
    make_path($dir);
}

#[data source] returns mail queue count stats using postqueue -j
sub get_postfix_mail_queue_count {

    my $queue_buffer = "";
    my %postfixMailQueueCount = (
        corrupt  => 0,
        incoming => 0,
        deferred => 0,
        active   => 0,
        hold     => 0
    );

    my $postqueue_std_out = qx(/opt/zextras/common/sbin/postqueue -j 2> /dev/null);
    my @data = split('\n', $postqueue_std_out);
    my $json = JSON::PP->new;

    #count the queues
    foreach my $queue_item_json (@data) {
        my $json_decoded = $json->decode($queue_item_json);
        my $queue_name = $json_decoded->{'queue_name'};
        if(exists $postfixMailQueueCount{$queue_name}){
            $postfixMailQueueCount{$queue_name}++;
        }
    }

    #preapare the return
    foreach my $key (keys %postfixMailQueueCount) {
        $queue_buffer .= "$key=$postfixMailQueueCount{$key}\n";
    }

    return $queue_buffer;
}


#[data source] returns mail queue size stats using postqueue -p
sub get_postfix_mail_queue_size {
    my $queue_size_stats_std_out = qx(/opt/zextras/common/sbin/postqueue -p 2> /dev/null | tail -1);
    chomp($queue_size_stats_std_out);
    $queue_size_stats_std_out =~ s/^\n+//;

    return $queue_size_stats_std_out;
}

#return hashmap of mail queue count from getPostfixMailQueueCount
sub parse_postfix_mail_queue_count {
    my @data = split('\n', get_postfix_mail_queue_count);

    my %data_hash;

    foreach my $queue_item (@data) {
        my $item = $queue_item;
        my @stat = split("=", $item);
        my $stat_key = $stat[0] | "";
        my $stat_value = $stat[1] | 0;
        $data_hash{$stat_key} = $stat_value;
    }

    return %data_hash;
}

#return hashmap of mail queue size from getPostfixMailQueueSize
sub parse_postfix_mail_queue_size {
    my $data = get_postfix_mail_queue_size;

    my $size = 0;
    my $requests = 0;
    my $is_empty = 'empty';

    if ($data !~ /\Q$is_empty\E/) {
        if ($data =~ /(\d+) Kbytes in (\d+) Requests/) {
            $size = $1;
            $requests = $2;
        }
    }
    my %data_hash = (
        size     => $size,
        requests => $requests
    );

    return %data_hash;
}

#prepare mail queue count data for write
sub prepare_postfix_mail_queue_count {
    my %postfixMailQueueCount = &parse_postfix_mail_queue_count;

    foreach my $queue (keys %postfixMailQueueCount) {
        append_log_buffer($STAT_PREFIX_COMPLEX . "{queue=\"$queue\"} $postfixMailQueueCount{$queue}\n");
    }
}

#prepare mail queue size data for write
sub prepare_postfix_mail_queue_size {
    my %postfixMailQueueSize = &parse_postfix_mail_queue_size;

    foreach my $key (keys %postfixMailQueueSize) {
        append_log_buffer($STAT_PREFIX . "$key $postfixMailQueueSize{$key}\n");
    }
}

#prepare stat timestamp data for write
sub prepare_last_extraction_timestamp {
    my $timestamp_millis = time() * 1000;
    append_log_buffer($STAT . "_last_extraction_timestamp $timestamp_millis\n");
}

#write stats data to stat file
sub write_stats {
    my $umask = umask(0777-0644);
    open(FH, '>', $STATS_DIR . '/' . $STATS_FILE) or die $!;
    umask($umask);
    print FH $LOG_BUFFER;
    close FH;
}


#=====================================MAIN ROUTINE======================================

ensure_dir_exists($STATS_DIR);

prepare_last_extraction_timestamp;

prepare_postfix_mail_queue_size;

prepare_postfix_mail_queue_count;

write_stats;
