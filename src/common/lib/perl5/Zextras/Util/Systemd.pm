#!/usr/bin/perl

# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

# Manage systemd services

package Zextras::Util::Systemd;
use strict;
use warnings;
use Exporter 'import';
our @EXPORT =
  qw($systemdStatus isSystemd isSystemdActiveUnit startAllSystemdTargets
  stopAllSystemdTargets systemdPrint);

# Define a variable to track the status of the systemd service
our $systemdStatus = 0;

# Array of systemd targets to check and start
our @systemdTargets = (
    "carbonio-directory-server.target", "carbonio-appserver.target",
    "carbonio-proxy.target",            "carbonio-mta.target",
);

# Check if any of the systemd targets are enabled
sub isSystemd {
    foreach my $target (@systemdTargets) {
        if ( isSystemdEnabledUnit($target) ) {
            $systemdStatus = 1;    # At least one target is enabled
            last;
        }
    }

    return $systemdStatus;
}

sub isSystemdActiveUnit {
    my ($unitName) = @_;

    # Execute the systemctl command to get the status of the unit
    my $status = `systemctl is-active $unitName 2>&1`;
    chomp($status);    # Remove trailing newline

    if ( $status eq 'active' ) {
        return 1;      # The unit is running
    }
    else {
        return 0;      # The unit is not running
    }
}

sub isSystemdEnabledUnit {
    my ($unitName) = @_;

    # Construct the command to check if the unit is enabled
    my $status = `systemctl is-enabled $unitName 2>&1`;
    chomp($status);    # Remove trailing newline

    if ( $status eq 'enabled' ) {
        return 1;      # The unit is enabled
    }
    else {
        return 0;      # The unit is not enabled
    }
}

sub startAllSystemdTargets {
    foreach my $target (@systemdTargets) {
        if ( isSystemdEnabledUnit($target) ) {
            startSystemdUnit($target);
        }
    }
}

sub startSystemdUnit {
    my ($unitName) = @_;

    # Construct the command to start the target
    my $command = "systemctl start $unitName 2>&1";

    # Execute the command and capture the output
    print "\tstarting $unitName...";
    my $output = `$command`;
    my $rc     = $? >> 8;      # Get the exit status of the command

    # Check the exit status
    if ( $rc == 0 ) {
        print "Done.\n";
        return 1;              # The target was stopped successfully
    }
    else {
        return 0;
    }
}

sub stopAllSystemdTargets {
    foreach my $target (@systemdTargets) {
        if ( isSystemdEnabledUnit($target) ) {
            stopSystemdUnit($target);
        }
    }
}

sub stopSystemdUnit {
    my ($unitName) = @_;

    # Construct the command to stop the target
    my $command = "systemctl stop $unitName 2>&1";

    # Execute the command and capture the output
    print "\tstopping $unitName...";
    my $output = `$command`;
    my $rc     = $? >> 8;      # Get the exit status of the command

    # Check the exit status
    if ( $rc == 0 ) {
        print "Done.\n";
        return 1;              # The target was stopped successfully
    }
    else {
        return 0;
    }
}

sub systemdPrint {
    print "Services are now handled by systemd.\n\n";
    print "Enabled systemd targets:\n\n";
    foreach my $target (@systemdTargets) {
        if ( isSystemdEnabledUnit($target) ) {
            print "  - $target\n"    # At least one target is enabled
        }
    }
    print "\nPlease check the documentation for further details.\nExiting.\n";
    exit 1;
}
1;    # End of module
