#!/bin/bash
# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

#
# Find and set local config variables.
#

# Array of systemd targets to check and start
systemd_targets=(
  "carbonio-directory-server.target"
  "carbonio-appserver.target"
  "carbonio-proxy.target"
  "carbonio-mta.target"
)

zmsetvars() {
  if [ "$1" = "-f" ]; then
    shift
  else
    if [ "${zmsetvars}" = "true" ]; then
      return
    fi
  fi

  zmlocalconfig="/opt/zextras/bin/zmlocalconfig"
  if [ ! -x "${zmlocalconfig}" ]; then
    echo Error: can not find zmlocalconfig program
    exit 1
  fi

  if ! eval "$(${zmlocalconfig} -q -m export)"; then
    echo Error: executing: ${zmlocalconfig} -q -m export
    exit 1
  fi

  export zmsetvars='true'
}

#
# Check if a conditional expression is true.
#
assert() {
  if [ "$@" ]; then
    return
  fi
  echo "Error: assertion" "$@" "failed" && exit 1
}

#
# Get available system memory in KB.
#
zmsysmemkb() {
  if [ -f /proc/meminfo ]; then
    memkb=$(awk '/^MemTotal.*kB$/ { print $2; }' /proc/meminfo)
  else
    memkb=$(/usr/sbin/sysctl hw.memsize 2>/dev/null | awk -F: '{ print $2 / 1024; }')
  fi
  if ! echo "$memkb" | grep '^[0-9]*$' >/dev/null; then
    memkb=524288
  fi
  echo "$memkb"
}

is_systemd() {
  local systemd_status=1 # Default to not enabled

  # Check if any of the systemd targets are enabled
  for target in "${systemd_targets[@]}"; do
    if is_systemd_enabled_unit "$target"; then
      systemd_status=0 # At least one target is enabled
    fi
  done

  return $systemd_status
}

is_systemd_active_unit() {
  local unit_name="$1"

  # Execute the command and check if the unit is enabled
  if systemctl is-active "${unit_name}" &>/dev/null; then
    return 0 # The unit is running
  elif [ $? -eq 1 ]; then
    return 1 # The unit is not running
  else
    echo "Error: Unable to check the status of ${unit_name}" >&2
    return 2 # An error occurred
  fi
}

is_systemd_enabled_unit() {
  local unit_name="$1"

  # Execute the command and check if the unit is enabled
  if systemctl is-enabled "${unit_name}" &>/dev/null; then
    return 0 # The unit is enabled
  else
    return 1 # The unit is disabled
  fi
}

start_all_systemd_targets() {
  local target

  # Start all enabled systemd units
  for target in "${systemd_targets[@]}"; do
    if is_systemd_enabled_unit "$target"; then
      systemctl start "${target}"
      if [ $? -eq 0 ]; then
        echo "Started ${target}"
      else
        echo "Failed to start ${target}"
      fi
    fi
  done
}

stop_all_systemd_targets() {
  local target

  # Stop all enabled systemd units
  for target in "${systemd_targets[@]}"; do
    if is_systemd_enabled_unit "$target"; then
      systemctl stop "${target}"
      if [ $? -eq 0 ]; then
        echo "Stopped ${target}"
      else
        echo "Failed to stop ${target}"
      fi
    fi
  done
}

systemd_print() {
  echo "Services are now handled by systemd."
  echo
  echo "Enabled systemd targets:"
  echo

  for target in "${systemd_targets[@]}"; do
    if is_systemd_enabled_unit "$target"; then
      echo "  - ${target}" # At least one target is enabled
    fi
  done

  echo
  echo "Please check the documentation for further details."
  echo "Exiting."
  exit 1
}
