#!/bin/bash

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

if [ "$(whoami)" != zextras ]; then
  echo Error: must be run as zextras user
  exit 1
fi

source /opt/zextras/bin/zmshutil || exit 1

if is_systemd; then
  systemd_print
fi
zmsetvars

if [ "$ldap_is_master" = "false" ]; then
  if [ "$ldap_url" = "$ldap_master_url" ] && [ "$1" != "stop" ]; then
    echo "ldap_url and ldap_master_url cannot be the same on an ldap replica"
    exit 1
  fi
fi

get_pid() {
  pid=$(pidof /opt/zextras/common/libexec/slapd)
}

check_running() {
  get_pid
  if [ "$pid" = "" ]; then
    running=0
  else
    running=1
  fi
}

check_listening() {
  searchtimeout=30 #timelimit for ldapsearch
  if [ "$ldap_common_require_tls" = "0" ]; then
    /opt/zextras/common/bin/ldapsearch -x -l $searchtimeout -b "" -s base -H ldapi:/// >/dev/null 2>&1
  else
    /opt/zextras/common/bin/ldapsearch -ZZ -x -l $searchtimeout -b "" -s base -H ldapi:/// >/dev/null 2>&1
  fi
  rc=$?
  if [ $rc -ne 0 ]; then
    listening=0
  else
    listening=1
  fi
}

start() {
  # Our ldap url should be the first in the list in localconfig
  bind_url=$ldap_bind_url
  if [ "$bind_url" = "" ]; then
    bind_url=$(echo "${ldap_url}" | awk '{print $1}')
  fi

  check_running
  echo -n "Starting openldap..."
  if [ $running = 1 ]; then
    echo "openldap is already running."
    exit 1
  fi

  /opt/zextras/libexec/zmslapd -l LOCAL0 \
    -h "${bind_url} ldapi:///" -F /opt/zextras/data/ldap/config

  for ((i = 0; i < 10; i++)); do
    check_running
    check_listening
    if [ $running = 1 ] && [ $listening = 1 ]; then
      break
    fi
    sleep 1
  done
  if [ "$pid" != "" ]; then
    echo "done."
    exit 0
  else
    echo "failed."
    exit 1
  fi
}

stop() {
  check_running
  echo -n "Stopping openldap..."
  if [ $running = 0 ]; then
    echo "openldap is not running."
    exit 0
  else
    kill "$pid" 2>/dev/null
    rc=$?
    for ((i = 0; i < 10; i++)); do
      check_running
      if [ $running = 0 ]; then
        break
      fi
      sleep 1
    done
    if [ "$rc" -ne 0 ]; then
      echo "failed."
      exit 1
    else
      echo "done."
    fi
  fi
  exit 0
}

status() {
  echo -n "openldap is "
  check_running
  if [ $running = 0 ]; then
    echo "not running."
    exit 1
  else
    echo "running."
    exit 0
  fi
}

case "$1" in
  restart)
    $0 stop
    $0 start
    ;;
  start)
    start
    ;;
  stop)
    stop
    ;;
  status)
    status
    ;;
  *)
    echo "Usage: $0 start|stop|status"
    exit 1
    ;;
esac
