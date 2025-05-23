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

dbfile=${cbpolicyd_db_file:=/opt/zextras/data/cbpolicyd/db/cbpolicyd.sqlitedb}

rewrite_config() {
  /opt/zextras/libexec/configrewrite cbpolicyd >/dev/null 2>&1
}

get_pid() {
  pid=$(pgrep -f /opt/zextras/common/bin/cbpolicyd)
}

check_running() {
  get_pid
  if [ "$pid" = "" ]; then
    running=0
  else
    running=1
  fi
}

#
# Main
#
case "$1" in
  'start')
    if [ ! -x /opt/zextras/common/bin/cbpolicyd ]; then
      echo "cbpolicyd not installed, skipping."
      exit 0
    fi
    check_running

    echo -n "Starting policyd..."
    if [ $running = 1 ]; then
      echo "policyd is already running."
      exit 0
    else
      if [ ! -d /opt/zextras/data/cbpolicyd/db ]; then
        mkdir /opt/zextras/data/cbpolicyd/db
      fi
      if [ ! -f "${dbfile}" ]; then
        /opt/zextras/libexec/zmcbpolicydinit
        rc=$?
        if [ $rc -ne 0 ]; then
          echo "Unable to initialize cbpolicyd database."
          exit 1
        fi
      fi
      if [ "$2" = "" ]; then
        rewrite_config
      fi
      /opt/zextras/common/bin/cbpolicyd --config /opt/zextras/conf/cbpolicyd.conf 2>/dev/null
      for ((i = 0; i < 10; i++)); do
        sleep 1
        check_running
        if [ $running = 1 ]; then
          break
        fi
      done
      if [ "$pid" = "" ]; then
        echo "failed."
        exit 1
      else
        echo "done."
      fi
    fi
    ;;

  'kill' | 'stop')
    check_running
    echo -n "Stopping policyd..."
    if [ $running = 0 ]; then
      echo "policyd is not running."
      exit 0
    else
      echo "$pid" | xargs kill 2>/dev/null
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
    ;;

  'restart' | 'reload')
    $0 stop
    $0 start "$2"
    ;;

  'status')
    check_running
    echo -n "policyd is "
    if [ $running = 0 ]; then
      echo "not running."
      exit 1
    else
      echo "running."
      exit 0
    fi
    ;;

  *)
    echo "Usage: $0 start|stop|kill|reload|restart|status"
    exit 1
    ;;
esac
