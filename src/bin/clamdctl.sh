#!/bin/bash

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

if [ "$(whoami)" != zextras ]; then
  echo Error: must be run as zextras user
  exit 1
fi

if [ ! -x "/opt/zextras/common/sbin/clamd" ]; then
  exit 0
fi

source /opt/zextras/bin/zmshutil || exit 1

if is_systemd; then
  systemd_print
fi
zmsetvars

if [ ! -d "/opt/zextras/data/clamav/db" ]; then
  mkdir -p /opt/zextras/data/clamav/db
fi

rewrite_config() {
  /opt/zextras/libexec/configrewrite antivirus >/dev/null 2>&1
}

get_pid() {
  # shellcheck disable=SC2009
  # we only need the parent pid: pgrep and pidof don't support this use case
  pid=$(ps --ppid 1 -o pid,cmd | grep /opt/zextras/common/sbin/clamd | awk '{ print $1 }')
}

check_running() {
  get_pid
  # clamd
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
    if [ "$2" == "" ]; then
      rewrite_config
    fi

    check_running
    echo -n "Starting clamd..."
    if [ $running = 1 ]; then
      echo "clamd is already running."
    else
      /opt/zextras/common/sbin/clamd \
        --config-file=/opt/zextras/conf/clamd.conf \
        >>"${zimbra_log_directory}/clamd.log" 2>&1 &

      for ((i = 0; i < 12; i++)); do
        check_running
        if [ $running = 1 ]; then
          echo "done."
          exit 0
        fi
        sleep 5
      done
      echo "failed."
      exit 1
    fi
    exit 0
    ;;

  'kill')
    check_running
    kill "$pid" 2>/dev/null
    exit 0
    ;;

  'stop')
    check_running
    echo -n "Stopping clamd..."
    if [ $running = 0 ]; then
      echo "clamd is not running."
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
      if [ $rc -ne 0 ]; then
        echo "failed."
        quit 1
      else
        echo " done."
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
    echo -n "clamd is "
    if [ $running = 1 ]; then
      echo "running."
      exit 0
    else
      echo "not runnning."
      exit 1
    fi
    ;;

  *)
    echo "Usage: $0 start|stop|kill|restart|status"
    exit 1
    ;;
esac
