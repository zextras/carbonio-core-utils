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

rewrite_config() {
  /opt/zextras/libexec/configrewrite sasl >/dev/null 2>&1
}

get_pid() {
  pid=$(pidof /opt/zextras/common/sbin/saslauthd)
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
    check_running
    echo -n "Starting saslauthd..."
    if [ $running = 1 ]; then
      echo "already running."
      exit 0
    fi
    if [ "$2" = "" ]; then
      rewrite_config
    fi
    /opt/zextras/common/sbin/saslauthd -r -a zimbra
    for ((i = 0; i < 10; i++)); do
      check_running
      if [ $running = 1 ]; then
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
    ;;

  'kill' | 'stop')
    check_running
    echo -n "Stopping saslauthd..."
    if [ $running = 0 ]; then
      echo "saslauthd is not running."
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
    if [ $running = 1 ]; then
      echo "saslauthd is running."
      exit 0
    else
      echo "saslauthd is not running."
      exit 1
    fi
    ;;

  *)
    echo "Usage: $0 start|stop|kill|restart|reload|status"
    exit 1
    ;;
esac
