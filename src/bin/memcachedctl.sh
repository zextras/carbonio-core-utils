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

get_pid() {
  pid=$(pidof /opt/zextras/common/bin/memcached)
}

check_running() {
  get_pid
  if [ "$pid" = "" ]; then
    running=0
  else
    running=1
  fi
}

case "$1" in
  start)

    if [ ! -x /opt/zextras/common/bin/memcached ]; then
      echo "Error: memcached not installed"
      exit 1
    fi

    check_running
    echo -n "Starting memcached..."
    if [ $running = 1 ]; then
      echo "memcached is already running."
      exit 0
    fi

    /opt/zextras/common/bin/memcached -d -U 0 -l 127.0.1.1,127.0.0.1 -p 11211
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
  stop)
    check_running
    echo -n "Stopping memcached..."
    if [ $running = 0 ]; then
      echo "memcached is not running."
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
    ;;
  restart)
    $0 stop
    $0 start
    ;;
  reload)
    check_running
    if [ $running = 1 ] && [ "$pid" != "" ]; then
      echo -n "Reloading memcached..."
      kill -HUP "$pid"
      echo "done."
    fi

    ;;
  status)
    echo -n "memcached is "
    check_running
    if [ $running = 0 ]; then
      echo "not running."
      exit 1
    else
      echo "running."
      exit 0
    fi
    ;;
  *)
    echo "$0 start|stop|restart|reload|status"
    exit 1
    ;;
esac
