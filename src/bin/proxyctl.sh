#!/bin/bash

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

if [ "$(whoami)" != zextras ]; then
  echo "Error: must be run as zextras user"
  exit 1
fi

source /opt/zextras/bin/zmshutil || exit 1

if is_systemd; then
  systemd_print
fi
zmsetvars

configfile=/opt/zextras/conf/nginx.conf

get_pid() {
  # shellcheck disable=SC2009
  # we only need the parent pid: pgrep and pidof don't support this use case
  pid=$(ps --ppid 1 -o pid,cmd | grep /opt/zextras/common/sbin/nginx | awk '{ print $1 }')
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
    if [ ! -x /opt/zextras/common/sbin/nginx ]; then
      echo "Error: nginx not installed"
      exit 1
    fi

    check_running
    echo -n "Starting proxy..."
    if [ $running = 1 ]; then
      echo "proxy is already running."
      exit 0
    fi
    if [ "$2" = "" ]; then
      /opt/zextras/libexec/configrewrite proxy >/dev/null 2>&1
    fi

    if [ ! -f ${configfile} ]; then
      echo "failed.  ${configfile} is missing."
      exit 1
    fi

    # read the last line of nginx.conf which indicates the conf gen result
    res=$(tail -n 1 ${configfile})
    warn=''

    if ! [[ $res =~ __SUCCESS__ ]]; then
      msg=$(echo "$res" | awk -F ':' '{print $2}')
      if [ "$msg" = "" ]; then msg="unknown"; fi
      if ! [[ $res =~ "No available nginx lookup handlers could be contacted" ]]; then
        echo "failed."
        echo "nginx start failed. reason: $msg"
        exit 1
      else
        warn=$msg
      fi
    fi

    /opt/zextras/common/sbin/nginx -c ${configfile}
    for ((i = 0; i < 10; i++)); do
      check_running
      if [ $running = 1 ]; then
        break
      fi
      sleep 1
    done
    if [ "$pid" != "" ]; then
      echo "done."
      if [ "$warn" != "" ]; then
        echo "Warning: $warn"
      fi
      exit 0
    else
      echo "failed."
      exit 1
    fi
    ;;
  stop)
    check_running
    echo -n "Stopping proxy..."
    if [ $running = 0 ]; then
      echo "proxy is not running."
      exit 0
    else
      /opt/zextras/common/sbin/nginx -c /opt/zextras/conf/nginx.conf -s stop
      rc=$?
      for ((i = 0; i < 60; i++)); do
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
    $0 start "$2"
    ;;
  reload)
    check_running
    if [ $running = 1 ] && [ "$pid" != "" ]; then
      echo -n "Reloading proxy..."
      /opt/zextras/common/sbin/nginx -c /opt/zextras/conf/nginx.conf -s reload
      echo "done."
    fi

    ;;
  status)
    echo -n "proxy is "
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
