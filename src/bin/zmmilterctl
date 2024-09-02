#!/bin/bash

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

source /opt/zextras/bin/zmshutil || exit 1
is_systemd
if [ $? -eq 1 ]; then
  systemd_print
fi
zmsetvars

configfile=/opt/zextras/conf/localconfig.xml
log4jfile=/opt/zextras/conf/milter.log4j.properties
java="/opt/zextras/bin/zmjava"

runcmd="${java} -Dlog4j.configurationFile=file:${log4jfile} -Dzimbra.home=\"/opt/zextras\" -Dzimbra.config=\"${configfile}\" \
   com.zimbra.cs.milter.MilterServer"

get_pid() {
  pid=$(pgrep -f '/opt/zextras/.*/java.*milter.MilterServer')
}

check_running() {
  get_pid
  if [ "$pid" = "" ]; then
    running=0
  else
    running=1
  fi
}

refresh() {
  get_pid
  if [ "$pid" = "" ]; then
    echo "milter server is not currently running"
  else
    kill -CONT "$pid" 2>/dev/null
  fi
}

case "$1" in
  start)
    check_running
    echo -n "Starting milter server..."
    if [ $running = 1 ]; then
      echo "milter server is already running."
      exit 0
    fi

    nohup sh -c "exec ${runcmd} 2>&1" >/opt/zextras/log/milter.out 2>&1 &
    sleep 3

    check_running
    if [ $running = 1 ]; then
      echo "done."
      exit 0
    else
      echo "failed."
      exit 1
    fi
    ;;
  stop)
    check_running
    echo -n "Stopping milter server..."
    if [ $running = 0 ]; then
      echo "milter server is not running."
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
    $0 stop
    $0 start
    ;;
  refresh)
    refresh
    ;;
  status)
    echo -n "Milter server is "
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
    echo "$0 start|stop|restart|reload|refresh|status"
    exit 1
    ;;
esac
