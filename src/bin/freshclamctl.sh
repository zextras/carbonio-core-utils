#!/bin/bash

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

if [ "$(whoami)" != zextras ]; then
  echo Error: must be run as zextras user
  exit 1
fi

if [ ! -x "/opt/zextras/common/bin/freshclam" ]; then
  exit 0
fi

source /opt/zextras/bin/zmshutil || exit 1
is_systemd
if [ $? -eq 1 ]; then
  systemd_print
fi
zmsetvars

rewrite_config() {
  /opt/zextras/libexec/configrewrite antivirus >/dev/null 2>&1
}

get_pid() {
  pid=$(pidof /opt/zextras/common/bin/freshclam)
}

check_running() {
  get_pid
  # freshclam
  if [ "$pid" = "" ]; then
    running=0
  else
    running=1
  fi
}

pskillall() {
  killsig="$1"
  pid=$(pidof "$2")
  kill "${killsig}" "${pid}"
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
    echo -n "Starting freshclam..."
    if [ $running = 1 ]; then
      echo "freshclam is already running."
    else
      /opt/zextras/common/bin/freshclam \
        --config-file=/opt/zextras/conf/freshclam.conf --quiet --daemon --checks=12 \
        >>"${zimbra_log_directory}/freshclam.log" 2>&1 &
      echo "done."
    fi
    exit 0
    ;;

  'kill')
    if [[ "${pid}" != "" ]]; then
      pid=$(pidof /opt/zextras/common/bin/freshclam)
      kill "$cpid" 2>/dev/null
    fi
    pskillall /opt/zextras/common/bin/freshclam
    exit 0
    ;;

  'stop')
    check_running
    echo -n "Stopping freshclam..."
    if [ $running = 0 ]; then
      echo "freshclam is not running."
    else
      kill "$pid" 2>/dev/null
      rc=$?
      if [ $rc -eq 0 ]; then
        echo "done."
      else
        echo "failed."
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
    echo -n "freshclam is "
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
