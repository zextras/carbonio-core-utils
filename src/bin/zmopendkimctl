#!/bin/bash

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

# shellcheck disable=SC2046

if [ "$(whoami)" != zextras ]; then
  echo Error: must be run as zextras user
  exit 1
fi

if [ ! -x "/opt/zextras/common/sbin/opendkim" ]; then
  exit 0
fi

source /opt/zextras/bin/zmshutil || exit 1
is_systemd
if [ $? -eq 1 ]; then
  systemd_print
fi
zmsetvars

odk=/opt/zextras/common/sbin/opendkim
config=/opt/zextras/conf/opendkim.conf

rewrite_config() {
  /opt/zextras/libexec/configrewrite opendkim >/dev/null 2>&1
}

check_running() {
  if pidof "${odk}" >/dev/null 2>&1; then
    running=1
  else
    running=0
  fi
}

start() {
  check_running
  if [ $running = 0 ]; then
    if [ "$1" == "" ]; then
      rewrite_config
    fi

    if ! $odk -x $config -u zextras; then
      echo "Failed to start opendkim"
      exit 1
    fi
    echo "Started opendkim"
  else
    echo "zmopendkimctl already running"
    exit 0
  fi
}

stop() {
  check_running
  if [ $running = 0 ]; then
    echo "zmopendkimctl not running"
    exit 0
  else
    echo -n "Stopping opendkim..."
    if ! kill $(pidof $odk 2>/dev/null); then
      echo " failed to stop $PID"
      exit 1
    else
      echo " done."
    fi
  fi
  exit 0
}

status() {
  check_running
  echo -n "zmopendkimctl is "
  if [ $running = 0 ]; then
    echo "not running."
    exit 1
  else
    echo "running."
    exit 0
  fi
}

case "$1" in
  reload | restart)
    $0 stop
    $0 start "$2"
    ;;
  start)
    start "$2"
    ;;
  stop)
    stop
    ;;
  status)
    status
    ;;
  *)
    echo "Usage: $0 start|stop|restart|reload|status"
    exit 1
    ;;
esac
