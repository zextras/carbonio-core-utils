#!/bin/bash

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

if [ "$(whoami)" != zextras ]; then
  echo Error: must be run as zextras user
  exit 1
fi

if [ ! -x "/opt/zextras/common/sbin/amavisd" ]; then
  exit 0
fi

source /opt/zextras/bin/zmshutil || exit 1

if is_systemd; then
  systemd_print
fi
zmsetvars

if [ ! -d "/opt/zextras/data/amavisd/.spamassassin" ]; then
  mkdir -p /opt/zextras/data/amavisd/.spamassassin
fi

rewrite_config() {
  /opt/zextras/libexec/configrewrite amavis antispam >/dev/null 2>&1
  /opt/zextras/libexec/zmaltermimeconfig >/dev/null 2>&1
}

check_running() {
  # Get pid from scanning the proc table.
  if [ "$pid" = "" ]; then
    # pid file is NULL.  Get info from proc table.
    pid=$(ps axo user,pid,ppid,command | awk '{ if ((($4 ~ /^amavisd$/) || ($4 ~ /^\/opt\/zextras\/common\/sbin\/amavisd$/)) && ($5 ~ /^\(master\)$/)) { print $2 } }')
  fi
  # If pid is still not set, then we cannot find any amavisd (master) process.  Assume amavisd is not running.
  if [ "$pid" = "" ]; then
    running=0
    return
  fi

  # If we get to this point the pid was defined in the pid file.  But we're not sure we trust it's validity
  # so we're going the verify it from ps output!
  pid=$(ps axo user,pid,ppid,command | awk '{ if (($2 == "$pid") && (($4 ~ /^amavisd$/) || ($4 ~ /^\/opt\/zextras\/common\/sbin\/amavisd$/)) && ($5 ~ /^\(master\)$/)) { print $2 } }')
  # If pid is NULL now, then the pid stored in the pid file was bogus!
  # Let's try to find the true amavisd (master) process ID
  if [ "$pid" = "" ]; then
    pid=$(ps axo user,pid,ppid,command | awk '{ if ((($4 ~ /^amavisd$/) || ($4 ~ /^\/opt\/zextras\/common\/sbin\/amavisd$/)) && ($5 ~ /^\(master\)$/)) { print $2 } }')
  fi
  # If the pid is still NULL now, it really must not be running.
  if [ "$pid" = "" ]; then
    running=0
    return
  else
    running=1
    return
  fi
}

check_running_mc() {
  #  Get pid from scanning the proc table.
  if [ "$mcpid" = "" ]; then
    # pid file is NULL.  Get info from proc table.
    mcpid=$(ps axo user,pid,ppid,command | awk '{ if ((($6 ~ /amavis-mc$/) || ($6 ~ /\/opt\/zextras\/common\/sbin\/amavis-mc$/))) { print $2 } }')
  fi
  # If pid is still not set, then we cannot find any amavisd (master) process.  Assume amavisd is not running.
  if [ "$mcpid" = "" ]; then
    running_mc=0
    return
  fi

  running_mc=1
  return
}

#
# Main
#
case "$1" in
  'start')
    check_running_mc
    echo -n "Starting amavisd-mc..."
    if [ $running_mc = 1 ]; then
      echo "amavisd-mc is already running."
    else
      if [ $running_mc = 0 ]; then
        sudo /opt/zextras/common/sbin/amavis-mc
        for ((i = 0; i < 10; i++)); do
          check_running_mc
          if [ $running_mc = 1 ]; then
            break
          fi
          sleep 1
        done
      fi
      if [ "$mcpid" = "" ]; then
        echo "failed."
        exit
      else
        echo "done."
      fi
    fi
    check_running
    echo -n "Starting amavisd..."
    if [ $running = 1 ]; then
      echo "amavisd is already running."
      exit 0
    else
      if [ ! -d /opt/zextras/data/amavisd/quarantine ]; then
        mkdir /opt/zextras/data/amavisd/quarantine
      fi
      if [ ! -d /opt/zextras/data/amavisd/tmp ]; then
        mkdir /opt/zextras/data/amavisd/tmp
      else
        find /opt/zextras/data/amavisd/tmp -maxdepth 1 -type d -name 'amavis-*' -exec rm -rf {} \; >/dev/null 2>&1
      fi
      if [ ! -d /opt/zextras/data/amavisd/var ]; then
        mkdir /opt/zextras/data/amavisd/var
      fi
      if [ "$2" == "" ]; then
        rewrite_config
      fi
      /opt/zextras/common/sbin/amavisd -X no_conf_file_writable_check -c \
        /opt/zextras/conf/amavisd.conf &
      for ((i = 0; i < 10; i++)); do
        check_running
        if [ $running = 1 ]; then
          break
        fi
        sleep 1
      done
      if [ "$pid" = "" ]; then
        echo "failed."
      else
        echo "done."
      fi
    fi
    ;;

  'kill' | 'stop')
    check_running
    echo -n "Stopping amavisd..."
    if [ $running = 0 ]; then
      echo "amavisd is not running."
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

    check_running_mc
    echo -n "Stopping amavisd-mc..."
    if [ $running_mc = 0 ]; then
      echo "amavisd-mc is not running."
    else
      kill "$mcpid" 2>/dev/null
      rc=$?
      for ((i = 0; i < 10; i++)); do
        check_running_mc
        if [ $running_mc = 0 ]; then
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
    echo -n "amavisd is "
    if [ $running = 0 ]; then
      echo "not running."
      exit 1
    else
      echo "running."
    fi
    check_running_mc
    echo -n "amavisd-mc is "
    if [ $running_mc = 0 ]; then
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
