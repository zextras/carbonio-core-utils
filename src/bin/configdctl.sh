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
is_systemd
if [ $? -eq 1 ]; then
  systemd_print
fi
zmsetvars

# These variables are not set if run via cron.  Make sure they are set prior to execution
if [ "$JYTHONPATH" = "" ]; then
  JAVA_HOME=/opt/zextras/common/lib/jvm/java
  PATH=/opt/zextras/bin:/opt/zextras/common/bin:${JAVA_HOME}/bin:/usr/sbin:${PATH}
  export PATH

  JYTHONPATH="/opt/zextras/common/lib/jylibs"
  export JYTHONPATH
fi

NC=$(command -v nc 2>/dev/null)
NC=${NC:-$(command -v netcat 2>/dev/null)}

get_pid() {
  pid=$(pgrep -f '/opt/zextras/.*/java.*configd')
}

check_running() {
  get_pid

  if [[ -z "${pid}" ]]; then
    running=0
  else
    status=$(echo STATUS | $NC -w 15 localhost "${zmconfigd_listen_port}" 2>/dev/null)
    rc=$?
    if [ $rc -eq 0 ] && [ "$status" = "SUCCESS ACTIVE" ]; then
      running=1
    else
      running=2
    fi
  fi
}

startconfigd() {
  err=0

  executable="/opt/zextras/libexec/zmconfigd"
  if [[ ! -x "${executable}" ]]; then
    echo "Error: configd executable does not exist or is not executable."
    err=1
    return
  fi

  echo -n "Starting configd..."
  check_running

  # Wait for the process to start
  case ${running} in
    1)
      echo "configd is already running."
      return
      ;;
    2)
      echo "configd is running, but it's not ready yet."
      return
      ;;
  esac

  if [[ -z "${JYTHONPATH}" ]]; then
    echo "Error: JYTHONPATH is unset!"
    err=1
    return
  fi

  # Kill existing process if PID is found
  if [[ -n "${pid}" ]]; then
    kill "${pid}" || { echo "Warning: Failed to kill existing configd process."; }
  fi

  # Start new process
  "${executable}" >/dev/null 2>&1 &

  # Wait for the process to start
  for ((i = 0; i < 10; i++)); do
    check_running
    if [[ ${running} -eq 1 ]]; then
      echo "done."
      return
    fi
    sleep 3
  done

  echo "Failed to start configd."
  err=1
}

case "$1" in
  'start')
    startconfigd
    exit "${err}"
    ;;

  'kill' | 'stop')
    check_running
    echo -n "Stopping configd..."
    if [[ ${running} -lt 1 ]]; then
      echo "configd is not running."
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
      if [ "$running" -ne 0 ]; then
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
    $0 start
    ;;

  'status')
    echo -n "configd is "
    check_running

    # Wait for the process to start
    case ${running} in
      0)
        echo "not running."
        exit 1
        ;;
      1)
        echo "already running."
        exit 0
        ;;
      2)
        echo "running, but it's not ready yet."
        exit 1
        ;;
    esac
    ;;
  *)
    echo "Usage: $0 start|stop|kill|restart|reload|status"
    exit 1
    ;;

esac
