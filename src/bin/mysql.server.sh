#!/bin/bash

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

source /opt/zextras/bin/zmshutil || exit 1

if is_systemd; then
  systemd_print
fi
zmsetvars

if [ "$(whoami)" != zextras ]; then
  echo Error: must be run as zextras user
  exit 1
fi

if [ ! -x /opt/zextras/common/bin/mysqld_safe ]; then
  exit 0
fi

if [ ! -d "${mailboxd_directory}" ]; then
  exit 0
fi

if [ ! -d "${zimbra_tmp_directory}/mysql" ]; then
  mkdir -p "${zimbra_tmp_directory}/mysql" >/dev/null 2>&1
fi

assert -d "${zimbra_tmp_directory}"
assert -r "${mysql_mycnf}"

get_pid() {
  pid=$(pgrep -f '/opt/zextras/.*conf/my.cnf')
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
  'start')
    check_running
    if [ $running = 1 ]; then
      echo "mysqld_safe already running"
      exit 0
    fi

    # --defaults-file must be first argument
    echo -n "Starting mysqld..."
    /opt/zextras/common/bin/mysqld_safe \
      --defaults-file="${mysql_mycnf}" \
      --external-locking \
      --log-error="${mysql_errlogfile}" \
      --malloc-lib=/opt/zextras/common/lib/libjemalloc.so \
      --ledir=/opt/zextras/common/sbin </dev/null >/dev/null 2>&1 &
    running=0
    for ((i = 0; i < 10; i++)); do
      /opt/zextras/bin/mysqladmin -s ping >/dev/null
      rc=$?
      if [ $rc -eq 0 ]; then
        running=1
        break
      fi
      sleep 3
    done
    if [ ${running} -ne 1 ]; then
      echo "failed."
    else
      echo "done."
    fi
    ;;

  'stop')
    check_running
    echo -n "Stopping mysqld..."
    if [ $running = 0 ]; then
      echo "mysqld not running: no pid"
      exit 0
    else
      echo "$pid" | xargs kill >>"${mysql_errlogfile}" 2>&1
      rc=$?
      for ((i = 0; i < zimbra_mysql_shutdown_timeout; i++)); do
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
    $0 start
    ;;

  'status')
    echo -n "mysql is "
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
    echo "Usage: $0 start|stop|restart|reload|status"
    exit 0
    ;;
esac
