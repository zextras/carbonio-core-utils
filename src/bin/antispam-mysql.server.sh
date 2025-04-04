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

antispam_mysql_enabled=$(echo "${antispam_mysql_enabled}" | tr '[:upper:]' '[:lower:]')
if [ "${antispam_mysql_enabled}" != "true" ] && [ "$1" != "stop" ] && [ "$1" != "restart" ] && [ "$1" != "reload" ]; then
  # antispam is not configured to use mysql db, so nothing to do here.
  exit 0
fi

# If antispam_mysql_host is set to the local host then setup and use local MySQL db.
# Otherwise, reconfigure the salocal.cf file to point to a remote MySQL db.
if [ "${antispam_mysql_host}" != "127.0.0.1" ] && [ "${antispam_mysql_host}" != "$(zmhostname)" ] && [ "${antispam_mysql_host}" != "localhost" ]; then
  # antispam is not configured to use DB on this (local) host
  exit 0
fi

if [ ! -x /opt/zextras/common/bin/mysql ] && [ ! -x /opt/zextras/common/sbin/amavisd ]; then
  exit 0
fi

if [ ! -d "${zimbra_tmp_directory}/antispam-mysql" ]; then
  mkdir -p "${zimbra_tmp_directory}/antispam-mysql" >/dev/null 2>&1
fi

assert -d "${zimbra_tmp_directory}"
assert -x /opt/zextras/common/bin/mysqld_safe

get_pid() {
  pid=$(pgrep -f '/opt/zextras/.*conf/antispam-my.cnf')
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
    if [ ! -d "${antispam_mysql_data_directory}" ]; then
      # The antispam mysql data directory does not appear to exist, assuming that db has not been initialized
      /opt/zextras/libexec/zmantispamdbinit
    fi

    assert -r "${antispam_mysql_mycnf}"
    if [ $running = 1 ]; then
      echo "mysqld_safe for anti-spam already running"
      exit 0
    fi

    # --defaults-file must be first argument
    echo -n "Starting mysqld for anti-spam..."
    /opt/zextras/common/bin/mysqld_safe \
      --defaults-file="${antispam_mysql_mycnf}" \
      --external-locking \
      --malloc-lib=/opt/zextras/common/lib/libjemalloc.so \
      --ledir=/opt/zextras/common/sbin </dev/null >/dev/null 2>&1 &
    running=0
    for ((i = 0; i < 10; i++)); do
      /opt/zextras/bin/antispam-mysqladmin -s ping >/dev/null
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
    echo -n "Stopping mysqld for anti-spam..."
    if [ $running = 0 ]; then
      # If mysql for antispam is enabled, then print the warning message.  Otherwise, we
      # shouldn't care that there is no PID file.
      if [ "${antispam_mysql_enabled}" == "TRUE" ]; then
        echo "mysqld for anti-spam not running: no pid"
      fi
      exit 0
    else
      echo "$pid" | xargs kill >>"${antispam_mysql_errlogfile}" 2>&1
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
