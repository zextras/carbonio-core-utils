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

MYSQL="/opt/zextras/bin/mysql -u zextras --password=${zimbra_mysql_password}"

START_ORDER="mysql.server zmmailboxdctl"
STOP_ORDER="zmmailboxdctl mysql.server"

STATUS=0

flushDirtyPages() {
  # make sure mysql is running
  /opt/zextras/bin/mysql.server status >/dev/null 2>&1
  rc=$?
  if [ $rc -ne 0 ]; then
    return
  fi

  # make sure innodb is enabled
  local innodb_status
  innodb_status=$(echo "show engines;" | ${MYSQL} | grep InnoDB | cut -f2)
  if [ "$innodb_status" = "DISABLED" ]; then
    return
  fi

  # set max_dirty_pages=0 so mysql starts flushing dirty pages to disk.
  ${MYSQL} -e "set global innodb_max_dirty_pages_pct=0;"
  rc=$?
  if [ $rc -ne 0 ]; then
    return
  fi

  # wait for 600 seconds or until there are no more dirty pages
  local i=0
  while [ $i -lt 600 ]; do
    local pages
    pages=$(${MYSQL} -e "show engine innodb status\G" | grep '^Modified db pages' | grep -Eo '[0-9]+$')
    local total_pages
    total_pages=$(awk -v RS=' ' '{sum+=$1} END {print sum}' <<<"$pages")

    if [ "$total_pages" = "0" ]; then
      break
    fi

    i=$((i + 1))
    sleep 1
  done
}

case "$1" in
  start)
    if [ "$2" == "" ]; then
      # Call tlsctl to get all the mailbox config files
      /opt/zextras/bin/zmtlsctl >/dev/null 2>&1
    fi
    for i in $START_ORDER; do
      /opt/zextras/bin/"$i" start norewrite >/dev/null 2>&1
      R=$?
      if [ $R -ne "0" ]; then
        STATUS=$R
      fi
    done
    exit $STATUS
    ;;
  stop)
    for i in $STOP_ORDER; do
      if [ "$i" = "mysql.server" ]; then
        flushDirtyPages
      fi
      /opt/zextras/bin/"$i" stop
      R=$?
      if [ $R -ne "0" ]; then
        STATUS=$R
      fi
    done
    exit $STATUS
    ;;
  restart | reload)
    for i in $STOP_ORDER; do
      if [ "$i" = "mysql.server" ]; then
        flushDirtyPages
      fi
      /opt/zextras/bin/"$i" stop
      R=$?
      if [ $R -ne "0" ]; then
        STATUS=$R
      fi
    done
    if [ "$2" == "" ]; then
      # Call tlsctl to get all the mailbox config files
      /opt/zextras/bin/zmtlsctl >/dev/null 2>&1
    fi
    for i in $START_ORDER; do
      /opt/zextras/bin/"$i" start norewrite
      R=$?
      if [ $R -ne "0" ]; then
        STATUS=$R
      fi
    done
    exit $STATUS
    ;;
  status)
    for i in $START_ORDER; do
      if [ "$i" = "mysql.server" ]; then
        /opt/zextras/bin/mysqladmin status >/dev/null 2>&1
      else
        /opt/zextras/bin/"$i" status >/dev/null 2>&1
      fi
      R=$?
      if [ $R -ne "0" ]; then
        echo "$i is not running."
        if [ "$i" != "zmconfigdctl" ]; then
          STATUS=$R
        fi
      fi
    done
    exit $STATUS
    ;;
  *)
    echo "$0 start|stop|restart|reload|status"
    exit 1
    ;;
esac
