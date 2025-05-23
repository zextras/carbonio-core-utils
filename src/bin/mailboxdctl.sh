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

if [ ! -d "${mailboxd_directory}" ]; then
  exit 0
fi

if [ ! -x /opt/zextras/common/bin/mysql ]; then
  exit 0
fi

if [ ! -d "${zimbra_java_home}" ]; then
  exit 0
fi

NC=$(which nc 2>/dev/null)
NC=${NC:-$(which netcat 2>/dev/null)}
#
# Memory for use by JVM.
#
javaXmx=${mailboxd_java_heap_size:=512}
javaXms=${javaXmx}
mailboxd_java_heap_new_size_percent=${mailboxd_java_heap_new_size_percent:=25}

get_pid() {
  pid=$(pgrep -f 'com.zextras.mailbox.Mailbox')
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
    if [ "$2" = "" ]; then
      /opt/zextras/bin/zmtlsctl >/dev/null 2>&1
    fi

    check_running
    if [ $running = 1 ]; then
      echo "mailboxd is already running."
      exit 0
    fi

    mkdir -p "${mailboxd_directory}/work/service/jsp"

    mailboxd_thread_stack_size=${mailboxd_thread_stack_size:=256k}
    if ! echo "${mailboxd_java_options}" | grep -q 'Xss'; then
      mailboxd_java_options="${mailboxd_java_options} -Xss${mailboxd_thread_stack_size}"
    fi

    networkaddress_cache_ttl=${networkaddress_cache_ttl:=60}
    if ! echo "${mailboxd_java_options}" | grep -q 'sun.net.inetaddr.ttl'; then
      mailboxd_java_options="${mailboxd_java_options} -Dsun.net.inetaddr.ttl=${networkaddress_cache_ttl}"
    fi

    if ! echo "${mailboxd_java_options}" | grep -q "log4j"; then
      mailboxd_java_options="${mailboxd_java_options} -Dlog4j.configurationFile=${zimbra_log4j_properties}"
    fi

    echo -n "Starting mailboxd..."

    # shellcheck disable=SC2086
    /opt/zextras/common/bin/java \
      -Dfile.encoding=UTF-8 \
      $mailboxd_java_options \
      -Xms${javaXms}m \
      -Xmx${javaXmx}m \
      -Djava.io.tmpdir=/opt/zextras/mailboxd/work \
      -Djava.library.path=/opt/zextras/lib \
      -Dzimbra.config=/opt/zextras/conf/localconfig.xml \
      -cp /opt/zextras/mailbox/jars/mailbox.jar:/opt/zextras/mailbox/jars/* \
      com.zextras.mailbox.Mailbox &>>/opt/zextras/log/zmmailboxd.out &
    rc=$?
    if [ $rc != 0 ]; then
      echo "failed."
      exit $rc
    fi
    rc=1
    MPORT=$(/opt/zextras/bin/zmprov -l gs "${zimbra_server_hostname}" zimbraMailPort | grep zimbraMailPort: | awk '{print $2}')
    ncOpt="-z"
    for ((i = 0; i < 12; i++)); do
      $NC $ncOpt localhost "${MPORT}" >/dev/null 2>&1
      rc=$?
      if [ $rc -eq 0 ]; then
        rc=0
        break
      fi
      sleep 5
    done
    if [ $rc = 0 ]; then
      echo "done."
      /opt/zextras/bin/advanced_status 2
    else
      echo "failed."
    fi
    exit $rc
    ;;

  'kill' | 'stop')
    check_running
    echo -n "Stopping mailboxd..."
    if [ $running = 0 ]; then
      echo "${servicename} is not running."
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

  'restart' | 'reload')
    $0 stop
    $0 start "$2"
    ;;

  'status')
    echo -n "mailboxd is "
    check_running
    if [ $running = 0 ]; then
      echo "not running."
      exit 1
    else
      echo "running."
      /opt/zextras/bin/advanced_status 0
      exit 0
    fi
    ;;

  'update')
    mk_download_dir
    ;;

  *)
    echo "Usage: $0 start|stop|kill|restart|reload|status|update"
    exit 1
    ;;
esac
