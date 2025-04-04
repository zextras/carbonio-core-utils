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

if [ ! -x /opt/zextras/common/sbin/postfix ]; then
  echo "Error: postfix not installed"
  exit 1
fi

if [ -f "/opt/zextras/conf/mta_milter_options" ]; then
  source /opt/zextras/conf/mta_milter_options
fi
zimbraMilterServerEnabled=${zimbraMilterServerEnabled:=FALSE}

if [ "$zimbraMilterServerEnabled" = "TRUE" ]; then
  START_SCRIPTS="zmmilterctl zmsaslauthdctl postfix"
  STOP_SCRIPTS="postfix zmsaslauthdctl zmmilterctl"
else
  START_SCRIPTS="zmsaslauthdctl postfix"
  STOP_SCRIPTS="postfix zmsaslauthdctl"
fi

rewrite_config() {
  echo -n "Rewriting configuration files..."
  if [ ! -f /opt/zextras/common/conf/main.cf ]; then
    touch /opt/zextras/common/conf/main.cf
    /opt/zextras/bin/postconf -e mail_owner="${postfix_mail_owner}" setgid_group="${postfix_setgid_group}"
  fi
  /opt/zextras/libexec/configrewrite antispam antivirus opendkim mta sasl >/dev/null 2>&1
  rc=$?
  if [ $rc -eq 0 ]; then
    echo "done."
  else
    echo "failed."
  fi
}

case "$1" in
  start)
    if [ "$2" == "" ]; then
      rewrite_config
    fi
    STATUS=0
    for i in $START_SCRIPTS; do
      /opt/zextras/bin/"$i" start norewrite
      R=$?
      if [ $R -ne "0" ]; then
        echo "$i failed to start"
        STATUS=$R
      fi
    done
    exit $STATUS
    ;;
  stop)
    for i in $STOP_SCRIPTS; do
      /opt/zextras/bin/"$i" stop
    done
    ;;
  reload | restart)
    if [ "$2" == "" ]; then
      rewrite_config
    fi
    for i in $START_SCRIPTS; do
      if [ "$2" == "" ]; then
        /opt/zextras/bin/"$i" reload
      else
        /opt/zextras/bin/"$i" reload "$2"
      fi
    done
    ;;
  status)
    STATUS=0
    for i in $START_SCRIPTS; do
      /opt/zextras/bin/"$i" status >/dev/null 2>&1
      R=$?
      if [ $R -ne "0" ]; then
        echo "$i is not running"
        STATUS=$R
      fi
    done
    exit $STATUS
    ;;
  *)
    echo "$0 start|stop|restart|reload|status"
    exit 1
    ;;
esac
