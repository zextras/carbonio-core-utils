#!/bin/bash

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

source /opt/zextras/bin/zmshutil || exit 1
zmsetvars

if [ "$(whoami)" != zextras ]; then
  echo Error: must be run as zextras user
  exit 1
fi

is_running() {
  zmmailboxdctl status 2>/dev/null
  return
}

opth=0
for opt in "$@"; do
  if [ "$opt" = "-h" ] || [ "$opt" = "--help" ]; then
    opth=1
    break
  fi
done

pid=$(pgrep -f '/opt/zextras/.*/java.*redolog.util.PlaybackUtil')

if [ $opth -eq 0 ]; then
  if is_systemd_active_unit carbonio-appserver.service; then
    echo "Error: carbonio-appserver.service still running. Stop it to execute zmplayredo."
    exit 1
  fi
  if is_running; then
    echo "Error: mailboxd still running.  Stop mailboxd before running zmplayredo."
    exit 1
  fi
  if [ "$pid" != "" ]; then
    echo "Error: another instance of zmplayredo (pid=$pid) is already running"
    echo "       remove $pid if this is not the case"
    exit 1
  fi
fi

if [ -d "${zimbra_java_home}/jre" ]; then
  JRE_EXT_DIR=${zimbra_java_home}/jre/lib/ext
fi

jardirs="${JRE_EXT_DIR}:/opt/zextras/mailbox/jars/*:"
if [ -e /opt/zextras/lib/ext-common ]; then
  jardirs="${jardirs}:/opt/zextras/lib/ext-common/*"
fi
while IFS= read -r -d '' jd; do
  if [ "${jd}" != /opt/zextras/lib/ext ]; then
    jardirs="${jardirs}:${jd}/*"
  fi
done < <(find /opt/zextras/lib/ext -type d -print0)

#
# Memory for use by JVM
#
jm=${mailboxd_java_heap_size}
if [ -n "$jm" ]; then
  xms_xmx_options="-Xms${jm}m -Xmx${jm}m"
fi

# Remove "-verbose:gc" and all options that start with "-XX:+PrintGC".  These pollute stdout/stderr.
for opt in $mailboxd_java_options; do
  if [ "$opt" = "-verbose:gc" ] || [[ "$opt" == "-XX:+PrintGC"* ]]; then
    continue
  fi
  if [ -z "$sanitized_options" ]; then
    sanitized_options="$opt"
  else
    sanitized_options="$sanitized_options $opt"
  fi
done

# shellcheck disable=SC2086
${zimbra_java_home}/bin/java \
  ${xms_xmx_options} ${sanitized_options} \
  -Dzimbra.config=/opt/zextras/conf/localconfig.xml \
  -Djava.library.path=/opt/zextras/lib \
  -classpath ${jardirs} \
  com.zimbra.cs.redolog.util.PlaybackUtil "$@"
rc=$?
exit $rc
