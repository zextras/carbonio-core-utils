#!/bin/bash -

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

PATH=/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin:/opt/zextras/bin:/opt/zextras/libexec

echo ""
printf %s "Rotating log files:"
cd /var/log || return
log_name=carbonio.log
if [ -f "${log_name}" ]; then
  printf %s " ${log_name}"
  if [ -x /usr/bin/gzip ]; then gzext=".gz"; else gzext=""; fi
  if [ -f "${log_name}.6${gzext}" ]; then mv -f "${log_name}.6${gzext}" "${log_name}.7${gzext}"; fi
  if [ -f "${log_name}.5${gzext}" ]; then mv -f "${log_name}.5${gzext}" "${log_name}.6${gzext}"; fi
  if [ -f "${log_name}.4${gzext}" ]; then mv -f "${log_name}.4${gzext}" "${log_name}.5${gzext}"; fi
  if [ -f "${log_name}.3${gzext}" ]; then mv -f "${log_name}.3${gzext}" "${log_name}.4${gzext}"; fi
  if [ -f "${log_name}.2${gzext}" ]; then mv -f "${log_name}.2${gzext}" "${log_name}.3${gzext}"; fi
  if [ -f "${log_name}.1${gzext}" ]; then mv -f "${log_name}.1${gzext}" "${log_name}.2${gzext}"; fi
  if [ -f "${log_name}.0${gzext}" ]; then mv -f "${log_name}.0${gzext}" "${log_name}.1${gzext}"; fi
  if [ -f "${log_name}" ]; then
    touch "${log_name}.$$" && chmod 644 "${log_name}.$$" && chown zextras:zextras "${log_name}.$$"
    mv -f "${log_name}" "${log_name}.0" && mv "${log_name}.$$" "${log_name}" && if [ -x /usr/bin/gzip ]; then
      gzip -9 "${log_name}.0"
    fi
  fi
fi

# truncate, no saving old logs
true >carbonio-stats.log

cd /opt/zextras/log || return
for i in myslow.log logger_myslow.log sync.log zcs.log zmmtaconfig.log httpd_access.log httpd_error.log clamd.log zmswatch.out zmlogswatch.out freshclam.log synctrace.log syncstate.log nginx.log; do
  if [ -f "${i}" ]; then
    printf %s " ${i}"
    if [ -x /usr/bin/gzip ]; then gzext=".gz"; else gzext=""; fi
    if [ -f "${i}.6${gzext}" ]; then mv -f "${i}.6${gzext}" "${i}.7${gzext}"; fi
    if [ -f "${i}.5${gzext}" ]; then mv -f "${i}.5${gzext}" "${i}.6${gzext}"; fi
    if [ -f "${i}.4${gzext}" ]; then mv -f "${i}.4${gzext}" "${i}.5${gzext}"; fi
    if [ -f "${i}.3${gzext}" ]; then mv -f "${i}.3${gzext}" "${i}.4${gzext}"; fi
    if [ -f "${i}.2${gzext}" ]; then mv -f "${i}.2${gzext}" "${i}.3${gzext}"; fi
    if [ -f "${i}.1${gzext}" ]; then mv -f "${i}.1${gzext}" "${i}.2${gzext}"; fi
    if [ -f "${i}.0${gzext}" ]; then mv -f "${i}.0${gzext}" "${i}.1${gzext}"; fi
    if [ -f "${i}" ]; then
      touch "${i}.$$" && chmod 644 "${i}.$$" && chown zextras:zextras "${i}.$$"
      mv -f "${i}" "${i}.0" && mv "${i}.$$" "${i}" && if [ -x /usr/bin/gzip ]; then
        gzip -9 "${i}.0"
      fi
    fi
  fi
done
echo ""

echo "Sending sighup to syslogd"
systemctl kill -s HUP rsyslog.service >/dev/null 2>&1 || true

pid=$(pgrep -f '/opt/zextras/.*/nginx.*conf')
if [ "$pid" != "" ]; then
  echo "Sending USR1 to nginx"
  kill -USR1 "$pid"
fi
