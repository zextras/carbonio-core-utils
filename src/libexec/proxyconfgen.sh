#!/bin/bash
#
# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only
#

source /opt/zextras/bin/zmshutil || exit 1
zmsetvars -f

java_options="-XX:ErrorFile=/opt/zextras/log"

if [ "${zimbra_zmjava_java_library_path}" = "" ]; then
  zimbra_zmjava_java_library_path=/opt/zextras/lib
fi

# shellcheck disable=SC2086
exec "${zimbra_java_home}/bin/java" ${java_options} \
  -client ${zimbra_zmjava_options} \
  -Dzimbra.home=/opt/zextras \
  -Djava.library.path=${zimbra_zmjava_java_library_path} \
  -classpath "/opt/zextras/lib/jars/proxyconfgen.jar" \
  com.zimbra.cs.util.proxyconfgen.ProxyConfGen
  "$@"

