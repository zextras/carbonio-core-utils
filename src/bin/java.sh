#!/bin/bash

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

# Much faster; just call zmlocalconfig once
source /opt/zextras/bin/zmshutil || exit 1
zmsetvars -f

for i in $ZIMBRA_EXTENSIONS; do
  if [ -d "/opt/zextras/lib/ext/$i" ]; then
    ZIMBRA_EXT_DIR="${ZIMBRA_EXT_DIR}:/opt/zextras/lib/ext/$i/*"
  fi
done

java_options="-XX:ErrorFile=/opt/zextras/log"

if [ "${zimbra_zmjava_java_library_path}" = "" ]; then
  zimbra_zmjava_java_library_path=/opt/zextras/lib
fi

# shellcheck disable=SC2086
exec "${zimbra_java_home}/bin/java" ${java_options} \
  -client ${zimbra_zmjava_options} \
  -Dzimbra.home=/opt/zextras \
  -Djava.library.path=${zimbra_zmjava_java_library_path} \
  -classpath "/opt/zextras/mailbox/jars/*" \
  "$@"
