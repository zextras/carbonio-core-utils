#!/bin/bash

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

# Much faster; just call zmlocalconfig once
source /opt/zextras/bin/zmshutil || exit 1
zmsetvars -f

if [ -d "${zimbra_java_home}/jre" ]; then
  JRE_EXT_DIR=${zimbra_java_home}/jre/lib/ext
else
  JRE_EXT_DIR=${zimbra_java_home}/lib/ext
fi

ZIMBRA_EXTENSIONS="backup clamscanner network zimbrahsm zimbrasync twofactorauth"
ZIMBRA_EXT_DIR="/opt/zextras/lib/ext-common/*"
for i in $ZIMBRA_EXTENSIONS; do
  if [ -d "/opt/zextras/lib/ext/$i" ]; then
    ZIMBRA_EXT_DIR="${ZIMBRA_EXT_DIR}:/opt/zextras/lib/ext/$i/*"
  fi
done

java_options="-XX:ErrorFile=/opt/zextras/log"

if [ "${zimbra_zmjava_java_library_path}" = "" ]; then
  zimbra_zmjava_java_library_path=/opt/zextras/lib
fi

if [ "${zimbra_zmjava_java_ext_dirs}" = "" ]; then
  zimbra_zmjava_java_ext_dirs=${JRE_EXT_DIR}:/opt/zextras/mailbox/jars:${ZIMBRA_EXT_DIR}
fi

if [ -n "${EXT_JAR_PATH}" ]; then
  zimbra_zmjava_java_ext_dirs=${zimbra_zmjava_java_ext_dirs}:${EXT_JAR_PATH}
fi

# shellcheck disable=SC2086
exec "${zimbra_java_home}/bin/java" ${java_options} \
  -client ${zimbra_zmjava_options} \
  -Dzimbra.home=/opt/zextras \
  -Djava.library.path=${zimbra_zmjava_java_library_path} \
  -classpath "${zimbra_zmjava_java_ext_dirs}:/opt/zextras/lib/jars/*:/opt/zextras/mailbox/jars/*:/opt/zextras/conf" \
  "$@"
