#!/bin/bash

# SPDX-FileCopyrightText: 2026 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

# Much faster; just call zmlocalconfig once
source /opt/zextras/bin/zmshutil || exit 1
zmsetvars -f

java_options="-XX:ErrorFile=/opt/zextras/log"

# Use the Carbonio-bundled JVM directly. Avoids the chicken-and-egg
# where setup.pl invokes Java tools BEFORE zimbra_java_home is written
# to localconfig, which used to cause "/bin/java: No such file" errors.
JAVA_BIN=/opt/zextras/common/lib/jvm/java/bin/java

# shellcheck disable=SC2086
exec "${JAVA_BIN}" ${java_options} \
  -client ${zimbra_zmjava_options} \
  -Dzimbra.home=/opt/zextras \
  -classpath "/opt/zextras/mailbox/jars/*" \
  "$@"
