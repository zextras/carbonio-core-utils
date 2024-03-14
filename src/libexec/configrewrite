#!/bin/bash

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

source /opt/zextras/bin/zmshutil || exit 1
zmsetvars

NC=$(which nc 2>/dev/null)
NC=${NC:-$(which netcat 2>/dev/null)}

echo REWRITE "$@" | $NC -w "${zimbra_configrewrite_timeout}" localhost "${zmconfigd_listen_port}" >/dev/null 2>&1
rc=$?

# If nc fails to connect, run zmconfigd directly
if [ $rc -ne 0 ]; then
  /opt/zextras/libexec/zmconfigd "$@"
  rc=$?
  stty echo
else
  sleep 5
fi
exit $rc
