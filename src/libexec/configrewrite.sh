#!/bin/bash

# SPDX-FileCopyrightText: 2026 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

source /opt/zextras/bin/zmshutil || exit 1
zmsetvars

NC=$(which nc 2>/dev/null)
NC=${NC:-$(which netcat 2>/dev/null)}

echo REWRITE "$@" | $NC -w "${zimbra_configrewrite_timeout}" localhost "${zmconfigd_listen_port}" >/dev/null 2>&1
rc=$?

# If nc fails to connect, the configd service should be running
# No fallback needed - configd should be managed by systemd
if [ $rc -ne 0 ]; then
  echo "Warning: Could not connect to configd service on port ${zmconfigd_listen_port}" >&2
  echo "Ensure carbonio-configd.service is running" >&2
else
  sleep 5
fi
exit $rc
