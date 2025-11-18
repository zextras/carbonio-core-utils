#!/bin/bash
#
# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only
#

exec /opt/zextras/bin/zmjava -classpath "/opt/zextras/lib/jars/proxyconfgen.jar" com.zimbra.cs.util.proxyconfgen.ProxyConfGen "$@"
