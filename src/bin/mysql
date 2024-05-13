#!/bin/bash

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

source /opt/zextras/bin/zmshutil || exit 1
zmsetvars

exec /opt/zextras/common/bin/mysql -S /run/carbonio/mysql.sock \
  -u "${zimbra_mysql_user}" --password="${zimbra_mysql_password}" "$@"
