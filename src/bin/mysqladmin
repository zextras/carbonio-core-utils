#!/bin/bash

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

source /opt/zextras/bin/zmshutil || exit 1
zmsetvars

exec /opt/zextras/common/bin/mysqladmin \
  -S /run/carbonio/mysql.sock \
  -u root \
  --password="${mysql_root_password}" "$@"
