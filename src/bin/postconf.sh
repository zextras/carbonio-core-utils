#!/bin/bash

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

if [ ! -x /opt/zextras/common/sbin/postconf ]; then
  echo "Error: postfix not installed"
  exit 1
fi

sudo /opt/zextras/common/sbin/postconf "$@"
