#!/bin/bash

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

source /opt/zextras/bin/zmshutil || exit 1
zmsetvars

if [ "$(whoami)" != "zextras" ]; then
  echo "$0 must be run as user zextras."
  exit 1
fi

sudo /opt/zextras/common/sbin/qshape.pl "$@"
