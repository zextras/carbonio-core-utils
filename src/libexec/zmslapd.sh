#!/bin/bash

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

export LD_PRELOAD=/opt/zextras/common/lib/libjemalloc.so

exec /opt/zextras/common/libexec/slapd "$@"
