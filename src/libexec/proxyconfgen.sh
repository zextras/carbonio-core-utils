#!/bin/bash
# SPDX-FileCopyrightText: 2026 Zextras <https://www.zextras.com>
# SPDX-License-Identifier: GPL-2.0-only
#
# Compatibility wrapper — Go replacement for the legacy zmproxyconfgen Java wrapper.
# Generates nginx proxy configuration files via the running configd daemon.
exec /opt/zextras/bin/configd proxy gen "$@"
