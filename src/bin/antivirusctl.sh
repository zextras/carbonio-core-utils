#!/bin/bash
# SPDX-FileCopyrightText: 2026 Zextras <https://www.zextras.com>
# SPDX-License-Identifier: GPL-2.0-only
# Compatibility wrapper — delegates to configd service.
exec /opt/zextras/bin/configd service "$1" "antivirus" "${@:2}"
