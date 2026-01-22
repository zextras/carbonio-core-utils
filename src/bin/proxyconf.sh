#!/bin/bash
# SPDX-FileCopyrightText: 2026 Zextras <https://www.zextras.com>
# SPDX-License-Identifier: GPL-2.0-only
#
# Compatibility wrapper — Go replacement for the legacy zmproxyconf Perl script.
# Prints the assembled nginx configuration by following all include directives.
exec /opt/zextras/bin/configd proxy conf "$@"
