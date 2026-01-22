#!/bin/bash
# SPDX-FileCopyrightText: 2026 Zextras <https://www.zextras.com>
# SPDX-License-Identifier: GPL-2.0-only
#
# Compatibility wrapper — delegates zmtlsctl to the Go-based `configd tls`
# subcommand. Preserves the legacy CLI surface:
#   zmtlsctl                        → config rewrite only
#   zmtlsctl <mode>                 → set zimbraMailMode + rewrite
#   zmtlsctl help|--help|-help      → help
case "${1:-}" in
  help | --help | -help) exec /opt/zextras/bin/configd tls --help ;;
  *) exec /opt/zextras/bin/configd tls "$@" ;;
esac
