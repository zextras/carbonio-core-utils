#!/bin/bash
# SPDX-FileCopyrightText: 2026 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

# Compatibility wrapper — translates zmlocalconfig invocations to configd localconfig.
# Drop-in replacement for the Java LocalConfigCLI.

CONFIGD=/opt/zextras/bin/configd

if [ ! -x "$CONFIGD" ]; then
  echo "Error: configd binary not found at $CONFIGD" >&2
  exit 1
fi

# Handle flags that are not ported
for arg in "$@"; do
  case "$arg" in
    -l | --reload)
      echo "Warning: -l (reload) is deprecated and not supported by configd" >&2
      exit 1
      ;;
    -i | --info | --all)
      echo "Warning: $arg (info/docs) is not supported by configd" >&2
      exit 1
      ;;
  esac
done

exec "$CONFIGD" localconfig "$@"
