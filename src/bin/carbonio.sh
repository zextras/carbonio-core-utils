#!/bin/bash

# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

# shellcheck disable=SC1091
# shellcheck disable=SC2068

if [ "$(whoami)" != "zextras" ]; then
  echo "Please run as zextras user"
  exit 1
fi

carbonio_cli_path="/usr/share/carbonio-advanced-cli"
carbonio_cli="carbonio-advanced-cli.jar"

# check for tty presence and set TPUT usage accordingly
{
  [[ -t 0 && -t 1 && -n $TERM && $TERM != dumb ]] && which tput &>/dev/null && USE_TPUT=1
} || USE_TPUT=0

# default columns value
TTY_COLS=80
if [[ $USE_TPUT -eq 1 ]]; then
  # cols existing tty value
  TTY_COLS="$(tput cols)"
fi

call_cli() {
  if [ ! -f "${carbonio_cli_path}/${carbonio_cli}" ]; then
    exec /opt/zextras/bin/zmjava \
      com.zimbra.cs.account.ProvUtil \
      "$@"
  else
    exec /opt/zextras/bin/zmjava \
      -cp "${carbonio_cli_path}/*" \
      -Xmx128m com.zextras.cli.AdvancedCLI \
      --columns "$TTY_COLS" \
      "$@"
  fi
}

call_cli "$@"
