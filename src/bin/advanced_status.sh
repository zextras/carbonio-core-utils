#!/bin/bash

check_advanced() {
  local timeout
  timeout="${1:-2}" # Default to 2

  if ! ls /opt/zextras/lib/ext/carbonio/carbonio-advanced-*.jar >/dev/null 2>&1; then
    return 1
  fi

  echo "Carbonio Advanced installed."
  echo -n "Checking advanced modules status"

  if ! command -v /opt/zextras/bin/carbonio >/dev/null 2>&1; then
    echo "Failed to check advanced modules status. Carbonio CLI not found!"
    return 1
  fi

  for ((i = 0; i < 10; i++)); do
    echo -n "."
    if check_running_advanced; then
      echo
      if ! /opt/zextras/bin/carbonio --json core getAllServicesStatus |
        jq -r '.response[] | "\(.commercialName) is \(if .running then "running" else "NOT running" end)"'; then

        echo "Failed to check advanced modules status. Carbonio CLI not working!"
        return 1
      fi
      return 0
    fi
    sleep "$timeout"
  done

  echo
  echo "Failed to check advanced modules status. Carbonio Advanced is not running."
  echo "Check logs for more information."
  return 1
}

check_running_advanced() {
  local output
  if output=$(/opt/zextras/bin/carbonio core getVersion 2>&1); then
    [[ "$output" != *"Unable to communicate with server"* ]]
  else
    return 1
  fi
}

check_advanced "$1"
