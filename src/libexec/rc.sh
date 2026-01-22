#!/bin/bash
# zmrc - SSH wrapper for remote Carbonio service control
# Legacy compatibility shim: forwards commands to configd control -H <host>

set -e

if [ $# -lt 1 ]; then
  echo "Usage: zmrc <hostname>" >&2
  echo "Reads commands from stdin in format: HOST:<hostname> <action> <service>" >&2
  exit 1
fi

HOST="$1"

# Read command from stdin
while IFS= read -r line; do
  # Parse: HOST:<hostname> <action> <service>
  # Example: HOST:mail.example.com start mailbox

  if [[ ! "$line" =~ ^HOST: ]]; then
    echo "Error: Invalid command format. Expected 'HOST:<hostname> <action> <service>'" >&2
    exit 1
  fi

  # Strip "HOST:<hostname> " prefix
  cmd="${line#HOST:*[[:space:]]}"

  # Extract action and service
  action=$(echo "$cmd" | awk '{print $1}')
  service=$(echo "$cmd" | awk '{print $2}')

  case "$action" in
    start | stop | restart | status)
      exec /opt/zextras/bin/configd control "$action" -H "$HOST" "$service"
      ;;
    *)
      echo "Error: Unknown action '$action'. Valid: start, stop, restart, status" >&2
      exit 1
      ;;
  esac
done
