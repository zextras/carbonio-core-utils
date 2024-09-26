#!/bin/bash

if [ "$(whoami)" != "zextras" ]; then
  echo "${0} must be run as user zextras"
  exit 1
fi

delete_command="certbot delete -n --cert-name"

certonly() {
  if certbot "${@}" --dry-run; then
    certbot "${@}"
  fi
}

delete() {
  for domain in "${@}"; do
    ${delete_command} "$domain"
  done
}

case "$1" in
  certonly)
    certonly "${@}"
    ;;
  delete)
    delete "${@:2}"
    ;;
  *)
    echo "Usage: $(basename "$0") certonly|delete"
    exit 0
    ;;
esac
