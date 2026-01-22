#!/bin/bash
# shellcheck disable=SC2154
# Read configuration from localconfig.xml using xmllint (faster than Java CLI)

LOCALCONFIG="/opt/zextras/conf/localconfig.xml"

# Helper function to get value from localconfig.xml
get_lc() {
  /opt/zextras/common/bin/xmllint --xpath "string(//key[@name='$1']/value)" "$LOCALCONFIG" 2>/dev/null
}

# Read required values from localconfig.xml
ldap_url=$(get_lc "ldap_url")
ldap_bind_url=$(get_lc "ldap_bind_url")
ldap_port=$(get_lc "ldap_port")
antispam_enable_restarts=$(get_lc "antispam_enable_restarts")
antispam_enable_rule_compilation=$(get_lc "antispam_enable_rule_compilation")
antispam_enable_rule_updates=$(get_lc "antispam_enable_rule_updates")

# openldap
# Check for ldap_bind_url first (can contain multiple URLs), then fall back to ldap_url
if [[ -n "$ldap_bind_url" ]]; then
  bind_url="$ldap_bind_url"
  # Extract first URL for ldap_domain
  read -ra bind_url_array <<<"$ldap_bind_url"
  first_url=${bind_url_array[0]}
else
  # Read LDAP bind urls as bash array from ldap_url
  read -ra bind_url_array <<<"$ldap_url"
  first_url=${bind_url_array[0]}
  bind_url="$first_url"
fi

# Remove the protocol and retrieve the hostname
url="${first_url#*//}"
ldap_domain="${url%:*}"

# Write environment file (quote values with spaces for systemd compatibility)
{
  echo "antispam_enable_restarts=${antispam_enable_restarts}"
  echo "antispam_enable_rule_compilation=${antispam_enable_rule_compilation}"
  echo "antispam_enable_rule_updates=${antispam_enable_rule_updates}"
  echo "bind_url=${bind_url}"
  echo "ldap_domain=${ldap_domain}"
  echo "ldap_port=${ldap_port}"
} >/opt/zextras/data/systemd.env
