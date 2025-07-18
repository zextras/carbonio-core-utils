#!/bin/bash

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

shopt -s nullglob

root_user=root

if [ "$(whoami)" != root ]; then
  echo Error: must be run as root user
  exit 1
fi

root_group=root

postfix_owner=postfix
postfix_suid_group=postdrop

syslog_user=syslog
syslog_group=adm

zextras_user=zextras
zextras_group=zextras

verbose=no

components="\
  keyview \
  conf/crontabs \
  common/lib/jylibs \
"

usage() {
  echo "$0 [-help] [-verbose]"
  echo "-help     Usage"
  echo "-verbose  Verbose output"
  echo
  exit
}

for opt in "$@"; do
  case "$opt" in
    -verbose | --verbose | -v)
      verbose=yes
      shift
      ;;
    -help | --help | -h | --h)
      usage
      ;;
    *)
      echo "Unknown option $opt"
      usage
      ;;
  esac
done

printMsg() {
  if [ $verbose = "yes" ]; then
    echo "$@"
  fi
}

dirs=(
  "/opt/zextras/admin"
  "/opt/zextras/jetty"
  "/opt/zextras/jetty_base"
  "/opt/zextras/jython"
  "/opt/zextras/mailbox"
  "/opt/zextras/mailboxd"
  "/opt/zextras/web"
  "/opt/zextras/zal"
)

for dir in "${dirs[@]}"; do
  if [ -d "$dir" ]; then
    chown -R ${zextras_user}:${zextras_group} "$dir" 2>/dev/null
  fi
done

chown ${zextras_user}:${zextras_group} /opt/zextras/config.* 2>/dev/null

chown ${root_user}:${root_group} /opt
chmod 755 /opt
chown ${root_user}:${root_group} /opt/zextras
chmod 755 /opt/zextras
chown -R ${root_user}:${root_group} /opt/zextras/common
chmod 755 /opt/zextras/common
chown -R ${root_user}:${zextras_group} /opt/zextras/common/conf
chmod 775 /opt/zextras/common/conf

for i in master.cf master.cf.in bysender bysender.lmdb tag_as_foreign.re tag_as_foreign.re.in tag_as_originating.re tag_as_originating.re.in; do
  if [ -f /opt/zextras/common/conf/${i} ]; then
    chown -f ${zextras_user}:${zextras_group} /opt/zextras/common/conf/${i}
  fi
done

if [ -d "/opt/zextras/common/certbot/etc/letsencrypt" ]; then
  chown -R ${zextras_user}:${zextras_group} /opt/zextras/common/certbot/etc/letsencrypt
fi

if [ -f /opt/zextras/common/conf/main.cf ]; then
  chown -f ${root_user}:${root_group} /opt/zextras/common/conf/main.cf
fi

if [ -d /opt/zextras ]; then
  chown ${root_user}:${root_group} /opt/zextras
  chmod 755 /opt/zextras

  if [ -f /opt/zextras/.viminfo ]; then
    chown ${zextras_user}:${zextras_group} /opt/zextras/.viminfo
  fi

  if [ -f /opt/zextras/.ldaprc ]; then
    chown ${zextras_user}:${zextras_group} /opt/zextras/.ldaprc
  fi

  if [ -f /opt/zextras/.exrc ]; then
    chown ${zextras_user}:${zextras_group} /opt/zextras/.exrc
  fi

  if [ -f /opt/zextras/.bash_profile ]; then
    chown ${zextras_user}:${zextras_group} /opt/zextras/.bash_profile
  fi

  if [ -f /opt/zextras/.bashrc ]; then
    chown ${zextras_user}:${zextras_group} /opt/zextras/.bashrc
  fi

  if [ -f /opt/zextras/.platform ]; then
    chown ${zextras_user}:${zextras_group} /opt/zextras/.platform
  fi

  for i in .zmmailbox_history .zmprov_history .bash_history; do
    if [ ! -f /opt/zextras/${i} ]; then
      touch /opt/zextras/${i}
    fi
    chown ${zextras_user}:${zextras_group} /opt/zextras/${i}
    chmod 640 /opt/zextras/${i}
  done

  if [ -f /selinux/enforce ]; then
    if [ "$(cat /selinux/enforce 2>/dev/null)" = "1" ]; then
      # make sure ssh keys are in home dir selinux type
      chcon -R -v -u system_u -t user_home_t /opt/zextras/.ssh/
      # Fix upgrades selinux perms
      restorecon -R /etc/security
    fi
  fi

  # Required by HSM features
  if [ -d /opt/zextras/cache ]; then
    chown ${zextras_user}:${zextras_group} /opt/zextras/cache
  fi

  if [ -d /opt/zextras/contrib ]; then
    chown -R ${root_user}:${root_group} /opt/zextras/contrib
    chmod 755 /opt/zextras/contrib/* 2>/dev/null
  fi

  # Required by HSM features
  if [ -d /opt/zextras/incoming ]; then
    chown -R ${zextras_user}:${zextras_group} /opt/zextras/incoming
    chmod 755 /opt/zextras/incoming/* 2>/dev/null
  fi

  if [ -d /opt/zextras/libexec ]; then
    chown -R ${root_user}:${root_group} /opt/zextras/libexec
    chmod 755 /opt/zextras/libexec/* 2>/dev/null
  fi

  if [ -d /opt/zextras/log ]; then
    chown -R ${zextras_user}:${zextras_group} /opt/zextras/log
    if [ -f /opt/zextras/log/.hotspot_compiler ]; then
      chown ${root_user}:${root_group} /opt/zextras/log/.hotspot_compiler
      chmod 444 /opt/zextras/log/.hotspot_compiler
    fi
  fi

  if [ -d /opt/zextras/bin ]; then
    chown -R ${root_user}:${root_group} /opt/zextras/bin
    chmod 755 /opt/zextras/bin/* 2>/dev/null
  fi

  if [ -d /opt/zextras/lib ]; then
    chown -R ${root_user}:${root_group} /opt/zextras/lib
  fi

  if [ -d /opt/zextras/conf ]; then
    printMsg "Fixing ownership and permissions on /opt/zextras/conf"
    chown -R ${zextras_user}:${zextras_group} /opt/zextras/conf

    if [ -f /opt/zextras/conf/localconfig.xml ]; then
      chown ${zextras_user}:${zextras_group} /opt/zextras/conf/localconfig.xml
      chmod 640 /opt/zextras/conf/localconfig.xml
    fi

    if [ -f /opt/zextras/conf/attrs/attrs.xml ]; then
      chown ${zextras_user}:${zextras_group} /opt/zextras/conf/attrs/attrs.xml
      chmod 444 /opt/zextras/conf/attrs/attrs.xml
    fi

    if [ -d /opt/zextras/conf/ca ]; then
      printMsg "Fixing permissions on /opt/zextras/conf/ca"
      chmod 755 /opt/zextras/conf/ca
      for i in /opt/zextras/conf/ca/*.{crt,pem}; do
        if [ -f "$i" ]; then
          printMsg "Fixing permissions on ${i}"
          chmod 644 "${i}"
        fi
      done
    fi

    if [ -d /opt/zextras/conf/spamassassin ]; then
      printMsg "Fixing permissions on /opt/zextras/conf/spamassassin"
      chmod 755 /opt/zextras/conf/spamassassin
    fi

    if [ -f /opt/zextras/conf/nginx.conf ]; then
      chown ${zextras_user}:${zextras_group} /opt/zextras/conf/nginx.conf
      chmod 644 /opt/zextras/conf/nginx.conf
    fi

    for i in /opt/zextras/conf/*-{canonical,slm,transport,vad,vam,vmd,vmm}.cf; do
      printMsg "Fixing ownership and permissions on ${i}"
      chgrp -f ${postfix_owner} "${i}"
      chmod 640 "${i}"
    done

    if [ -f /opt/zextras/conf/my.cnf ]; then
      chown ${zextras_user}:${zextras_group} /opt/zextras/conf/my.cnf
      chmod 640 /opt/zextras/conf/my.cnf
    fi

    if [ -f /opt/zextras/conf/saslauthd.conf.in ]; then
      chmod 640 /opt/zextras/conf/saslauthd.conf.in
      chown ${zextras_user}:${zextras_group} /opt/zextras/conf/saslauthd.conf.in
    fi
    if [ -f /opt/zextras/conf/saslauthd.conf ]; then
      chmod 440 /opt/zextras/conf/saslauthd.conf
      chown ${zextras_user}:${zextras_group} /opt/zextras/conf/saslauthd.conf
    fi
    if [ -f /opt/zextras/conf/sasl2/smtpd.conf.in ]; then
      chmod 640 /opt/zextras/conf/sasl2/smtpd.conf.in
      chown ${zextras_user}:${zextras_group} /opt/zextras/conf/sasl2/smtpd.conf.in
    fi
    if [ -f /opt/zextras/conf/sasl2/smtpd.conf ]; then
      chmod 640 /opt/zextras/conf/sasl2/smtpd.conf
      chown ${zextras_user}:${zextras_group} /opt/zextras/conf/sasl2/smtpd.conf
    fi

    if [ -d /opt/zextras/conf/templates/ ]; then
      chown -R ${zextras_user}:${zextras_group} /opt/zextras/conf/templates
      find /opt/zextras/conf/templates/ -type d -exec chmod 755 {} \;
      find /opt/zextras/conf/templates/ -type f -exec chmod 644 {} \;
    fi

    if [ -d /opt/zextras/conf/templates_custom/ ]; then
      chown -R ${zextras_user}:${zextras_group} /opt/zextras/conf/templates_custom
      find /opt/zextras/conf/templates_custom/ -type d -exec chmod 755 {} \;
      find /opt/zextras/conf/templates_custom/ -type f -exec chmod 644 {} \;
    fi
  fi

  if [ -d /opt/zextras/docs ]; then
    printMsg "Fixing permissions and ownership on /opt/zextras/docs"
    chown carbonio-docs-editor: /opt/zextras/docs
  fi

  if [ -d /opt/zextras/documentation ]; then
    chown -R ${zextras_user}:${zextras_group} /opt/zextras/documentation
    find /opt/zextras/documentation -type d -exec chmod 755 {} \;
    find /opt/zextras/documentation -type f -exec chmod 444 {} \;
  fi

  for i in /opt/zextras/conf/*.crt /opt/zextras/conf/*.key /opt/zextras/conf/zmssl.cnf; do
    if [ -f "${i}" ]; then
      printMsg "Fixing permissions and ownership on ${i}"
      chown ${zextras_user}:${zextras_group} "$i"
      chmod 640 "$i"
    fi
  done

  if [ ! -d /opt/zextras/data ]; then
    mkdir -p /opt/zextras/data
  fi
  chmod 755 /opt/zextras/data
  chown ${zextras_user}:${zextras_group} /opt/zextras/data
fi

# fix the temp directory
if [ ! -d /opt/zextras/data/tmp ]; then
  mkdir -p /opt/zextras/data/tmp
fi
if [ -f /opt/zextras/data/tmp/current.csr ]; then
  chown ${zextras_user}:${zextras_group} /opt/zextras/data/tmp/current.csr
  chmod 644 /opt/zextras/data/tmp/current.csr
fi

# Handle nginx path problems bug#42156
if [ ! -d /opt/zextras/data/tmp/nginx ]; then
  mkdir -p /opt/zextras/data/tmp/nginx/client
  mkdir -p /opt/zextras/data/tmp/nginx/proxy
  mkdir -p /opt/zextras/data/tmp/nginx/fastcgi
fi
chown -R ${zextras_user}:${zextras_group} /opt/zextras/data/tmp
chmod 1777 /opt/zextras/data/tmp
chmod 755 /opt/zextras/data/tmp/nginx
chmod 755 /opt/zextras/data/tmp/nginx/client
chmod 755 /opt/zextras/data/tmp/nginx/proxy
chmod 755 /opt/zextras/data/tmp/nginx/fastcgi

if [ -d /var/log/ ]; then
  printMsg "Fixing ownership and permissions on /var/log/carbonio.log"
  if [ ! -f /var/log/carbonio.log ]; then
    touch /var/log/carbonio.log
  fi
  chown ${syslog_user}:${syslog_group} /var/log/carbonio.log
  chmod 644 /var/log/carbonio.log
fi

for i in ${components}; do
  if [ -L "/opt/zextras/${i}" ]; then
    printMsg "Fixing ownership and permissions on /opt/zextras/${i}"
    for l in "/opt/zextras/${i}-"*; do
      chown ${root_user}:${root_group} "${l}" 2>/dev/null
    done
    for l in "/opt/zextras/${i}/"* "/opt/zextras/${i}/".???*; do
      chown -R ${root_user}:${root_group} "${l}" 2>/dev/null
    done
  elif [ -d "/opt/zextras/${i}" ]; then
    printMsg "Fixing ownership and permissions on /opt/zextras/${i}"
    chown -R ${root_user}:${root_group} "/opt/zextras/${i}" 2>/dev/null
    if [ "$i" = "common/lib/jylibs" ]; then
      chmod a+r "/opt/zextras/${i}/"*.class 2>/dev/null
    fi
  fi
done

if [ -d /opt/zextras/lib ]; then
  printMsg "Fixing ownership and permissions on /opt/zextras/lib"
  for i in /opt/zextras/lib/lib*so*; do
    chown ${root_user}:${root_group} "$i"
    chmod 755 "$i"
  done
  if [ -d /opt/zextras/mailbox/jars ]; then
    for i in /opt/zextras/mailbox/jars/*; do
      chown ${root_user}:${root_group} "$i"
      chmod 444 "$i"
    done
  fi

  if [ -d /opt/zextras/lib/ext ]; then
    find /opt/zextras/lib/ext -type f -exec chown ${root_user}:${root_group} {} \;
    find /opt/zextras/lib/ext -type f -exec chmod 444 {} \;
  fi
  if [ -d /opt/zextras/lib/ext-common ]; then
    find /opt/zextras/lib/ext-common -type f -exec chown ${root_user}:${root_group} {} \;
    find /opt/zextras/lib/ext-common -type f -exec chmod 444 {} \;
  fi
fi

if [ -d /opt/zextras/db ]; then
  printMsg "Fixing ownership and permissions on /opt/zextras/db"
  if [ ! -d /opt/zextras/db/data ]; then
    mkdir -p /opt/zextras/db/data
  fi
  chown -R ${zextras_user}:${zextras_group} /opt/zextras/db
  find /opt/zextras/db -maxdepth 1 -type f -exec chmod 444 {} \;
fi

if [ -d /opt/zextras/common/share/database ]; then
  for i in data/cbpolicyd data/cbpolicyd/db; do
    if [ ! -d "/opt/zextras/${i}" ]; then
      mkdir -p /opt/zextras/${i}
    fi
  done
  chown -R ${zextras_user}:${zextras_group} /opt/zextras/data/cbpolicyd
fi

if [ -x /opt/zextras/common/bin/altermime ]; then
  if [ ! -d "/opt/zextras/data/altermime" ]; then
    mkdir -p /opt/zextras/data/altermime
  fi
  chown -R ${zextras_user}:${zextras_group} /opt/zextras/data/altermime
fi

if [ -x /opt/zextras/common/sbin/amavisd ]; then
  printMsg "Fixing ownership and permissions on /opt/zextras/data/amavisd"
  if [ ! -d "/opt/zextras/data/amavisd" ]; then
    mkdir -p /opt/zextras/data/amavisd/.spamassassin
  fi
  if [ ! -d "/var/spamassassin" ]; then
    mkdir -p /var/spamassassin
    chown -R ${zextras_user}:${zextras_group} /var/spamassassin
  fi
  chown -R ${zextras_user}:${zextras_group} /opt/zextras/data/amavisd
  if [ -d /opt/zextras/data/amavisd/.spamassassin ]; then
    chown -R ${zextras_user}:${zextras_group} /opt/zextras/data/amavisd/.spamassassin
  fi
  if [ -d /opt/zextras/data/spamassassin ]; then
    chown -R ${zextras_user}:${zextras_group} /opt/zextras/data/spamassassin
  fi
fi

if [ -L /opt/zextras/jetty ]; then
  printMsg "Fixing ownership and permissions on /opt/zextras/jetty"

  chown ${root_user}:${root_group} /opt/zextras/jetty-* 2>/dev/null
  for i in \
    keystore mailboxd.{der,pem} jetty.xml{,.in} service.web.xml.in; do
    if [ -f "/opt/zextras/jetty/etc/${i}" ]; then
      chown ${zextras_user}:${zextras_group} "/opt/zextras/jetty/etc/${i}"
      chmod 640 "/opt/zextras/jetty/etc/${i}"
    fi
  done

  if [ ! -d /opt/zextras/fbqueue ]; then
    mkdir -p /opt/zextras/fbqueue
  fi
  chown ${zextras_user}:${zextras_group} /opt/zextras/fbqueue
  chmod 755 /opt/zextras/fbqueue

  for i in /opt/zextras/jetty/*; do
    chown -R ${zextras_user}:${zextras_group} "${i}"
  done

  if [ -d /opt/zextras/jetty/lib ]; then
    find /opt/zextras/jetty/lib -type f -name '*.jar' -exec chown ${root_user}:${root_group} {} \; -exec chmod 444 {} \;
    find /opt/zextras/jetty/lib -type d -exec chown ${root_user}:${root_group} {} \; -exec chmod 755 {} \;
  fi

  if [ -d /opt/zextras/jetty/common/lib ]; then
    find /opt/zextras/jetty/common/lib -type f -name '*.jar' -exec chown ${root_user}:${root_group} {} \; -exec chmod 444 {} \;
  fi

  if [ -d /opt/zextras/jetty/common ]; then
    find /opt/zextras/jetty/common -type d -exec chown ${root_user}:${root_group} {} \; -exec chmod 755 {} \;
  fi

  if [ ! -d /opt/zextras/data/mailboxd ]; then
    mkdir -p /opt/zextras/data/mailboxd
  fi
  chown ${zextras_user}:${zextras_group} /opt/zextras/data/mailboxd
  chmod 755 /opt/zextras/data/mailboxd
fi

if [ -f /opt/zextras/common/etc/java/cacerts ]; then
  chown zextras:zextras /opt/zextras/common/etc/java/cacerts
  chmod 644 /opt/zextras/common/etc/java/cacerts
fi

if [ -d /opt/zextras/ssl ]; then
  printMsg "Fixing ownership and permissions on /opt/zextras/ssl"
  chown -R ${zextras_user}:${zextras_group} /opt/zextras/ssl
  find /opt/zextras/ssl -type f -exec chmod 640 {} \;
fi

if [ -x /opt/zextras/common/libexec/slapd ]; then
  printMsg "Fixing ownership and permissions on /opt/zextras/data/ldap"
  if [ -d /opt/zextras/data/ldap ]; then
    chown -R ${zextras_user}:${zextras_group} /opt/zextras/data/ldap
    chown ${zextras_user}:${zextras_group} /opt/zextras/data/ldap
  fi
fi

if [ -d /opt/zextras/data/clamav ]; then
  chown -R ${zextras_user}:${zextras_group} /opt/zextras/data/clamav
fi

if [ -d /opt/zextras/zmstat ]; then
  printMsg "Fixing ownership and permissions on /opt/zextras/zmstat"
  chown -R ${zextras_user}:${zextras_group} /opt/zextras/zmstat
fi

if [ -x /opt/zextras/common/sbin/postfix ]; then
  printMsg "Fixing postfix related permissions"

  if [ -f /opt/zextras/common/sbin/postqueue ]; then
    chgrp -f ${postfix_suid_group} /opt/zextras/common/sbin/postqueue
    chmod -f u=rwx,g=rsx,o=rx /opt/zextras/common/sbin/postqueue
  fi
  if [ -f /opt/zextras/common/sbin/postdrop ]; then
    chgrp -f ${postfix_suid_group} /opt/zextras/common/sbin/postdrop
    chmod -f u=rwx,g=rsx,o=rx /opt/zextras/common/sbin/postdrop
  fi
  if [ -e /opt/zextras/common/conf ]; then
    if [ -f /opt/zextras/common/conf/master.cf.in ]; then
      chown -f ${zextras_user}:${zextras_group} /opt/zextras/common/conf/master.cf.in
    fi
    if [ -f /opt/zextras/common/conf/tag_as_foreign.re ]; then
      chown -f ${zextras_user}:${zextras_group} /opt/zextras/common/conf/tag_as_foreign.re
    fi
    if [ -f /opt/zextras/common/conf/tag_as_originating.re ]; then
      chown -f ${zextras_user}:${zextras_group} /opt/zextras/common/conf/tag_as_originating.re
    fi
  fi
fi

if [ -d /opt/zextras/data/postfix ]; then
  printMsg "Fixing ownership and permissions on /opt/zextras/data/postfix"
  if [ ! -d /opt/zextras/data/postfix/data ]; then
    mkdir -p /opt/zextras/data/postfix/data
  fi
  if [ ! -d /opt/zextras/data/postfix/spool/pid ]; then
    mkdir -p /opt/zextras/data/postfix/spool/pid
  fi
  chmod 755 /opt/zextras/data/postfix
  chown -fR ${postfix_owner}:${postfix_owner} /opt/zextras/data/postfix/spool
  chown -f ${root_user} /opt/zextras/data/postfix/spool
  chown -f ${postfix_owner} /opt/zextras/data/postfix/spool/pid
  chgrp -f ${root_group} /opt/zextras/data/postfix/spool/pid
  # Postfix specific permissions
  if [ -d /opt/zextras/data/postfix/spool/public ]; then
    chgrp -f ${postfix_suid_group} /opt/zextras/data/postfix/spool/public
  fi
  if [ -d /opt/zextras/data/postfix/spool/maildrop ]; then
    chmod 730 /opt/zextras/data/postfix/spool/maildrop
    chgrp -f ${postfix_suid_group} /opt/zextras/data/postfix/spool/maildrop
    chmod 730 /opt/zextras/data/postfix/spool/maildrop
  fi
  chown -f ${postfix_owner} /opt/zextras/data/postfix
  chown -f ${postfix_owner} /opt/zextras/data/postfix/* 2>/dev/null
  chgrp -f ${postfix_suid_group} /opt/zextras/data/postfix/data
  chmod 755 /opt/zextras/data/postfix/data
  chown -f ${postfix_owner}:${postfix_owner} /opt/zextras/data/postfix/data/* 2>/dev/null
  # `postfix check` checks that everything under data is not group or other writable
  chmod -R go-w /opt/zextras/data/postfix/data
  chown -f ${root_user} /opt/zextras/data/postfix/spool
  chgrp -f ${root_group} /opt/zextras/data/postfix/spool
fi

if [ -d /opt/zextras/index ]; then
  printMsg "Fixing ownership of /opt/zextras/index"
  chown ${zextras_user}:${zextras_group} /opt/zextras/index
fi

if [ -d /opt/zextras/backup ]; then
  printMsg "Fixing ownership of /opt/zextras/backup"
  chown ${zextras_user}:${zextras_group} /opt/zextras/backup
fi

if [ -d /opt/zextras/redolog ]; then
  printMsg "Fixing ownership of /opt/zextras/redolog"
  chown ${zextras_user}:${zextras_group} /opt/zextras/redolog
fi

if [ -d /opt/zextras/store ]; then
  printMsg "Fixing ownership of /opt/zextras/store"
  chown ${zextras_user}:${zextras_group} /opt/zextras/store
fi

# Fix permissions for default openldap configuration files
for i in slapd.conf slapd.conf.default slapd.ldif slapd.ldif.default; do
  if [ -f /opt/zextras/common/etc/openldap/${i} ]; then
    chown -f ${root_user}:${root_group} /opt/zextras/common/etc/openldap/${i}
    chmod 644 /opt/zextras/common/etc/openldap/${i}
  fi
done

##### Fix permissions for ldap and proxy #####

if [ -x /opt/zextras/common/sbin/nginx ]; then
  chown ${root_user}:${zextras_group} /opt/zextras/common/sbin/nginx
  chmod 750 /opt/zextras/common/sbin/nginx

  if [ -f /opt/zextras/log/nginx.access.log ]; then
    chown ${zextras_user}:${zextras_group} /opt/zextras/log/nginx.access.log
    chmod 644 /opt/zextras/log/nginx.access.log
  fi

  # changing permission will reset capabilities so set it again
  setcap CAP_NET_BIND_SERVICE=+ep /opt/zextras/common/sbin/nginx
fi

if [ -x /opt/zextras/common/libexec/slapd ]; then
  chown ${root_user}:${zextras_group} /opt/zextras/common/libexec/slapd
  chmod 750 /opt/zextras/common/libexec/slapd

  # changing permission will reset capabilities so set it again
  setcap CAP_NET_BIND_SERVICE=+ep /opt/zextras/common/libexec/slapd
fi

exit 0
