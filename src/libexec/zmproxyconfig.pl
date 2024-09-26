#!/usr/bin/perl

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

# This script enables and disables proxy, and sets the default values for each case

use strict;
use lib "/opt/zextras/common/lib/perl5";
use Zimbra::Util::Common;
use Getopt::Std;
use IPC::Open3;
use FileHandle;
use Net::LDAP;

my $enabledHTTPProxy;
my $enabledMailProxy;
my ($i1, $i2, $i3, $i4, $p1, $p2, $p3, $p4, $w1, $w2, $w3, $w4, $n1, $n2);

my %packageServiceMap = (
  mailbox   => "carbonio-appserver",
  proxy => "carbonio-proxy",
);

my $ImapEnabled="7143:143:7993:993";
my $ImapDisabled="143:7143:993:7993";
my $PopEnabled="7110:110:7995:995";
my $PopDisabled="110:7110:995:7995";
my $WebEnabled="8080:80:8443:443";
my $WebDisabled="80:0:443:0";
my $AdminEnabled="7071:9071";
my $AdminDisabled="7071:9071";
my $storeMailMode="http";
my $proxyMailMode="http";
my $SSLToUp="REMAIN";

our %options = ();
our %loaded = ();

getopts('a:defhH:i:mop:rstwx:cCn:uU',\%options) or die "Unable to set options\n";

our $ZMPROV = "/opt/zextras/bin/zmprov -l 1>/dev/null";
our $platform = qx(grep -oP '(?<=^ID=).+' /etc/os-release);
chomp ($platform);

my $id = getpwuid($<);
chomp $id;
if ($id ne "zextras") {
    print STDERR "Error: must be run as zextras user\n";
    exit (1);
}

if ($options{h})  {
   usage();
   exit 1;
}

if ( !$options{H} ) {
    usage();
    exit 1;
}

if ( $options{d} + $options{e} > 1) {
    usage();
    exit 1;
}

if (!$options{f}) {
  if ( !$options{d} && !$options{e} ) {
      usage();
      exit 1;
  }

  if ( !$options{m} && !$options{w} ) {
      usage();
      exit 1;
  }
} else {
   if ( ($options{d} || $options{e}) && (!$options{w} && !$options{m})) {
      usage();
      exit 1;
   }
}

if (!$options{d} && !$options{e} && ($options{i} || $options{p} || $options{a})) {
    usage();
    exit 1;
}

if (($options{d} || $options{e}) && ($options{i} || $options{p}) && !$options{m}) {
    usage();
    exit 1;
}
if (($options{d} || $options{e}) && $options{a} && !$options{w}) {
    usage();
    exit 1;
}
if ($options{d} && $options{x} && !$options{w}) {
    usage();
    exit 1;
}
if ($options{e} && $options{x} && !$options{w}) {
    usage();
    exit 1;
}

if ($options{t} && !$options{d}) {
    usage();
    exit 1;
}

if (($options{c} || $options{C}) && !$options{w}) {
   print "Error: web proxy configure should be specified (-w) before admin console proxy is configured.\n";
   usage();
   exit 1;
}

if ($options{n} && (!$options{c} && !$options{C})) {
   print "Error: admin console proxy ports should be configured when admin console proxy is configured (-C/-c).\n";
   usage();
   exit 1;
}

if ($options{d} && $options{w} && $options{C}) {
   print "Error: when disable web proxy, you can't enable admin console proxy. Instead use \"-c -n n1:n2\" to specify the admin console ports after proxy is disabled.\n";
   usage();
   exit 1;
}

if (($options{u} || $options{U}) && !$options{e}) {
   print "Error: it's meaningful to specify \"SSL to upstream\" configure only when enable proxy (-e).\n";
   usage();
   exit 1;
}

if ($options{u} && $options{U}) {
   print "Error: -u and -U can't be set together.\n";
   usage();
   exit 1;
}

my $hostname = $options{H};
my $zimbra_server_hostname=getLocalConfig("zimbra_server_hostname");

#check SSL to Upstream setting
if (!$options{u} || !$options{U}) {
	my @res = qx(/opt/zextras/bin/zmprov -l gs $hostname zimbraReverseProxySSLToUpstreamEnabled\n);
    if ($res[1] =~ /zimbraReverseProxySSLToUpstreamEnabled:\ (.+)/) {
        $SSLToUp = $1;
	}
}

if ($options{u}) {
    $SSLToUp = "FALSE";
}

if ($options{U}) {
    $SSLToUp = "TRUE";
}

if ($SSLToUp eq "TRUE" && $options{e}) {
	if ($options{x} eq "http" ||
	    $options{x} eq "both" ||
	    $options{x} eq "mixed") {
	    print "Error: proxy mail mode $options{x} is invalid when SSL to upstream is enabled\n";
	    usage();
	    exit 1;
	}
}

if ($#ARGV != -1) {
    usage();
    exit 1;

}

if ((lc($hostname) ne lc($zimbra_server_hostname)) && !$options{r}) {
   print "Must use -r option to modify a remote host.\n";
   exit 1;
}

if (!isInstalled("carbonio-appserver") && !isInstalled("carbonio-proxy")) {
    print STDERR "Error: The store or proxy package must be installed.\n";
    exit {1};
}


open(ZMPROV, "|$ZMPROV");

if ($options{f}) {
  my $zimbraReverseProxyMailHostQuery =
        "\(\|\(zimbraMailDeliveryAddress=\${USER}\)\(zimbraMailAlias=\${USER}\)\(zimbraId=\${USER}\)\)";
  my $zimbraReverseProxyDomainNameQuery =
        '\(\&\(zimbraVirtualIPAddress=\${IPADDR}\)\(objectClass=zimbraDomain\)\)';
  my $zimbraReverseProxyPortQuery =
        '\(\&\(zimbraServiceHostname=\${MAILHOST}\)\(objectClass=zimbraServer\)\)';
  
  print ZMPROV "mcf zimbraReverseProxyDomainNameQuery $zimbraReverseProxyDomainNameQuery\n";
  print ZMPROV "mcf zimbraReverseProxyMailHostQuery $zimbraReverseProxyMailHostQuery\n";
  print ZMPROV "mcf zimbraReverseProxyPortQuery $zimbraReverseProxyPortQuery\n";
  print ZMPROV "mcf zimbraMemcachedBindPort 11211\n";
  print ZMPROV "mcf zimbraReverseProxyMailHostAttribute zimbraMailHost\n";
  print ZMPROV "mcf zimbraReverseProxyPop3PortAttribute zimbraPop3BindPort\n";
  print ZMPROV "mcf zimbraReverseProxyPop3SSLPortAttribute zimbraPop3SSLBindPort\n";
  print ZMPROV "mcf zimbraReverseProxyImapPortAttribute zimbraImapBindPort\n";
  print ZMPROV "mcf zimbraReverseProxyImapSSLPortAttribute zimbraImapSSLBindPort\n";
  print ZMPROV "mcf zimbraReverseProxyDomainNameAttribute zimbraDomainName\n";
  print ZMPROV "mcf zimbraReverseProxyAuthWaitInterval 10s\n";
  print ZMPROV "mcf zimbraReverseProxyIPLoginLimit 0\n";
  print ZMPROV "mcf zimbraReverseProxyIPLoginLimitTime 3600\n";
  print ZMPROV "mcf zimbraReverseProxyUserLoginLimit 0\n";
  print ZMPROV "mcf zimbraReverseProxyUserLoginLimitTime 3600\n";
}

if ($options{e}) {
  if ($options{i}) {
       $ImapEnabled = $options{i};
  }
  if ($options{p}) {
       $PopEnabled = $options{p};
  }
  if ($options{a}) {
       $WebEnabled = $options{a};
  }
  if ($options{n}) {
       $AdminEnabled = $options{n};
  }

  chomp ($ImapEnabled);
  chomp ($PopEnabled);
  chomp ($WebEnabled);
  chomp ($AdminEnabled);
  ($i1,$i2,$i3,$i4) = split /:/, $ImapEnabled, 4;
  ($p1,$p2,$p3,$p4) = split /:/, $PopEnabled, 4;
  ($w1,$w2,$w3,$w4) = split /:/, $WebEnabled, 4;
  ($n1,$n2) = split /:/, $AdminEnabled, 2;

  if (isInstalled("carbonio-appserver") && isInstalled("carbonio-proxy")) {
            if ($options{m}) {
               print ZMPROV "ms $hostname ".
                 "zimbraImapBindPort $i1 ".
                 "zimbraImapProxyBindPort $i2 ".
                 "zimbraImapSSLBindPort $i3 ".
                 "zimbraImapSSLProxyBindPort $i4 ".
                 "zimbraPop3BindPort $p1 ".
                 "zimbraPop3ProxyBindPort $p2 ".
                 "zimbraPop3SSLBindPort $p3 ".
                 "zimbraPop3SSLProxyBindPort $p4 ".
                 "zimbraImapCleartextLoginEnabled TRUE ".
                 "zimbraPop3CleartextLoginEnabled TRUE ".
                 "zimbraReverseProxyLookupTarget TRUE ".
                 "zimbraReverseProxyMailEnabled TRUE\n";
            }
            if ($options{w}) {
               ($proxyMailMode, $storeMailMode) = getMailMode($SSLToUp);
               chomp($proxyMailMode);
               print ZMPROV "ms $hostname ".
               "zimbraMailReferMode reverse-proxied ".
               "zimbraMailPort $w1 ".
               "zimbraMailProxyPort $w2 ".
               "zimbraMailSSLPort $w3 ".
               "zimbraMailSSLProxyPort $w4 ".
               "zimbraMailMode $storeMailMode ".
               "zimbraReverseProxyMailMode $proxyMailMode ".
               "zimbraReverseProxyLookupTarget TRUE ".
               "zimbraReverseProxyHttpEnabled TRUE\n";

               if ($options{C}) {
                   print ZMPROV "ms $hostname ".
                   "zimbraReverseProxyAdminEnabled TRUE ".
                   "zimbraAdminPort $n1 ".
                   "zimbraAdminProxyPort $n2\n";
               }
               if ($options{c}) {
                   print ZMPROV "ms $hostname ".
                   "zimbraReverseProxyAdminEnabled FALSE ".
                   "zimbraAdminPort $n1 ".
                   "zimbraAdminProxyPort $n2\n";
               }
            }
            if ($SSLToUp ne "REMAIN") {
                 print ZMPROV "ms $hostname zimbraReverseProxySSLToUpstreamEnabled $SSLToUp\n";
            }

            if (!isEnabled("carbonio-proxy")) {
                 print ZMPROV "ms $hostname ".
                      "+zimbraServiceEnabled proxy\n";
            }
  } else {
       if (isEnabled("carbonio-appserver") || (isInstalled("carbonio-appserver") && $options{o})) {
            if ($options{m}) {
               print ZMPROV "ms $hostname ".
                 "zimbraImapBindPort $i1 ".
                 "zimbraImapProxyBindPort $i2 ".
                 "zimbraImapSSLBindPort $i3 ".
                 "zimbraImapSSLProxyBindPort $i4 ".
                 "zimbraPop3BindPort $p1 ".
                 "zimbraPop3ProxyBindPort $p2 ".
                 "zimbraPop3SSLBindPort $p3 ".
                 "zimbraPop3SSLProxyBindPort $p4 ".
                 "zimbraImapCleartextLoginEnabled TRUE ".
                 "zimbraReverseProxyLookupTarget TRUE ".
                 "zimbraPop3CleartextLoginEnabled TRUE\n";
            }
            if ($options{w}) {
               ($proxyMailMode, $storeMailMode) = getMailMode($SSLToUp);
               print ZMPROV "ms $hostname ".
               "zimbraMailReferMode reverse-proxied ".
               "zimbraMailPort $w1 ".
               "zimbraMailProxyPort $w2 ".
               "zimbraMailSSLPort $w3 ".
               "zimbraMailSSLProxyPort $w4 ".
               "zimbraReverseProxyLookupTarget TRUE ".
               "zimbraMailMode $storeMailMode\n";

               if ($options{C}) {
                   print ZMPROV "ms $hostname ".
                   "zimbraReverseProxyAdminEnabled TRUE ".
                   "zimbraAdminPort $n1 ".
                   "zimbraAdminProxyPort $n2\n";
               }
               if ($options{c}) {
                   print ZMPROV "ms $hostname ".
                   "zimbraReverseProxyAdminEnabled FALSE ".
                   "zimbraAdminPort $n2 ".
                   "zimbraAdminProxyPort $n2\n";
               }
            }
            if ($SSLToUp ne "REMAIN") {
                print ZMPROV "ms $hostname zimbraReverseProxySSLToUpstreamEnabled $SSLToUp\n";
            }
       }
       if (isInstalled("carbonio-proxy")) {
            if ($options{m}) {
                print ZMPROV "ms $hostname ".
                 "zimbraImapBindPort $i1 ".
                 "zimbraImapProxyBindPort $i2 ".
                 "zimbraImapSSLBindPort $i3 ".
                 "zimbraImapSSLProxyBindPort $i4 ".
                 "zimbraPop3BindPort $p1 ".
                 "zimbraPop3ProxyBindPort $p2 ".
                 "zimbraPop3SSLBindPort $p3 ".
                 "zimbraPop3SSLProxyBindPort $p4 ".
                 "zimbraReverseProxyMailEnabled TRUE\n";
     	   }
            if ($options{w}) {
                ($proxyMailMode, $storeMailMode) = getMailMode($SSLToUp);
                chomp($proxyMailMode);
                print ZMPROV "ms $hostname ".
                 "zimbraMailPort $w1 ".
                 "zimbraMailProxyPort $w2 ".
                 "zimbraMailSSLPort $w3 ".
                 "zimbraMailSSLProxyPort $w4 ".
                 "zimbraReverseProxyMailMode $proxyMailMode ".
                 "zimbraReverseProxyHttpEnabled TRUE\n";

               if ($options{C}) {
                   print ZMPROV "ms $hostname ".
                   "zimbraReverseProxyAdminEnabled TRUE ".
                   "zimbraAdminPort $n1 ".
                   "zimbraAdminProxyPort $n2\n";
               }
               if ($options{c}) {
                   print ZMPROV "ms $hostname ".
                   "zimbraReverseProxyAdminEnabled FALSE ".
                   "zimbraAdminPort $n1 ".
                   "zimbraAdminProxyPort $n2\n";
               }
            }
            if ($SSLToUp ne "REMAIN") {
                 print ZMPROV "ms $hostname zimbraReverseProxySSLToUpstreamEnabled $SSLToUp\n";
            }

            if (!isEnabled("carbonio-proxy")) {
                 print ZMPROV "ms $hostname ".
                      "+zimbraServiceEnabled proxy\n";
            }
       }
  }
}

if ($options{d}) {
  if ($options{i}) {
       $ImapDisabled = $options{i};
  }
  if ($options{p}) {
       $PopDisabled = $options{p};
  }
  if ($options{a}) {
       $WebDisabled = $options{a};
  }
  if ($options{n}) {
       $AdminDisabled = $options{n};
  }
  chomp ($ImapDisabled);
  chomp ($PopDisabled);
  chomp ($WebDisabled);
  ($i1,$i2,$i3,$i4) = split /:/, $ImapDisabled, 4;
  ($p1,$p2,$p3,$p4) = split /:/, $PopDisabled, 4;
  ($w1,$w2,$w3,$w4) = split /:/, $WebDisabled, 4;
  ($n1,$n2) = split /:/, $AdminDisabled, 2;
  if (isInstalled("carbonio-appserver") && isInstalled("carbonio-proxy")) {
       if ($options{m}) {
          print ZMPROV "ms $hostname ".
            "zimbraImapBindPort $i1 ".
            "zimbraImapProxyBindPort $i2 ".
            "zimbraImapSSLBindPort $i3 ".
            "zimbraImapSSLProxyBindPort $i4 ".
            "zimbraPop3BindPort $p1 ".
            "zimbraPop3ProxyBindPort $p2 ".
            "zimbraPop3SSLBindPort $p3 ".
            "zimbraPop3SSLProxyBindPort $p4 ".
            "zimbraReverseProxyMailEnabled FALSE\n";
          if ($options{s}) {
            print ZMPROV "ms $hostname ".
              "zimbraImapCleartextLoginEnabled FALSE ".
              "zimbraPop3CleartextLoginEnabled FALSE\n";
          }
       }
       if ($options{w}) {
            if ($options{x}) {
              $storeMailMode=$options{x};
            }
            chomp ($storeMailMode);
            print ZMPROV "ms $hostname ".
            "zimbraMailReferMode wronghost ".
            "zimbraMailPort $w1 ".
            "zimbraMailProxyPort $w2 ".
            "zimbraMailSSLPort $w3 ".
            "zimbraMailSSLProxyPort $w4 ".
            "zimbraMailMode $storeMailMode ".
            "zimbraReverseProxyMailMode $storeMailMode ".
            "zimbraReverseProxyHttpEnabled FALSE\n";

            #once web proxy is disabled, admin console proxy will be disabled for sure
            print ZMPROV "ms $hostname ".
                "zimbraReverseProxyAdminEnabled FALSE ".
                "zimbraAdminPort $n1 ".
                "zimbraAdminProxyPort $n2\n";
       }
       $enabledHTTPProxy = getLdapServerValue("zimbraReverseProxyHttpEnabled");
       $enabledMailProxy = getLdapServerValue("zimbraReverseProxyMailEnabled");
       if ($enabledHTTPProxy eq "FALSE" && $enabledMailProxy eq "FALSE" && isEnabled("carbonio-proxy")) {
            print ZMPROV "ms $hostname ".
               "-zimbraServiceEnabled proxy\n";
       }
       if ($enabledHTTPProxy eq "FALSE" && $enabledMailProxy eq "FALSE") {
            print ZMPROV "ms $hostname ".
               "zimbraReverseProxyLookupTarget FALSE\n";
       }
  } else {
       if (isEnabled("carbonio-appserver") || (isInstalled("carbonio-appserver") && $options{o})) {
            if ($options{m}) {
               print ZMPROV "ms $hostname ".
                 "zimbraImapBindPort $i1 ".
                 "zimbraImapProxyBindPort $i2 ".
                 "zimbraImapSSLBindPort $i3 ".
                 "zimbraImapSSLProxyBindPort $i4 ".
                 "zimbraPop3BindPort $p1 ".
                 "zimbraPop3ProxyBindPort $p2 ".
                 "zimbraPop3SSLBindPort $p3 ".
                 "zimbraPop3SSLProxyBindPort $p4\n";
               if ($options{s}) {
                 print ZMPROV "ms $hostname ".
                   "zimbraImapCleartextLoginEnabled FALSE ".
                   "zimbraPop3CleartextLoginEnabled FALSE\n";
               }
            }
            if ($options{w}) {
     		  if ($options{x}) {
     		       $storeMailMode=$options{x};
     		  }
     		  chomp ($storeMailMode);
                  print ZMPROV "ms $hostname ".
                      "zimbraMailReferMode wronghost ".
                      "zimbraMailPort $w1 ".
                      "zimbraMailProxyPort $w2 ".
                      "zimbraMailSSLPort $w3 ".
                      "zimbraMailSSLProxyPort $w4 ".
                      "zimbraMailMode $storeMailMode\n";

                  #once web proxy is disabled, admin console proxy will be disabled for sure
                  print ZMPROV "ms $hostname ".
                  "zimbraReverseProxyAdminEnabled FALSE ".
                  "zimbraAdminPort $n1 ".
                  "zimbraAdminProxyPort $n2\n";
           }
           if ($options{t}) {
                print ZMPROV "ms $hostname ".
               "zimbraReverseProxyLookupTarget FALSE\n";
           }
       }
       if (isInstalled("carbonio-proxy")) {
            if ($options{m}) {
                 print ZMPROV "ms $hostname ".
                 "zimbraImapBindPort $i1 ".
                 "zimbraImapProxyBindPort $i2 ".
                 "zimbraImapSSLBindPort $i3 ".
                 "zimbraImapSSLProxyBindPort $i4 ".
                 "zimbraPop3BindPort $p1 ".
                 "zimbraPop3ProxyBindPort $p2 ".
                 "zimbraPop3SSLBindPort $p3 ".
                 "zimbraPop3SSLProxyBindPort $p4 ".
                 "zimbraReverseProxyMailEnabled FALSE\n";
     	   }
     	   if ($options{w}) {
                 if ($options{x}) {
                   $proxyMailMode=$options{x};
                 }
                 chomp($proxyMailMode);
                 print ZMPROV "ms $hostname ".
                 "zimbraMailPort $w1 ".
                 "zimbraMailProxyPort $w2 ".
                 "zimbraMailSSLPort $w3 ".
                 "zimbraMailSSLProxyPort $w4 ".
                 "zimbraReverseProxyMailMode $proxyMailMode ".
                 "zimbraReverseProxyHttpEnabled FALSE\n";

                 #once web proxy is disabled, admin console proxy will be disabled for sure
                 print ZMPROV "ms $hostname ".
                   "zimbraReverseProxyAdminEnabled FALSE ".
                   "zimbraAdminPort $n1 ".
                   "zimbraAdminProxyPort $n2\n";
            }
            $enabledHTTPProxy = getLdapServerValue("zimbraReverseProxyHttpEnabled");
            $enabledMailProxy = getLdapServerValue("zimbraReverseProxyMailEnabled");
            if ($enabledHTTPProxy eq "FALSE" && $enabledMailProxy eq "FALSE" && isEnabled("carbonio-proxy")) {
                 print ZMPROV "ms $hostname ".
                    "-zimbraServiceEnabled proxy\n";
            }
       }
  }
}

print ZMPROV "exit\n";
close ZMPROV;
exit ($? >> 8);

sub usage() {
  print "Usage: $0 [-h] [-o] [-m] [-w] [-d [-r] [-s] [-a w1:w2:w3:w4] [-c [-n n1:n2]] [-i p1:p2:p3:p4] [-p p1:p2:p3:p4] [-x mailmode]] [-e [-a w1:w2:w3:w4] [[-c|-C] [-n n1:n2]] [-i p1:p2:p3:p4] [-p p1:p2:p3:p4] [-u|-U] [-x mailmode]] [-f] -H hostname\n";
  print "\t-h: display this help message\n";
  print "\t-H: Hostname of server on which enable/disable proxy functionality.\n";
  print "\t-a: Colon separated list of Web ports to use. Format: HTTP-STORE:HTTP-PROXY:HTTPS-STORE:HTTPS-PROXY (Ex: 8080:80:8443:443)\n";
  print "\t-d: disable proxy\n";
  print "\t-e: enable proxy\n";
  print "\t-f: Full reset on memcached port and search queries and POP/IMAP throttling.\n";
  print "\t-i: Colon separated list of IMAP ports to use. Format: IMAP-STORE:IMAP-PROXY:IMAPS-STORE:IMAPS-PROXY (Ex: 7143:143:7993:993)\n";
  print "\t-m: Toggle mail proxy portions\n";
  print "\t-o: Override enabled checks\n";
  print "\t-p: Colon separated list of POP ports to use. Format: POP-STORE:POP-PROXY:POPS-STORE:POPS-PROXY (Ex: 7110:110:7995:995)\n";
  print "\t-r: Run against a remote host.  Note that this requires the server to be properly configured in the LDAP master.\n";
  print "\t-s: Set cleartext to FALSE (secure mode) on disable\n";
  print "\t-t: Disable reverse proxy lookup target for store server.  Only valid with -d.  Be sure that you intend for all proxy function for the server to be disabled\n";
  print "\t-w: Toggle Web proxy portions\n";
  print "\t-c: Disable Admin Console proxy portions.\n";
  print "\t-C: Enable Admin Console proxy portions.\n";
  print "\t-n: Colon separated list of Admin Console ports to use. Format: ADMIN-CONSOLE-STORE:ADMIN-CONSOLE-PROXY (Ex: 7071:9071)\n";
  print "\t-x: the proxy mail mode when enable proxy, or the store mail mode when disable proxy (Both default: http).\n";
  print "\t-u: disable SSL connection from proxy to mail store.\n";
  print "\t-U: enable SSL connection from proxy to mail store.\n";
  print "hostname is the value of the zimbra_server_hostname LC key for the server being modified.\n";
  print "Required options are -f by itself, or -f with -d or -e.\n";
  print "Note that -d or -e require one or both of -m and -w.\n";
  print "Note that -i or -p require -m.\n";
  print "Note that -a requires -w.\n";
  print "Note that -c/-C requires -w, and -n requires -c/-C. When disabling web proxy, admin console proxy will be automatically disabled.\n";
  print "Note that -u or -U are only available when proxy is enabled by -e.\n";
  print "Note that -x requires -w and -d for store.\n";
  print "Note that -x requires -w for proxy.\n";
  print "Note that no matter what mail mode is set by -x and no matter proxy is enabled or disabled, admin console's mode is always https.\n";
  print "The following are the defaults for -a, -i, -p, and -x if they are not supplied as options.\n";
  print "-a default on enable: 8080:80:8443:443\n";
  print "-a default on disable: 80:0:443:0\n";
  print "-i default on enable: 7143:143:7993:993\n";
  print "-i default on disable: 143:7143:993:7993\n";
  print "-p default on enable: 7110:110:7995:995\n";
  print "-p default on disable: 110:7110:995:7995\n";
  print "-n default on enable: 7071:9071\n";
  print "-n default on disable: 7071:9071\n";
  print "-x default on store disable: http\n";
  print "-x default on proxy enable/disable: http, but -x default on proxy enable when upstream ssl connection is enabled: https\n";
  print "\n\n";
  exit 1;
}

sub getLdapServerValue {
  my $attrib = shift;
  my ($val,$err);
  my ($rfh,$wfh,$efh,$cmd,$rc);
  $rfh = new FileHandle;
  $wfh = new FileHandle;
  $efh = new FileHandle;
  $cmd = "$ZMPROV gs $hostname $attrib";
  my $pid = open3($wfh,$rfh,$efh, $cmd);
  unless(defined($pid)) {
    return undef;
  }
  close $wfh;
  chomp($val = (split(/\s+/, <$rfh>))[-1]);
  chomp($err = join "", <$efh>);
  waitpid($pid,0);
  if ($? == -1) {
    # failed to execute
    return undef;
  } elsif ($? & 127) {
    # died with signal
    return undef;
  } else {
    $rc = $? >> 8;
    return undef if ($rc != 0);
  }

  return $val;
}

sub checkPackage {
    my $key = shift;    
    my $pkg = shift;
    my $found = 0;
    my $size = 0;
    my @list;
    my $entry;
    my $mesg;
    my $ldapurl = getLocalConfig("ldap_url");
    my $zdn = getLocalConfig("zimbra_ldap_userdn");
    my $zps = getLocalConfig("zimbra_ldap_password");
    my $ldap_starttls_supported = getLocalConfig("ldap_starttls_supported");

    my $replica_ref=[ split(" ", $ldapurl) ];
    my $ldap = Net::LDAP->new( $replica_ref ) or die "Error connecting to LDAP server: $ldapurl";

    if ($ldapurl !~ /^ldaps/i) {
        if ($ldap_starttls_supported) {
            $mesg = $ldap->start_tls(verify => 'none', capath => "/opt/zextras/conf/ca",) or die "start_tls: $@";
            $mesg->code && die "TLS: " . $mesg->error . "\n";
        }
    }

    $mesg = $ldap->bind("$zdn", password=>"$zps");
    $mesg->code && die "Bind: ". $mesg->error . "\n";
    
    $mesg = $ldap->search(
        base=>"",
        filter=>"(&(objectClass=zimbraServer)(cn=$hostname))",
        scope=>"sub",
        attrs => [$key],
        );

    $size = $mesg->count;
    if ($size == 0) {
        print "Error: No services found in $key on $hostname\n";
        $ldap->unbind;
        exit 1;
    } 

    foreach $entry ($mesg->entries) {
        @list = $entry->get_value($key);
        foreach(@list) {
            if ($packageServiceMap{$_} eq $pkg) {
                $found = 1;
            }
        }
    }
    
    $ldap->unbind;
    return $found;
}

sub isEnabled {
	my $pkg = shift;
	return checkPackage("zimbraServiceEnabled", $pkg);
}

sub isInstalled {
    my $pkg = shift;
    my $pkgQuery;
    my $good = 0;
    
    if ($options{r}) {      
        return checkPackage("zimbraServiceInstalled", $pkg);
    } else {               
      if ($platform =~ /ubuntu/) {
        $pkgQuery = "dpkg -s $pkg";
      } else {
        $pkgQuery = "rpm -q $pkg";
      }
    
      my $rc = 0xffff & system ("$pkgQuery > /dev/null 2>&1");
      $rc >>= 8;
      if (($platform =~ /ubuntu/) && $rc == 0 ) {
        $good = 1;
        $pkgQuery = "dpkg -s $pkg | egrep '^Status: ' | grep 'not-installed'";
        $rc = 0xffff & system ("$pkgQuery > /dev/null 2>&1");
        $rc >>= 8;
        return ($rc == $good);
      } else {
        return ($rc == $good);
      }
    }
}

sub getLocalConfig {
  my $key = shift;

  return $main::loaded{lc}{$key}
    if (exists $main::loaded{lc}{$key});

  my $val = qx(/opt/zextras/bin/zmlocalconfig -x -s -m nokey ${key} 2> /dev/null);
  chomp $val;
  $main::loaded{lc}{$key} = $val;
  return $val;
}

# return the proxy mail mode and store mail mode because when SSLToUp is enabled,
# the proxy mail mode can't be set to http, both and mixed, which allows "http".
# Besides, the store mail mode depends on the original mail mode and current SSLToUp
# settings
sub getMailMode {

    my $sslToUpEnabled = shift;
    my @res = qx(/opt/zextras/bin/zmprov -l gs $hostname zimbraMailMode\n);
    my $mailMode = "http";
    my $proxyMailMode = "http";

    if ($res[1] =~ /zimbraMailMode:\ (.+)/) {
        $mailMode = $1; #original store mail mode
    }

    if ($sslToUpEnabled eq "TRUE") {
        if ($mailMode eq "http" || $mailMode eq "both") {
            $mailMode = "both";
        } else {
            $mailMode = "https";
        }

        if ($options{x}) {
            $proxyMailMode = $options{x};
        } else {
            #if user doesn't specify proxy mail mode and SSLToUp is enabled, default use "https"
            $proxyMailMode = "https";
        }
    } else {
        $mailMode = "http";
        if ($options{x}) {
	        $proxyMailMode = $options{x};
        }
    }

    return ($proxyMailMode, $mailMode);
}
