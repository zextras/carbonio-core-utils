#!/usr/bin/perl

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

use strict;
use lib '/opt/zextras/common/lib/perl5';
use Zextras::Util::Common;

use File::Path;
use File::Copy qw/ cp mv /;
use File::Temp qw/ tempfile /;
#use File::Touch;
use Socket;
use Sys::Hostname;

my $id=getpwuid($<);

if ( $id ne "root" ) {
  print "Must be run as root!\n\n";
  exit 1;
}

my $platform=qx(grep -oP '(?<=^ID=).+' /etc/os-release);
chomp($platform);

my $zimbra_tmp_directory=getLocalConfig("zimbra_tmp_directory");

my ($uid,$gid) = (getpwnam('zextras'))[2,3];
if ( !-d $zimbra_tmp_directory ) {
  File::Path::mkpath("$zimbra_tmp_directory");
  chown $uid, $gid, $zimbra_tmp_directory;
}

my $logfile = "-/var/log/carbonio.log";
my $LOCALHOST ||= (gethostbyname(Sys::Hostname::hostname))[0];

my $junk;
my $TYPE;
my $LOGHOST=qx(su - zextras -c '/opt/zextras/bin/zmprov -m -l gacf zimbraLogHostname');

if ( $LOGHOST eq "" ) {
  $TYPE="local";
} else {
  ($junk,$LOGHOST) = split /: /, $LOGHOST, 2;
  chomp($LOGHOST);
  if ( lc($LOGHOST) eq lc($LOCALHOST) ) {
    $TYPE="local";
  } else {
    $TYPE="remote";
  }
}

my $rsyslog=0;

sub usage {
  print "\n";
  print "$0: set up syslog.conf for local or remote logging\n\n";
  print "Usage:\n";
  print "  $0\n\n";
  exit 1;
}

sub updateSyslogNG {

  my $syslogconf; 
  if ( -f "/etc/syslog-ng/syslog-ng.conf.in" ) {
    $syslogconf="/etc/syslog-ng/syslog-ng.conf.in";
  } elsif ( -f "/etc/syslog-ng/syslog-ng.conf" ) {
    $syslogconf="/etc/syslog-ng/syslog-ng.conf";
  } elsif ( -f "/etc/syslog-ng.conf" ) {
    $syslogconf="/etc/syslog-ng.conf";
  } else  {
    print "Unable to locate syslog-ng.conf\n";
    exit 1;
  }

  # Make a backup copy
  my $rc=cp($syslogconf,"$syslogconf.bak");
  if (!$rc) {
    print "Unable to make a backup of ".$syslogconf."\n";
    exit 1;
  }

  # create a safe temp file and make sure we have enough space to fill it
  my (undef, $tmpfile) = tempfile("syslog-ng.conf.XXXX", DIR=>"$zimbra_tmp_directory",  OPEN=>0);
  cp($syslogconf, $tmpfile);
  if ( -s $tmpfile ) {
    print "updateSyslogNG: Updating $syslogconf...";
  } else {
    print "updateSyslogNG: Unable to create temp file: $tmpfile\n";
    exit 1;
  }

  open (TMPFH, ">$tmpfile");
  open (SYSFH, "<$syslogconf");

  my $flocal=0;
  while (<SYSFH>) {
    if ($_ !~ /zimbra/ || $_ =~ /not filter\(zimbra/) {
      print TMPFH $_;
    }
  }
  close(SYSFH);
  my $zsrc = "zimbra_src";
  print TMPFH "source zimbra_src {  unix-stream(\"/dev/log\" keep-alive(yes) max-connections(128)); }; # zextras\n";
  print TMPFH "filter zimbra_local0 { facility(local0); }; # zextras\n";
  print TMPFH "filter zimbra_local1 { facility(local1); }; # zextras\n";
  print TMPFH "filter zimbra_auth { facility(auth); }; # zextras\n";
  print TMPFH "filter zimbra_mail { facility(mail); }; # zextras\n";
  if ( $TYPE eq "local" ) {
    print TMPFH "destination zimbra_mail { file(\"/var/log/carbonio.log\" owner(\"zextras\")); }; # zextras\n";
    print TMPFH "destination zimbra_local0 { file(\"/var/log/carbonio.log\" owner(\"zextras\")); }; # zextras\n";
    print TMPFH "destination zimbra_auth { file(\"/var/log/carbonio.log\" owner(\"zextras\")); }; # zextras\n";
  } else {
    my $remoteIp=inet_ntoa(scalar(gethostbyname($LOGHOST)));
    print TMPFH "destination zimbra_mail { udp(\"$remoteIp\" port(514) ); file(\"/var/log/carbonio.log\" owner(\"zextras\")); }; # zextras\n";
    print TMPFH "destination zimbra_local0 { udp(\"$remoteIp\" port(514) ); file(\"/var/log/carbonio.log\" owner(\"zextras\")); }; # zextras\n";
    print TMPFH "destination zimbra_auth { udp(\"$remoteIp\" port(514) ); file(\"/var/log/carbonio.log\" owner(\"zextras\")); }; # zextras\n";
  }
  print TMPFH "log { source($zsrc); filter(zimbra_mail); destination(zimbra_mail); }; # zextras\n";
  print TMPFH "log { source($zsrc); filter(zimbra_local0); destination(zimbra_local0); }; # zextras\n";
  print TMPFH "log { source($zsrc); filter(zimbra_local1); destination(zimbra_local1); }; # zextras\n";
  print TMPFH "log { source($zsrc); filter(zimbra_auth); destination(zimbra_auth); }; # zextras\n";

  close(TMPFH);

  # remove duplicate logging
  do {
    local $^I="~";
    local @ARGV="$tmpfile";
  
    while (<>) {
      s/(^destination mailinfo.*)/#$1/;
      s/(^log.*f_mailinfo)/#$1/;
      s/(^destination mailwarn.*)/#$1/;
      s/(^log.*f_mailwarn)/#$1/;
      s/(^destination mailerr.*)/#$1/;
      s/(^log.*f_mailerr)/#$1/;
      s|(^destination mail \{ file\("/var/log/mail"\); \};)|#$1|;
      s/(^log.*filter\(f_mail\); destination\(mail\); \};)/#$1/;
      print;
    }
  };
  mv($tmpfile, $syslogconf);
  if ( -f "/etc/logrotate.d/carbonio" ) {
    local $^I="~";
    local @ARGV="/etc/logrotate.d/carbonio";
    while (<>) {
      s/syslogd/syslog-ng/;
      s/USER/zextras/;
      s/GROUP/zextras/;

      print;
    }
  }
  if ( !-f "/var/log/carbonio.log") {
    open(my $tlog, ">/var/log/carbonio.log");
  }
  chown $uid,$gid,"/var/log/carbonio.log";
  if ( -f "/etc/logrotate.d/carbonio~" ){
    unlink("/etc/logrotate.d/carbonio~" );
  }
  print "done.\n"
}

sub updateSyslog {
  my $syslogconf="/etc/syslog.conf";
  if ( -f "/etc/rsyslog.conf" ) {
    $syslogconf="/etc/rsyslog.conf";
    $rsyslog=1 
  }

  # Make a backup copy
  my $rc=cp($syslogconf,"$syslogconf.bak");
  if (!$rc) {
    print "Unable to make a backup of ".$syslogconf."\n";
    exit 1;
  }

  # create a safe temp file and make sure we have enough space to fill it
  my (undef, $tmpfile) = tempfile("syslog.conf.XXXX", DIR=>"$zimbra_tmp_directory",  OPEN=>0);
  cp($syslogconf,$tmpfile);
  if ( -s $tmpfile ) {
    print "updateSyslog: Updating $syslogconf...";
  } else  {
    print "updateSyslog: Unable to create temp file: $tmpfile\n";
    exit 1;
  }

  open (TMPFH, ">$tmpfile");
  open (SYSFH, "<$syslogconf");
  # Remove existing entries that we may have added.
  while (<SYSFH>) {
    if ($_ !~ /^local0\.\*/ && $_ !~ /^local1\.\*/) {
      if ( $rsyslog == 1 && $_ =~ /^\tlocal0,local1.none;\\/ ) {
        next;
      }
      if ( $_ =~ /^auth\.\* / ) {
        next;
      }
      if ( $_ =~ /^mail.*($LOGHOST|zimbra)/ ) {
        next;
      }
      s/;local0.none//g;
      s/;local1.none//g;
      s/;auth.none//g;
      if ( $rsyslog == 0 ) {
        s/^\*\.info/\*\.info;local0.none;local1.none;auth.none/;
      }
      if ($rsyslog == 1 ) {
        s/;mail.none//g;
        if ($platform ne "ubuntu") {
          s/^\*\.info/\*\.info;local0.none;local1.none;mail.none;auth.none/;
        }
        s/^\*\.\*;auth,authpriv.none/\*\.\*;auth,authpriv.none;local0.none;local1.none;mail.none/;
        s/^\*\.=debug;\\/\*.=debug;\\\n\tlocal0,local1.none;\\/;
        s/^\*\.=info;\*\.=notice;\*\.=warn;\\/\*.=info;\*.=notice;\*.=warn;\\\n\tlocal0,local1.none;\\/;
      }
      print TMPFH $_;
    }
  }
  close(SYSFH);

  if ( $TYPE eq "remote" ) {
    print TMPFH "local0.*                @".$LOGHOST."\n";
    print TMPFH "local1.*                @".$LOGHOST."\n";
    print TMPFH "auth.*                  @".$LOGHOST."\n";
  }
  print TMPFH "local0.*                $logfile\n";
  print TMPFH "auth.*                  $logfile\n";

  if ($TYPE eq "remote" ) {
    print TMPFH "mail.*                @".$LOGHOST."\n";
  }
  print TMPFH "mail.*                $logfile\n";
  close (TMPFH);

  cp($tmpfile,$syslogconf);

  if ( !-f "/var/log/carbonio.log") {
    open(my $tlog, ">/var/log/carbonio.log");
  }
  chown $uid,$gid,"/var/log/carbonio.log";

  if ( -f "/etc/logrotate.d/carbonio" ) {
    local $^I="~";
    local @ARGV=("/etc/logrotate.d/carbonio");
    while (<>) {
      s/USER/zextras/;
      s/GROUP/zextras/;
      print;
    }
  }
  if ( -f "/etc/logrotate.d/carbonio~" ){
    unlink("/etc/logrotate.d/carbonio~" );
  }
  print "done.\n";
}

sub updateRsyslogd {
  my $conf;
  if (-f "/etc/rsyslog.d/50-default.conf") {
    $conf="/etc/rsyslog.d/50-default.conf";
  } else {
     print "Error: No default configuration found, exiting...\n";
     exit(1);
  }

  # create a safe temp file and make sure we have enough space to fill it
  my (undef, $tmpfile) = tempfile("syslog.conf.XXXX", DIR=>"$zimbra_tmp_directory",  OPEN=>0);
  cp($conf,$tmpfile);
  if ( -s $tmpfile ) {
    print "updateRsyslogd: Updating $conf...";
  } else  {
    print "updateRsyslogd: Unable to create temp file: $tmpfile\n";
    exit 1;
  }

  open (TMPFH, ">$tmpfile");
  open (SYSFH, "<$conf");
  # Remove existing entries that we may have added.
  while (<SYSFH>) {
    if ($_ !~ /^local0\.\*/ && $_ !~ /^local1\.\*/) {
      if ( $_ =~ /^\tlocal0,local1.none;\\/ ) {
        next;
      }
      if ( $_ =~ /^auth\.\* / ) {
        next;
      }
      s/;local0.none//g;
      s/;local1.none//g;
      s/;auth.none//g;
      s/;mail.none//g;
      s/^\*\.\*;auth,authpriv.none/\*\.\*;auth,authpriv.none;local0.none;local1.none;mail.none/;
      s/^\*\.=debug;\\/\*.=debug;\\\n\tlocal0,local1.none;\\/;
      s/^\*\.=info;\*\.=notice;\*\.=warn;\\/\*.=info;\*.=notice;\*.=warn;\\\n\tlocal0,local1.none;\\/;
      print TMPFH $_;
    }
  }
  close(SYSFH);
  close (TMPFH);
  cp($tmpfile,$conf);
  
  #Remove old files
  if (-f "/etc/rsyslog.d/60-zimbra.conf") {
    unlink("/etc/rsyslog.d/60-zimbra.conf");
  }
  if (-f "/etc/rsyslog.d/60-carbonio.conf") {
    unlink("/etc/rsyslog.d/60-carbonio.conf");
  }
  open(ZFH, ">/etc/rsyslog.d/60-carbonio.conf");
  if ( $TYPE eq "remote" ) {
    print ZFH "local0.*                @".$LOGHOST."\n";
    print ZFH "local1.*                @".$LOGHOST."\n";
    print ZFH "auth.*                  @".$LOGHOST."\n";
  }
  print ZFH "local0.*                $logfile\n";
  print ZFH "auth.*                  $logfile\n";

  if ($TYPE eq "remote" ) {
    print ZFH "mail.*                @".$LOGHOST."\n";
  }
  print ZFH "mail.*                $logfile\n";
  close(ZFH);


  if ( !-f "/var/log/carbonio.log") {
    open(my $tlog, ">/var/log/carbonio.log");
  }

  if ($platform eq "ubuntu") {
    my $junk;
    ($junk, $junk, $uid, $junk) = getpwnam("syslog");
    $gid = getgrnam("adm");
    chown $uid,$gid,"/var/log/carbonio.log";
  } else {
    chown $uid,$gid,"/var/log/carbonio.log";
  }

  if ( -f "/etc/logrotate.d/carbonio" ) {
    local $^I="~";
    local @ARGV=("/etc/logrotate.d/carbonio");
    while (<>) {
      if ($platform eq "ubuntu") {
        s/USER/syslog/;
        s/GROUP/adm/;
      	s/#su zextras zextras/su zextras zextras/;
      } else {
        s/USER/zextras/;
        s/GROUP/zextras/;
      }
      print;
    }
  }
  if ( -f "/etc/logrotate.d/carbonio~" ){
    unlink("/etc/logrotate.d/carbonio~" );
  }
  print "done.\n";
}

my $edited=0;

if ( -f "/etc/syslog-ng/syslog-ng.conf" ||
     -f "/etc/syslog-ng/syslog-ng.conf.in" ||
     -f "/etc/syslog-ng.conf" ) {
  &updateSyslogNG;
  $edited=1;
}

if ( (-f "/etc/rsyslog.conf" && -d "/etc/rsyslog.d") && $edited == 0 && ($platform eq "ubuntu" )) {
  &updateRsyslogd;
  $edited=1;
}

if ( (-f "/etc/syslog.conf" || -f "/etc/rsyslog.conf") && $edited == 0 ) {
  &updateSyslog;
  $edited=1;
}

if ( !$edited ) {
  print "ERROR: No syslog configuration edited\n";
  exit 1;
}

if ( -e "/usr/lib/systemd/system/rsyslog.service" ) {
  qx(/usr/bin/systemctl restart rsyslog.service >/dev/null 2>&1);
  exit 0;
} else {
  print "Unable to restart rsyslog.  Please do it manually.\n";
  exit 1;
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

