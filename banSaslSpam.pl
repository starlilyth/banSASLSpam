#!/usr/bin/perl
use strict;
use warnings;

# More than this will trigger the banning
# 65,536 IPs in a /16, 65,536 /16s total.
my $threshold16 = 6;
# 255 IPs in a /24
my $threshold24 = 1;

my $flag = $ARGV[0];
my $notice = "no";
$notice = "yes" if (defined $flag && $flag eq "y");
print "Ban SASL spammers (auto: $notice)\n";
print " \033[0;32m".`date +"%H:%M - %m/%d"`."\033[0m";

my @bannedips = get_bans();
if (defined $flag && $flag eq "b") {
  print "Current ban list:\n";
  foreach my $bip (@bannedips) {
    print "$bip\n";
  }
  exit;
}

my $count = 0;
my @branges;
my @cranges;
my ($p1, $p2, $p3, $p4)=(0)x4;
my ($c1, $c2, $c3, $c4)=(0)x4;
my @ips = get_log_entries();
print "Getting ranges...\n";
my @sorted_ips = sort { $a cmp $b } @ips;
foreach my $ip (@sorted_ips) {
  my ($o1, $o2, $o3, $o4) = split(/\./, $ip);
  if ($o1 == $p1) { $c1++ } else { $c1 = 0 };
  if ($c1 > 0 && $o2 == $p2) { $c2++ }
  else {
    if ($c2 > $threshold16) {
      my $range = "$p1.$p2.0.0/16";
      my $matched = grep { /$range/ } @bannedips;
      if (!defined $matched || $matched == 0) {
        push(@branges, $range);
        $count++;
      }
    }
    $c2 = 0;
  };
  if ($c2 > 0 && $o3 == $p3) { $c3++ }
  else {
    if ($c3 > $threshold24) {
      my $range = "$p1.$p2.$p3.0/24";
      my $matched = grep { /$range/ } @bannedips;
      my $prange = "$p1.$p2.0.0/16";
      my $parent = grep { /$prange/ } @bannedips;
      if ((!defined $matched || $matched == 0) && (!defined $parent || $parent == 0)) {
        push(@cranges, $range);
        $count++;
      }
    }
    $c3 = 0;
  };
  ($p1, $p2, $p3, $p4) = ($o1, $o2, $o3, $o4);
}

my $display_count = "0";
$display_count = "\033[0;31m$count\033[0m" if ($count gt 0);
print " $display_count IP ranges found \n";
foreach my $banrange (@branges) { banit($banrange) }
foreach my $banrange (@cranges) { banit($banrange) }
print "Done.\n";

sub get_bans {
  my $banned_count = 0;
  my @bannedips;
  print "Getting banned list... \n";
  my @rawbanned = `/bin/firewall-cmd --list-all | grep 'port="587" protocol="tcp" drop' | sort -V`;
  foreach my $banline (@rawbanned) {
    if ($banline =~ /source address="(.*?)" /) {
      my $bannedip = $1;
      push @bannedips, ($bannedip);
      $banned_count++;
    }
  }
  print "\033[0;33m $banned_count\033[0m bans\n";
  return @bannedips;
}

sub get_log_entries {
  my @pfldata;
  print "Getting log entries... \n";
  @pfldata = `/sbin/pflogsumm /var/log/maillog /var/log/maillog-* --verbose`;
  my $logged_count = 0;
  my @ips;
  foreach my $line (@pfldata) {
    if ($line =~ /\[(\d+.\d+.\d+.\d+)\]: SASL (PLAIN|LOGIN) authentication failed:/) {
      push @ips, ($1);
      $logged_count++;
    }
    if ($line =~ /does not resolve to address (\d+.\d+.\d+.\d+)/) {
      push @ips, ($1);
      $logged_count++;
    }
  }
  print "\033[0;33m $logged_count\033[0m entries logged\n";
  return @ips;
}

sub banit {
  my @ranges = @_;
  my $banrange = $ranges[0];
  my $input;
  if (defined $flag && $flag eq "y") {
    $input = $flag
  } else {
    print " IPs found in range $banrange. Ban it? y/n ";
    $input = <>; chomp($input);
  }
  if ($input eq "y") {
    ban_range($banrange);
  }
}

sub ban_range {
  my @ranges = @_;
  my $banrange = $ranges[0];
  if (defined $banrange && $banrange =~ /(\d+).(\d+).\d+.0\/(16|24)/) {
    my $o1 = $1;
    my $o2 = $2;
    my $parent;
    if ($banrange =~ /\/24/) {
      my $prange = "$o1.$o2.0.0/16";
      $parent = grep { /^$prange/ } @bannedips;
    }
    if ($banrange =~ /\/16/) {
      my $crange = "$o1.$o2.\\d+.0/24";
      my @children = grep { /^$crange$/ } @bannedips;
      if (@children) {print "   Sub range of \033[0;33m$banrange\033[0m already banned...\n";}
      foreach my $child (@children) {
        print " - Unbanning $child from port 25...";
        `firewall-cmd --remove-rich-rule='rule family=ipv4 port port="25" protocol="tcp" source address=$child drop'`;
        `firewall-cmd --remove-rich-rule='rule family=ipv4 port port="25" protocol="tcp" source address=$child drop' --permanent`;
        print " and port 587.\n";
        `firewall-cmd --remove-rich-rule='rule family=ipv4 port port="587" protocol="tcp" source address=$child drop'`;
        `firewall-cmd --remove-rich-rule='rule family=ipv4 port port="587" protocol="tcp" source address=$child drop' --permanent`;
      }
    }
    if (defined $parent && $parent > 0) {
      print "   Parent of $banrange was banned, skipping\n";
    } else {
      print " + Banning $banrange from port 25...";
      `firewall-cmd --add-rich-rule='rule family=ipv4 port port="25" protocol="tcp" source address=$banrange drop'`;
      `firewall-cmd --add-rich-rule='rule family=ipv4 port port="25" protocol="tcp" source address=$banrange drop' --permanent`;
      print " and port 587.\n";
      `firewall-cmd --add-rich-rule='rule family=ipv4 port port="587" protocol="tcp" source address=$banrange drop'`;
      `firewall-cmd --add-rich-rule='rule family=ipv4 port port="587" protocol="tcp" source address=$banrange drop' --permanent`;
      push @bannedips, ($banrange);
    }
  } else {
    print "\033[0;33m Invalid range \033[0m\n";
  }
}