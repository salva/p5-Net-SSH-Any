#!/usr/bin/perl

use strict;
use warnings;
use feature 'say';

my $host = shift @ARGV;
my $iface = 'eth0';

#my $size = 512 * 1024 * 1024;
my $size = 128 * 1024 * 1024;
my $dd_bs = 16 * 1024;
my $dd_count = int($size / $dd_bs);

my @delays  = (0, map 2**$_, 4, 6, 7, 8, 9);
my @windows = (0.25, 0.5, 1, 2, 4, 8, 16);

#my @delays = (0, 20, 80);
#my @windows = (0.5, 2, 8);

use Time::HiRes qw(time);
use Net::SSH::Any;

my $ssh2 = Net::SSH::Any->new($host,
			      strict_host_key_checking => 0,
			      known_hosts_path => '/dev/null',
			      key_path => scalar(<~/.ssh/id_dsa>),
			      compress => 0,
			      backends => 'Net::SSH2');
$ssh2->error and die "unabel to connect using libssh2: " . $ssh2->error;

my $openssh = Net::SSH::Any->new($host,
			      strict_host_key_checking => 0,
			      known_hosts_path => '/dev/null',
			      key_path => scalar(<~/.ssh/id_dsa>),
			      compress => 0,
			      backends => 'Net::OpenSSH');
$openssh->error and die "unabel to connect using OpenSSH: " . $openssh->error;

my %summary;

$| = 1;

sub test {
    my ($ssh, $delay, $window) = @_;
    my %opts = (stdout_file => '/dev/null');
    my ($window_name);
    if ($window =~ /^[\d\.]+$/) {
	$opts{_window_size} = $window * 1024 * 1024;
	$window_name = "${window}MB";
    }
    else {
	$window_name = $window;
    }
    my $time0 = time;
    $ssh2->system(\%opts, "dd bs=$dd_bs count=$dd_count if=/dev/zero 2>/dev/null");
    my $time1 = time;
    my $dt = $time1 - $time0;
    my $speed = $size / $dt / 1024 / 1024; # MB/s
    printf "delay: %dms, window: %s, time: %.1fs, speed: %.2fMB/s\n", $delay, $window_name, $dt, $speed;
    $summary{"$window,$delay"} = $speed;
}

for my $delay (@delays) {
    $ssh2->system("tc qdisc del dev $iface root netem delay 0ms 2>/dev/null");
    $ssh2->system("tc qdisc add dev $iface root netem delay ${delay}ms");
    test($ssh2, $delay, $_) for @windows;
    test($openssh, $delay, 'OpenSSH');
    $ssh2->system("tc qdisc del dev $iface root netem delay ${delay}ms");
    say "";
}

END {
    say join(', ', 'windows', @windows, 'OpenSSH');
    for my $delay (@delays) {
	say join(', ', $delay, map $summary{"$_,$delay"}, @windows, 'OpenSSH');
    }
}
