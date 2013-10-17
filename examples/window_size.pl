#!/usr/bin/perl

use strict;
use warnings;

my $host = shift @ARGV;
my $iface = 'eth0';

#my $size = 512 * 1024 * 1024;
my $size = 64 * 1024 * 1024;
my $dd_bs = 16 * 1024;
my $dd_count = int($size / $dd_bs);

my @delays = (0, map 2**$_, 1..9);
my @windows = (0.25, 0.5, 1, 2, 4, 8, 16);

use Time::HiRes qw(time);
use Net::SSH::Any;

my $ssh = Net::SSH::Any->new($host,
                             strict_host_key_checking => 0,
                             known_hosts_path => '/dev/null',
                             compress => 0);

for my $delay (@delays) {
    $ssh->system("tc qdisc add dev $iface root netem delay ${delay}ms");
    for my $window (@windows) {
        my $time0 = time;
        $ssh->system( { stdout_file => '/dev/null',
                        _window_size => $window * 1024 * 1024 },
                      "dd bs=$dd_bs count=$dd_count if=/dev/zero 2>/dev/null");
        my $time1 = time;
        my $dt = $time1 - $time0;
        my $speed = $size / $dt / 1024 / 1024; # MB/s
        printf "d: %dms, w: %.2fMB, t:%.1fs, s:%.2fMB/s\n", $delay, $window, $dt, $speed;
    }
    $ssh->system("tc qdisc del dev $iface root netem delay ${delay}ms");

}
