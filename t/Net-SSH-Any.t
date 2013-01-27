#!/usr/bin/perl

use strict;
use warnings;

use Test::More;

my $sshd = eval {
    require Test::SSH;
    Test::SSH->new(run_server => ($ENV{AUTHOR_TESTING} || $ENV{AUTOMATED_TESTING}));
};

if (!$sshd) {
    plan skip_all => 'Test::SSH is not installed or the module was not able to find a SSH server';
    exit(0);
}

plan tests => 2;
use_ok('Net::SSH::Any');
my $ssh = Net::SSH::Any->new($sshd->connection_params);
ok($ssh, "connects ok");

my $out = $ssh->capture("uname -a");
if ($? == 0) {
    diag "remote system runs unix";
}
else {
    $out = $ssh->capture('cmd /c ver');
    if ($? == 0) {
        diag "remote system runs windows";
    }
}



