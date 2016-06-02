#!/usr/bin/perl

use strict;
use warnings;

use Test::More;

use Net::SSH::Any::Test::Isolated;
use Net::SSH::Any;

$Net::SSH::Any::Test::Isolated::debug =-1;

my $tssh = Net::SSH::Any::Test::Isolated->new(logger => 'diag');
if (my $error = $tssh->error) {
    diag "Unable to find or start SSH service: $error";
}
else {
    my $ssh = Net::SSH::Any->new($tssh->uri);
    ok($ssh, "connects ok");

    my $out = $ssh->capture("uname -a");
    if ($? == 0) {
        diag "remote runs some Unix based operating system";
    }
    else {
        $out = $ssh->capture('cmd /c ver');
        if ($? == 0) {
            diag "remote system runs MS Windows";
        }
    }
}

done_testing();
