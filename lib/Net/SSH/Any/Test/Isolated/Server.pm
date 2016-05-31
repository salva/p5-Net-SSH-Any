package Net::SSH::Any::Test::Isolated::Server;

use strict;
use warnings;
use feature qw(say);

use Net::SSH::Any::Test;

sub run {
    $| = 1;
    say STDERR "slave saying ok!";
    say "ok!";
    while (<>) {
        chomp;
        say STDERR "slave recv: $_";
        say "ok!";
    }
}


1;
