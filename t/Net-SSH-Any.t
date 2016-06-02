#!/usr/bin/perl

use strict;
use warnings;

use Test::More;

use Net::SSH::Any::Test::Isolated;
use Net::SSH::Any;
use Net::SSH::Any::Constants qw(SSHA_NO_BACKEND_ERROR
                                SSHA_REMOTE_CMD_ERROR);

#$Net::SSH::Any::Test::Isolated::debug =-1;

my %remote_cmd;

sub ssh_ok {
    my $ssh = shift;
    my $msg = join(': ', 'no ssh error', @_);
    if (my $error = $ssh->error) {
        return is($error, 0, $msg);
    }
    ok(1, $msg);
}

sub which {
    my ($ssh, $cmd) = @_;
    $remote_cmd{$cmd} //= do {
        my $out = $ssh->capture(which => $cmd);
        if ($ssh->error) {
            if ($ssh->error == SSHA_REMOTE_CMD_ERROR) {
                diag "remote command $cmd not found";
            }
            else {
                ssh_ok($ssh, "looking for $cmd");
            }
            undef;
        }
        else {
            chomp $out;
            diag "$cmd found at $out";
            $out;
        }
    };
}

my %detect_os_cmds = ( windows => ['cmd /c ver'],
                       unix    => ['uname -a'] );

my $tssh = Net::SSH::Any::Test::Isolated->new(logger => 'diag');
if (my $error = $tssh->error) {
    diag "Unable to find or start SSH service: $error";
}
else {
    for my $be (qw(Net_SSH2 Net_OpenSSH Ssh_Cmd)) {
        diag "Testing backend $be";

        my %opts = ( backend => $be,
                     timeout => 30,
                     strict_host_key_checking => 0,
                     batch_mode => 1,
                     backend_opts => { Net_OpenSSH => { strict_mode => 0 } } );

        my $ssh = Net::SSH::Any->new($tssh->uri, %opts);

        ok($ssh, "constructor returns an object");
        if (my $error = $ssh->error) {
            is ($error+0, SSHA_NO_BACKEND_ERROR+0, "no backend available")
                or diag "error: $error";
            next;
        }
        ok(1, "no constructor error");

        my $os;
    OUTER: for my $detect (qw(unix windows)) {
            for my $cmd (@{$detect_os_cmds{$detect}}) {
                my $out = $ssh->capture($cmd);
                if ($? == 0) {
                    $os = $detect;
                    chomp $out;
                    diag "remote operating system is $os ($out)";
                    last OUTER;
                }
            }
        }

        ok($os, "OS detected");

        chomp(my $rshell = $ssh->capture(echo => \\'$SHELL'));
        ssh_ok($ssh);
        diag "Remote shell is $rshell";
        my $rshell_is_csh = ($rshell =~ /\bt?csh$/);
        diag "Remote shell is " . ($rshell_is_csh ? "" : "not ") . "csh";

        my $cat = which($ssh, 'cat');

    }
}

done_testing();
