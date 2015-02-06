package Net::SSH::Any::Test::Backend::Remote;

use strict;
use warnings;

use Net::SSH::Any;
use Net::SSH::Any::Constants qw(SSHA_REMOTE_CMD_ERROR SSHA_BACKEND_ERROR);

sub start_and_check {
    my $tssh = shift;

    for my $uri (@{$tssh->{uris}}) {
        $tssh->_check_and_set_uri($uri) and return 1;
        for my $key_path (@{$tssh->{key_paths}}) {
            my $uri2 = Net::SSH::Any::URI->new($uri->uri);
            $uri2->set(password => ());
            $uri2->set(key_path => $key_path);
            $tssh->_check_and_set_uri($uri2) and return 1;
        }
        for my $password (@{$tssh->{passwords}}) {
            my $uri2 = Net::SSH::Any::URI->new($uri->uri);
            $uri2->set(password => $password);
            $uri2->set(key_path => ());
            $tssh->_check_and_set_uri($uri2) and return 1;
        }
    }
    $tssh->_set_error(SSHA_BACKEND_ERROR, "Open SSH server not found");
    ()
}

sub _check_and_set_uri {
    my ($tssh, $uri) = @_;
    $tssh->_log("Checking URI ".$uri->uri);
    my $ssh;
    for my $cmd (@{$tssh->{test_commands}}) {
        unless ($ssh) {
            $tssh->_log("Trying to connect to server at ".$uri->uri);
            $ssh = Net::SSH::Any->new($uri,
                                      timeout => $tssh->{timeout},
                                      backends => $tssh->{any_backends});
            if ($ssh->error) {
                $tssh->_log("Unable to establish SSH connection", $ssh->error, uri => $uri->as_string);
                return;
            }
        }
        my ($out, $err) = $ssh->capture2($cmd);
        if (my $error = $ssh->error) {
            $tssh->_log("Running command '$cmd' failed, rc: $?, error: $error");
            undef $ssh unless $error != SSHA_REMOTE_CMD_ERROR;
        }
        else {
            if (length $out) {
                $out =~ s/\n?$/\n/; $out =~ s/^/out: /mg;
            }
            if (length $err) {
                $err =~ s/\n?$/\n/; $err =~ s/^/err: /mg;
            }
            $tssh->_log("Running command '$cmd', rc: $?\n$out$err");
            return 1;
        }
    }
}

sub start { 1 }

1;
