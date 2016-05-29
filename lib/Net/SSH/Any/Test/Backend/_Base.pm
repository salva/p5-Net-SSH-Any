package Net::SSH::Any::Test::Backend::_Base;

use strict;
use warnings;

use Net::SSH::Any;
use Net::SSH::Any::Constants qw(SSHA_BACKEND_ERROR SSHA_REMOTE_CMD_ERROR);

our @CARP_NOT = qw(Net::SSH::Any::Test);

sub _validate_backend_opts { 1 }

my $dev_null = File::Spec->devnull;
sub _dev_null { $dev_null }

sub _check_and_set_uri {
    my ($tssh, $uri) = @_;
    $tssh->_log("Checking URI ".$uri->uri);
    my $ssh;
    for my $cmd (@{$tssh->{test_commands}}) {
        unless ($ssh) {
            $tssh->_log("Trying to connect to server at ".$uri->uri);
            $ssh = Net::SSH::Any->new($uri,
                                      batch_mode => 1,
                                      timeout => $tssh->{timeout},
                                      backends => $tssh->{any_backends},
                                      strict_host_key_checking => 0,
                                      known_hosts_path => $tssh->_dev_null);
            if ($ssh->error) {
                $tssh->_log("Unable to establish SSH connection", $ssh->error, uri => $uri->as_string);
                return;
            }
        }
        my ($out, $err) = $ssh->capture2($cmd);
        if (my $error = $ssh->error) {
            $tssh->_log("Running command '$cmd' failed, rc: $?, error: $error");
            undef $ssh unless $error == SSHA_REMOTE_CMD_ERROR;
        }
        else {
            if (length $out) {
                $out =~ s/\n?$/\n/; $out =~ s/^/out: /mg;
            }
            if (length $err) {
                $err =~ s/\n?$/\n/; $err =~ s/^/err: /mg;
            }
            $tssh->_log("Running command '$cmd', rc: $?\n$out$err");

            $tssh->{good_uri} = $uri;

            return 1;
        }
    }
}

sub _run_cmd {
    my ($tssh, $opts, $cmd, @args) = @_;
    $tssh->_log("Running cmd: $cmd @args");
    my $out_fn = $tssh->_log_fn($opts->{out_name} // $cmd);
    my $resolved_cmd = $tssh->_resolve_cmd($cmd);
    if (open my ($out_fh), '>>', $out_fn and
        open my ($in_fh), '<', $tssh->_dev_null) {
        if (my $proc = $tssh->_os_open4([$in_fh, $out_fh], [], undef, 1,
                                        $resolved_cmd => @args)) {
            $opts->{async} and return $proc;
            $tssh->_os_wait_proc($proc, $opts->{timeout}, $opts->{force_kill}) and return 1;
        }
        $tssh->_set_error(SSHA_BACKEND_ERROR, "Can't execute command $cmd: $!");
    }
    ()
}

sub _resolve_cmd {
    my ($tssh, $name) = @_;
    $tssh->_find_cmd($name);
}

1;