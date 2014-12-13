package Net::SSH::Any::Backend::_Cmd;

use strict;
use warnings;

use Carp;
our @CARP_NOT = qw(Net::SSH::Any);

use Net::SSH::Any::Util qw($debug _debug _first_defined _array_or_scalar_to_list);
use Net::SSH::Any::Constants qw(:error);

sub _backend_api_version { 1 }

sub _connect {
    my $any = shift;
    my %opts = map { $_ => $any->{$_} } qw(host port user password passphrase key_path timeout
                                           strict_host_key_checking known_host_path);
    if (my $extra = $any->{backend_opts}{$any->{backend}}) {
        @opts{keys %$extra} = values %$extra;
    }

    $any->_os_loaded or return; # ensure the OS module is loaded
    $any->_validate_connect_opts(%opts);
}

sub _system {
    my ($any, $opts, $cmd) = @_;
    my ($proc, @pipes) = $any->_os_run_cmd($opts, $cmd) or return;
    $any->_os_io3($proc, $opts->{timeout}, $opts->{stdin_data}, @pipes);
}

sub _capture {
    my ($any, $opts, $cmd) = @_;
    $opts->{stdout_pipe} = 1;
    my ($proc, @pipes) = $any->_os_run_cmd($opts, $cmd) or return;
    $any->_os_io3($proc, $opts->{timeout}, $opts->{stdin_data}, @pipes);
}

sub _capture2 {
    my ($any, $opts, $cmd) = @_;
    $opts->{stdout_pipe} = 1;
    $opts->{stderr_pipe} = 1;
    my ($proc, @pipes) = $any->_os_run_cmd($opts, $cmd) or return;
    $any->_os_io3($proc, $opts->{timeout}, $opts->{stdin_data}, @pipes);
}

sub _dpipe {
    my ($any, $opts, $cmd) = @_;
    $opts->{stdinout_dpipe} = 1;
    my (undef, $dpipe) = $any->_os_run_cmd($opts, $cmd) or return;
    $dpipe;
}

sub _sftp {
    my ($any, $opts) = @_;
    $opts->{subsystem} = 1;
    $opts->{stdin_pipe} = 1;
    $opts->{stdout_pipe} = 1;
    my ($proc, $in, $out) = $any->_os_run_cmd($opts, 'sftp') or return;
    my $pid = $any->_os_export_proc($proc) or return;
    Net::SFTP::Foreign->new(transport => [$in, $out, $pid], %$opts);
}

1;

