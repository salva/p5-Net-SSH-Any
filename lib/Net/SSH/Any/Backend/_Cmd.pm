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

    my $module = "Net::SSH::Any::Backend::_Cmd::OS::" .
        _first_defined(delete($opts{cmd_os_backend}),
                       ($^O =~ /^mswin/i ? 'MSWin' : 'POSIX'));

    $any->_load_module($module) or return;
    $any->{be_cmd_os} = $module->new or return;

    $any->_validate_connect_opts(%opts);
}

sub __cmd_os {
    my $any = shift;
    my $os = $any->{be_cmd_os};
    unless ($os) {
        $any->_or_set_error(SSHA_BACKEND_ERROR, "Internal error: _Cmd OS module not initialized");
        return;
    }
    $os;
}

sub __run_cmd {
    my $os = __cmd_os($_[0]) or return;
    $os->run_cmd(@_);
}

sub __export_proc {
    my ($any, $proc) = @_;
    my $os = __cmd_os($_[0]) or return;
    $os->export_proc(@_);
}

sub __io3 {
    my ($any, $proc, $timeout, $data, $in, $out, $err) = @_;
    my @data = grep { defined and length } _array_or_scalar_to_list $data;
    if (@data and not $in) {
        croak "remote input channel is not defined but data is available for sending"
    }
    my $os = __cmd_os($any) or return;
    $os->io3($any, $proc, $timeout, \@data, $in, $out, $err);
}

sub _system {
    my ($any, $opts, $cmd) = @_;
    my ($proc, @pipes) = __run_cmd($any, $opts, $cmd) or return;
    __io3($any, $proc, $opts->{timeout}, $opts->{stdin_data}, @pipes);
}

sub _capture {
    my ($any, $opts, $cmd) = @_;
    $opts->{stdout_pipe} = 1;
    my ($proc, @pipes) = __run_cmd($any, $opts, $cmd) or return;
    __io3($any, $proc, $opts->{timeout}, $opts->{stdin_data}, @pipes);
}

sub _capture2 {
    my ($any, $opts, $cmd) = @_;
    $opts->{stdout_pipe} = 1;
    $opts->{stderr_pipe} = 1;
    my ($proc, @pipes) = __run_cmd($any, $opts, $cmd) or return;
    __io3($any, $proc, $opts->{timeout}, $opts->{stdin_data}, @pipes);
}

sub _pipe {
    my ($any, $opts, $cmd) = @_;
    require Net::SSH::Any::Backend::_Cmd::Pipe;
    $opts->{stdinout_pipe} = 1;
    my ($proc, $pipe) = __run_cmd($any, $opts, $cmd) or return;
    $pipe;
}

sub _sftp {
    my ($any, $opts) = @_;
    $opts->{subsystem} = 1;
    $opts->{stdin_pipe} = 1;
    $opts->{stdout_pipe} = 1;
    my ($proc, $in, $out) = __run_cmd($any, $opts, 'sftp') or return;
    my $pid = __export_proc($any, $proc) or return;
    Net::SFTP::Foreign->new(transport => [$in, $out, $pid], %$opts);
}

1;

