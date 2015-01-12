package Net::SSH::Any::Backend::_Cmd;

use strict;
use warnings;

use Carp;
our @CARP_NOT = qw(Net::SSH::Any);

use Net::SSH::Any::Util qw($debug _debug _first_defined _array_or_scalar_to_list);
use Net::SSH::Any::Constants qw(:error);

sub _backend_api_version { 2 }

sub _validate_backend_opts {
    my $any = shift;
    $any->_os_loaded or return; # ensure the OS module is loaded
    1;
}

sub _connect { 1 }

sub _check_connection { 1 }

sub _export_proc {
    my ($any, $proc) = @_;
    $proc->{pid}
}

sub _find_cmd_by_friend {
    my ($any, $name, $friend) = @_;
    if (defined $friend) {
        require File::Spec;
        my ($drive, $dir) = File::Spec->splitpath($friend);
        my $cmd = File::Spec->join($drive, $dir, $name);
        return $any->_os_validate_cmd($cmd);
    }
    ()
}

sub _find_cmd {
    my ($any, $name, $friend, $app, $default) = @_;
    my $safe_name = $name;
    $safe_name =~ s/\W/_/g;
    return ( $any->{local_cmd}{$safe_name}             //
             $any->_find_cmd_by_friend($name, $friend) //
             $any->_find_helper_cmd($name)             //
             $any->_os_find_cmd_by_app($name, $app)    //
             $any->_os_validate_cmd($default)          //
             $name );
}

sub _find_helper_cmd {
    my ($any, $name) = @_;
    $debug and $debug & 1024 and _debug "looking for helper $name";
    my $module = my $last = $any->{backend_module} // return;
    $last =~ s/.*::// or return;
    $module =~ s{::}{/}g;
    $debug and $debug & 1024 and _debug "module as \$INC key is ", $module, ".pm";
    my $file_pm = $INC{"$module.pm"} // return;
    my ($drive, $dir) = File::Spec->splitpath(File::Spec->rel2abs($file_pm));
    my $path = File::Spec->join($drive, $dir, $last, 'Helpers', $name);
    $any->_os_validate_cmd($path);
}

my @stream_names = qw(stdin stdout stderr);
sub _run_cmd {
    my ($any, $opts, $cmd) = @_;
    my (@fhs, @pipes);

    $any->_check_connection or return;

    my $data = $opts->{stdin_data};
    $opts->{stdin_pipe} = 1 if defined $data;

    my $dpipe = delete $opts->{stdinout_dpipe};
    if ($dpipe) {
        if ($any->_os_has_working_socketpair) {
            ($fhs[0], $pipes[0]) = $any->_os_socketpair($fhs[0], $pipes[0]) or return;
            $fhs[1] = $fhs[0];
            $pipes[1] = undef;
        }
        else {
            $opts->{stdin_pipe} = 1;
            $opts->{stdout_pipe} = 1;
        }
    }

    for my $stream (@stream_names[@fhs .. 2]) {
        $debug and $debug & 1024 and _debug "seting up stream $stream";
        my ($fh, $pipe);
        if (delete $opts->{"${stream}_pipe"}) {
            ($pipe, $fh) = $any->_os_pipe or return;
            ($pipe, $fh) = ($fh, $pipe) if $stream eq 'stdin';
        }
        else {
            $fh = delete $opts->{"${stream}_fh"};
            unless ($fh) {
                my $file = (delete($opts->{"${stream}_discard"})
                            ? File::Spec->devnull
                            : delete $opts->{"${stream}_file"} );
                if (not defined $file and $stream eq 'stdin') {
                    # stdin is redirected from /dev/null by default
                    $file = File::Spec->devnull;
                }
                if (defined $file) {
                    my $dir = ($stream eq 'stdin' ? '<' : '>');
                    $fh = $any->_open_file($dir, $file) or return;
                }
            }
        }
        push @fhs, $fh;
        push @pipes, $pipe;
    }

    $any->_os_set_file_inherit_flag($_, 0)
        for grep defined, @pipes;

    my $stderr_to_stdout = (defined $fhs[2] ? 0 : delete $opts->{stderr_to_stdout});

    my @too_many = grep { /^std(?:in|out|err)_/ and
                          $_ ne 'stdin_data'    and
                          defined $opts->{$_} } keys %$opts;
    @too_many and croak "unsupported options or bad combination ('".join("', '", @too_many)."')";

    my @cmd = _array_or_scalar_to_list $cmd;
    unless ($opts->{_local}) {
        # FIXME: this is quite ugly, the make_cmd call should probably
        # be done outside this method. Actually, this method should
        # probably go into the OS module or in Any.
        @cmd = $any->_make_cmd($opts, @cmd) or return;
    };

    $debug and $debug & 1024 and _debug("launching cmd: '", join("', '", @cmd), "'");
    my $pty = ($any->{be_interactive_login} ? $any->_os_pty($any) : undef);
    my $proc = $any->_os_open4(\@fhs, \@pipes, $pty, $stderr_to_stdout, @cmd) or return;

    $debug and $debug & 1024 and _debug("pid: $proc->{pid}");

    if ($pty) {
        $any->_os_interactive_login($pty, $proc) or return undef;
        $any->{be_pty} = $pty;
        $pty->close_slave;
    }

    if ($dpipe) {
        $pipes[0] = $any->_os_make_dpipe($proc, @pipes[0, 1]) or return;
        $pipes[1] = undef;
        $debug and $debug & 1024 and _debug "fh upgraded to dpipe $pipes[0]";
    }

    return ($proc, @pipes);
}

sub _remap_child_error { 1 }

sub _io3 {
    my ($any, $opts, $proc, @pipes) = @_;
    my @r = $any->_os_io3($proc, $opts->{timeout}, $opts->{stdin_data}, @pipes);
    $any->_remap_child_error($proc);
    $? = $proc->{rc};
    @r;
}

sub _system {
    my ($any, $opts, $cmd) = @_;
    my ($proc, @pipes) = $any->_run_cmd($opts, $cmd) or return;
    $any->_io3($opts, $proc, @pipes);
}

sub _capture {
    my ($any, $opts, $cmd) = @_;
    $opts->{stdout_pipe} = 1;
    my ($proc, @pipes) = $any->_run_cmd($opts, $cmd) or return;
    $any->_io3($opts, $proc, @pipes);
}

sub _local_capture {
    # This method, or a better version, should go into Any
    my ($any, @cmd) = @_;
    my ($proc, @pipes) = $any->_run_cmd({ stdout_pipe => 1, stderr_to_stdout => 1, _local => 1 },
                                        \@cmd);
    my ($out) = $any->_io3({}, $proc, @pipes);
    $out // '';
}

sub _capture2 {
    my ($any, $opts, $cmd) = @_;
    $opts->{stdout_pipe} = 1;
    $opts->{stderr_pipe} = 1;
    my ($proc, @pipes) = $any->_run_cmd($opts, $cmd) or return;
    $any->_io3($opts, $proc, @pipes);
}

sub _dpipe {
    my ($any, $opts, $cmd) = @_;
    $opts->{stdinout_dpipe} = 1;
    my (undef, $dpipe) = $any->_run_cmd($opts, $cmd) or return;
    $dpipe;
}

sub _sftp {
    my ($any, $opts) = @_;
    $opts->{subsystem} = 1;
    $opts->{stdin_pipe} = 1;
    $opts->{stdout_pipe} = 1;
    my ($proc, $in, $out) = $any->_run_cmd($opts, 'sftp') or return;
    my $pid = $any->_export_proc($proc) or return;
    Net::SFTP::Foreign->new(transport => [$in, $out, $pid], %$opts);
}

1;
