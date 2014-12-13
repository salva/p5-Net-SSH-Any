package Net::SSH::Any::OS::MSWin;

use strict;
use warnings;

use Carp;
use Socket;
use Errno;
use Net::SSH::Any::Util qw($debug _debug _debug_hexdump _first_defined _array_or_scalar_to_list);
use Net::SSH::Any::Constants qw(:error);
use Time::HiRes qw(sleep);

require Net::SSH::Any::OS::_Base;
our @ISA = qw(Net::SSH::Any::OS::_Base);

# sub socketpair {
#     my ($os, $any) = @_;
#     my ($a, $b);
#     unless (CORE::socketpair($a, $b, AF_UNIX, SOCK_STREAM, PF_UNSPEC)) {
#         $any->_set_error(SSHA_LOCAL_IO_ERROR, "socketpair failed: $!");
#         return;
#     }
#     ($a, $b);
# }

sub pipe {
    my $any = shift;
    my ($r, $w);
    unless (CORE::pipe $r, $w) {
        $any->_set_error(SSHA_LOCAL_IO_ERROR, "Unable to create pipe: $!");
        return
    }
    ($r, $w);
}

sub make_dpipe {
    my ($any, $proc, $in, $out) = @_;
    require Net::SSH::Any::OS::MSWin::DPipe;
    Net::SSH::Any::OS::MSWin::DPipe->_upgrade_fh_to_dpipe($out, $any, $proc, $in);
}

my $win32_set_named_pipe_handle_state;
my $win32_get_osfhandle;
my $win32_set_handle_information;
my $win32_handle_flag_inherit = 0x1;
my $win32_pipe_nowait = 0x1;

sub __wrap_win32_functions {
    unless (defined $win32_set_named_pipe_handle_state) {
        require Config;
        require Win32::API;
        $Config::Config{libperl} =~ /libperl(\d+)/
            or croak "unable to infer Perl DLL version";
        my $perl_dll = "perl$1.dll";
        $debug and $debug & 1024 and _debug "Perl DLL name is $perl_dll";
        $win32_get_osfhandle = Win32::API::More->new($perl_dll, <<FSIGN)
long WINAPIV win32_get_osfhandle(int fd);
FSIGN
            or croak "unable to wrap $perl_dll win32_get_osfhandle function";

        $win32_set_named_pipe_handle_state = Win32::API::More->new("kernel32.dll", <<FSIGN)
BOOL SetNamedPipeHandleState(HANDLE hNamedPipe,
                             LPDWORD lpMode,
                             int ignore1,
                             int ignore2)
FSIGN
            or croak "unable to wrap kernel32.dll SetNamedPipeHandleState function";
        $win32_set_handle_information = Win32::API::More->new("kernel32.dll", <<FSIGN)
BOOL WINAPI SetHandleInformation(HANDLE hObject,
                                 DWORD dwMask,
                                 DWORD dwFlags);
FSIGN
            or croak "unable to wrap kernel32.dll SetHandleInformation function";

    }
}


sub unset_pipe_inherit_flag {
    my ($any, $pipe) = @_;
    __wrap_win32_functions($any);
    my $fn = fileno $pipe;
    my $wh = $win32_get_osfhandle->Call($fn)
        or die "internal error: win32_get_osfhandle failed unexpectedly";
    my $success = $win32_set_handle_information->Call($wh, $win32_handle_flag_inherit, 0);
    $debug and $debug & 1024 and
        _debug "Win32::SetHandleInformation($wh, $win32_handle_flag_inherit, 0) => $success",
            ($success ? () : (" \$^E: $^E"));
}

sub pty { croak "PTYs are not supported on Windows" }

sub open4 {
    my ($any, $fhs, $close, $pty, $stderr_to_stdout, @cmd) = @_;
    my ($pid, $error);

    my (@old, @new);

    $pty and croak "PTYs are not supported on Windows";
    grep tied $_, *STDIN, *STDOUT, *STDERR
        and croak "STDIN, STDOUT or STDERR is tied";
    grep { defined $_ and (tied $_ or not defined fileno $_) } @$fhs
        and croak "At least one of the given file-handles is tied or is not backed by a real OS file handle";

    for my $fd (0..2) {
        if (defined $fhs->[$fd]) {
            my $dir = ($fd ? '>' : '<');
            open $old[$fd], "$dir&", (\*STDIN, \*STDOUT, \*STDERR)[$fd] or $error = $!;
            open $new[$fd], "$dir&", $fhs->[$fd] or $error = $!;
        }
    }
    open $old[2], '<&', \*STDERR or $error = $! if $stderr_to_stdout;

    unless (defined $error) {
        if (not $new[0] or open STDIN, '<&', $new[0]) {
            if (not $new[1] or open STDOUT, '>&', $new[1]) {
                $new[2] = \*STDOUT if $stderr_to_stdout;
                if (not $new[2] or open STDERR, '>&', $new[2]) {
                    $pid = eval { system 1, @cmd } or $error = $!;
                    open STDERR, '>&', $old[2] or $error = $!
                        if $new[2]
                    }
                else {
                    $error = $!;
                }
                open STDOUT, '>&', $old[1] or $error = $!
                    if $new[1];
            }
            else {
                $error = $!
            }
            open STDIN, '<&', $old[0] or $error = $!
                if $new[0];
        }
        else {
            $error = $!;
        }
    }

    undef $_ for @old, @new;

    if (defined $error) {
        $any->_set_error(SSHA_CONNECTION_ERROR, "unable to start slave process: $error");
    }
    return { pid => $pid };
}

sub wait_proc {
    my ($any, $proc, $timeout, $force_kill) = @_;
    my $pid = $proc->{pid};
    $? = 0;

    $debug and $debug & 1024 and _debug "waiting for slave process $pid to exit";
    waitpid($pid, 0);
}

my @retriable = (Errno::EINTR, Errno::EAGAIN, Errno::ENOSPC, Errno::EINVAL);
push @retriable, Errno::EWOULDBLOCK if Errno::EWOULDBLOCK != Errno::EAGAIN;


sub __set_pipe_blocking {
    my ($any, $pipe, $blocking) = @_;
    if (defined $pipe) {
        __wrap_win32_functions($any);
        my $fileno = fileno $pipe;
        my $handle = $win32_get_osfhandle->Call($fileno);
        $debug and $debug & 1024 and _debug("setting pipe (pipe: ", $pipe,
                                            ", fileno: ", $fileno,
                                            ", handle: ", $handle, ") to",
                                            ($blocking ? " " : " non "), "blocking");
        my $success = $win32_set_named_pipe_handle_state->Call($handle,
                                                               ($blocking ? 0 : $win32_pipe_nowait),
                                                               0, 0);
        $debug and $debug & 1024 and _debug("Win32::SetNamedPipeHandleState => $success",
                                            ($success ? () : " ($^E)"));
    }
}

sub io3 {
    my ($any, $proc, $timeout, $data, $in, $out, $err) = @_;
    $timeout = $any->{timeout} unless defined $timeout;

    $debug and $debug & 1024 and _debug "io3 handles: ", $in, ", ", $out, ", ", $err;

    $data = $any->_os_io3_check_and_clean_data($data, $in);

    __set_pipe_blocking($any, $in,  0);
    __set_pipe_blocking($any, $out, 0);
    __set_pipe_blocking($any, $err, 0);

    $debug and $debug & 1024 and _debug "data array has ".scalar(@$data)." elements";

    my $bout = '';
    my $berr = '';
    while (defined $in or defined $out or defined $err) {
        my $delay = 1;
        if (defined $in) {
            while (@$data) {
                unless (defined $data->[0] and length $data->[0]) {
                    shift @$data;
                    next;
                }
                my $bytes = syswrite $in, $data->[0];
                if ($bytes) {
                    $debug and $debug & 1024 and _debug "$bytes bytes of data sent";
                    substr $data->[0], 0, $bytes, '';
                    undef $delay;
                }
                else {
                    unless (grep $! == $_, @retriable) {
                        $any->_set_error(SSHA_LOCAL_IO_ERROR, "failed to write to slave stdin channel: $!");
                        close $in;
                        undef $in;
                        undef $delay;
                    }
                    last;
                }
            }
            unless (@$data) {
                $debug and $debug & 1024 and _debug "closing slave stdin channel";
                close $in;
                undef $in;
                undef $delay;
            }
        }

        if (defined $out) {
            my $bytes = sysread($out, $bout, 20480, length($bout));
            if (defined $bytes) {
                $debug and $debug & 1024 and _debug "received ", $bytes, " bytes of data over stdout";
                undef $delay;
                unless ($bytes) {
                    $debug and $debug & 1024 and _debug "closing slave stdout channel at EOF";
                    close $out;
                    undef $out;
                }
            }
            else {
                unless (grep $! == $_, @retriable) {
                    $any->_set_error(SSHA_LOCAL_IO_ERROR, "failed to read from slave stdout channel: $!");
                    close $out;
                    undef $out;
                    undef $delay;
                }
            }
        }

        if (defined $err) {
            my $bytes = sysread($err, $berr, 20480, length($berr));
            if (defined $bytes) {
                $debug and $debug & 1024 and _debug "received ", $bytes, " bytes of data over stderr";
                undef $delay;
                unless ($bytes) {
                    $debug and $debug & 1024 and _debug "closing slave stderr channel at EOF";
                    close $err;
                    undef $err;
                }
            }
            else {
                unless (grep $! == $_, @retriable) {
                    $any->_set_error(SSHA_LOCAL_IO_ERROR, "failed to read from slave stderr channel: $!");
                    close $err;
                    undef $err;
                    undef $delay;
                }
            }
        }
        if ($delay) {
            # $debug and $debug & 1024 and _debug "delaying...";
            sleep 0.02; # experimentation has show the load introduced
                        # with this delay is not noticeable!
        }
    }

    $debug and $debug & 1024 and _debug "waiting for child";
    $any->_os_wait_proc($proc, $timeout);

    $debug and $debug & 1024 and _debug "leaving io3()";
    return ($bout, $berr);
}

1;
