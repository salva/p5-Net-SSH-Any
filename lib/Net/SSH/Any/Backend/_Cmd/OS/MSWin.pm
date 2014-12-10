package Net::SSH::Any::Backend::_Cmd::OS::MSWin;

use strict;
use warnings;

use Carp;
use Socket;
use Errno;
use Net::SSH::Any::Util qw($debug _debug _debug_hexdump _first_defined _array_or_scalar_to_list);
use Net::SSH::Any::Constants qw(:error);
use Win32API::File ();

require Net::SSH::Any::Backend::_Cmd::OS::_Base;
our @ISA = qw(Net::SSH::Any::Backend::_Cmd::OS::_Base);

sub socketpair {
    my ($os, $any) = @_;
    my ($a, $b);
    unless (CORE::socketpair($a, $b, AF_UNIX, SOCK_STREAM, PF_UNSPEC)) {
        $any->_set_error(SSHA_LOCAL_IO_ERROR, "socketpair failed: $!");
        return;
    }
    ($a, $b);
}

sub pipe {
    my ($os, $any) = @_;
    my ($r, $w);
    unless (CORE::pipe $r, $w) {
        $any->_set_error(SSHA_LOCAL_IO_ERROR, "Unable to create pipe: $!");
        return
    }
    ($r, $w);
}

sub unset_pipe_inherit_flag {
    my ($os, $any, $pipe) = @_;
    my $wh = Win32API::File::FdGetOsFHandle(fileno $pipe)
        or croak "Win32API::File::FdGetOsFHandle failed unexpectedly";
    Win32API::File::SetHandleInformation($wh, Win32API::File::HANDLE_FLAG_INHERIT, 0)
}

sub pty {
    my ($os, $any) = @_;
    croak "PTYs are not supported on Windows";
}

sub open4 {
    my ($os, $any, $fhs, $close, $pty, $stderr_to_stdout, @cmd) = @_;
    my ($pid, $error);

    my (@old, @new);

    $pty and croak "PTYs are not supported on Windows";
    grep tied $_, *STDIN, *STDOUT, *STDERR
        and croak "STDIN, STDOUT or STDERR is tied";
    grep { defined $_ and (tied $_ or not defined fileno $_) } @$fhs
        and croak "At least one of the given file-handles is tied or is not backed by a real OS file handle";

    use Data::Dumper;
    print Dumper $fhs;

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
    my ($os, $any, $proc, $timeout, $force_kill) = @_;
    my $pid = $proc->{pid};
    $? = 0;

    $debug and $debug & 1024 and _debug "waiting for slave process $pid to exit";
    waitpid($pid, 0);
}

my @retriable = (Errno::EINTR, Errno::EAGAIN);
push @retriable, Errno::EWOULDBLOCK if Errno::EWOULDBLOCK != Errno::EAGAIN;

sub io3 {
    my ($os, $any, $proc, $timeout, $data, $in, $out, $err) = @_;
    my @data = _array_or_scalar_to_list $data;
    $timeout = $any->{timeout} unless defined $timeout;

    if (defined $in) {
        for my $data (grep { defined and length } @data) {
            #my $bytes = print $in $data; # FIXME: print may fail to send all the data
            my $bytes = syswrite $in, $data;
            $debug and $debug & 1024 and _debug "send $bytes bytes of data";
        }
        $debug and $debug & 1024 and _debug "closing slave stdin channel";
    }

    my $bout = '';
    if (defined $out) {
        while (1) {
            my $read = sysread($out, $bout, 20480, length($bout));
            $read or grep($! == $_, @retriable) or last;
        }
        close $out;
    }

    my $berr = '';
    if (defined $err) {
        while (1) {
            my $read = sysread($err, $berr, 20480, length($berr));
            $read or grep($! == $_, @retriable) or last;
        }
        close $err;
    }

    $os->wait_proc($any, $proc, $timeout);

    $debug and $debug & 1024 and _debug "leaving __io3()";
    return ($bout, $berr);
}

1;
