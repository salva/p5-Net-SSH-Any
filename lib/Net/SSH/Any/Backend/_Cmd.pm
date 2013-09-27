package Net::SSH::Any::Backend::_Cmd;

use strict;
use warnings;

use Carp;
our @CARP_NOT = qw(Net::SSH::Any);

use POSIX ();
use Socket;
use Net::SSH::Any::Util qw($debug _debug _debug_hexdump _first_defined _array_or_scalar_to_list);
use Net::SSH::Any::Constants qw(:error);
use File::Spec;
use Time::HiRes ();
use Errno;

sub _backend_api_version { 1 }

sub _connect {
    my $any = shift;
    my %opts = map { $_ => $any->{$_} } qw(host port user password passphrase key_path timeout);
    if (my $extra = $any->{backend_opts}{$any->{backend}}) {
        @opts{keys %$extra} = values %$extra;
    }
    my $extra = $any->{backend_opts}{$any->{backend}};
    $any->_validate_connect_opts( ( map  { $_ => $any->{$_} }
                                    qw(host port user password passphrase key_path timeout) ),
                                  ( $extra ? %$extra : () ) );
}

sub __open_file {
    my ($any, $name_or_args) = @_;
    my ($mode, @args) = (ref $name_or_args
			 ? @$name_or_args
			 : ('>', $name_or_args));
    if (open my $fh, $mode, @args) {
        return $fh;
    }
    $any->_set_error(SSHA_LOCAL_IO_ERROR, "Unable to open file '@args': $!");
    return undef;
}

sub __fileno_dup_over {
    my ($good_fn, $fh) = @_;
    if (defined $fh) {
        my $fn = fileno $fh;
        for (1..5) {
            $fn >= $good_fn and return $fn;
            $fn = POSIX::dup($fn);
        }
        POSIX::_exit(255);
    }
    undef;
}

sub __fork_cmd {
    my ($any, $opts, $cmd) = @_;

    my $data = $opts->{stdin_data};
    $opts->{stdin_pipe} = 1 if defined $data;

    my (@fhs, @pipes);
    my $socket = delete $opts->{stdinout_socket};
    if ($socket) {
        unless (socketpair $fhs[0], $pipes[0], AF_UNIX, SOCK_STREAM, PF_UNSPEC) {
            $any->_set_error(SSHA_LOCAL_IO_ERROR, "socketpair failed: $!");
            return;
        }
        $fhs[1] = $fhs[0];
        $pipes[1] = undef;
    }

    for my $stream (($socket ? () : ('stdin', 'stdout')), 'stderr') {
        my ($fh, $pipe);
        if (delete $opts->{"${stream}_pipe"}) {
            unless (pipe $pipe, $fh) {
                $any->__set_error(SSHA_LOCAL_IO_ERROR, "Unable to create pipe: $!");
                return
            }
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
                    $fh = __open_file($any, $file) or return;
                }
            }
        }

        push @fhs, $fh;
        push @pipes, $pipe;
    }

    my $stderr_to_stdout = (defined $fhs[2] ? delete $opts->{stderr_to_stdout} : 0);

    my @too_many = grep { /^std(?:in|out|err)_/ and
                              $_ ne 'stdin_data' and
                                  defined $opts->{$_} } keys %$opts;
    @too_many and croak "unsupported options or bad combination ('".join("', '", @too_many)."')";

    my @cmd = $any->_make_cmd($opts, $cmd) or return;
    my $pid = fork;
    unless ($pid) {
        unless (defined $pid) {
            $any->__set_error(SSHA_CONNECTION_ERROR, "unable to fork new process: $!");
            return;
        }

        close $_ for grep defined, @pipes;
        my @fds = map __fileno_dup_over(3 => $_), @fhs;
        for (0..2) {
            my $fd = $fds[$_];
            POSIX::dup2($fd, $_)  if defined $fd;
        }
        POSIX::dup2(1, 2) if $stderr_to_stdout;

        do { exec @cmd };
        POSIX::_exit(255);
    }
    return ($pid, @pipes);
}

sub _waitpid {
    my ($any, $pid, $timeout) = @_;
    $? = 0;
    $timeout = $any->{_timeout} unless defined $timeout;

    my $time_limit;
    if (defined $timeout and $any->{_kill_ssh_on_timeout}) {
        $timeout = 0 if $any->error == SSHA_TIMEOUT_ERROR;
        $time_limit = time + $timeout;
    }
    local $SIG{CHLD} = sub {};
    while (1) {
        my $r;
        if (defined $time_limit) {
            while (1) {
                # TODO: we assume that all OSs return 0 when the
                # process is still running, that may not be true!
                $r = waitpid($pid, POSIX::WNOHANG()) and last;
                my $remaining = $time_limit - time;
                if ($remaining <= 0) {
                    $debug and $debug & 1024 and _debug "killing SSH slave, pid: $pid";
                    kill TERM => $pid;
                    $any->_or_set_error(SSHA_TIMEOUT_ERROR, "slave command timed out");
                }
                # There is a race condition here. We try to
                # minimize it keeping the waitpid and the select
                # together and limiting the sleep time to 1s:
                my $sleep = ($remaining < 0.1 ? 0.1 : 1);
                $debug and $debug & 1024 and
                    _debug "waiting for slave cmd, timeout: $timeout, remaining: $remaining, sleep: $sleep";
                $r = waitpid($pid, POSIX::WNOHANG()) and last;
                select(undef, undef, undef, $sleep);
            }
        }
        else {
            $r = waitpid($pid, 0);
        }
        $debug and $debug & 1024 and _debug "_waitpid($pid) => pid: $r, rc: $!";
        if ($r == $pid) {
            if ($?) {
                my $signal = ($? & 255);
                my $errstr = "child exited with code " . ($? >> 8);
                $errstr .= ", signal $signal" if $signal;
                $any->_or_set_error(SSHA_REMOTE_CMD_ERROR, $errstr);
                return undef;
            }
            return 1;
        }
        if ($r > 0) {
            warn "internal error: spurious process $r exited";
            next;
        }
        next if $! == Errno::EINTR();
        if ($! == Errno::ECHILD()) {
            $any->_or_set_error(SSHA_REMOTE_CMD_ERROR, "child process $pid does not exist", $!);
            return undef
        }
        warn "Internal error: unexpected error (".($!+0).": $!) from waitpid($pid) = $r. Report it, please!";

        # wait a bit before trying again
        select(undef, undef, undef, 0.1);
    }
}

my @retriable = (Errno::EINTR, Errno::EAGAIN);
push @retriable, Errno::EWOULDBLOCK if Errno::EWOULDBLOCK != Errno::EAGAIN;

sub __io3 {
    my ($any, $pid, $timeout, $data, $in, $out, $err) = @_;
    my @data = _array_or_scalar_to_list $data;
    my ($cin, $cout, $cerr) = map defined, $in, $out, $err;
    $timeout = $any->{timeout} unless defined $timeout;

    my $has_input = grep { defined and length } @data;
    if ($cin and !$has_input) {
        close $in;
        undef $cin;
    }
    elsif (!$cin and $has_input) {
        croak "remote input channel is not defined but data is available for sending"
    }

    my $bout = '';
    my $berr = '';
    my ($fnoout, $fnoerr, $fnoin);
    local $SIG{PIPE} = 'IGNORE';

 MLOOP: while ($cout or $cerr or $cin) {
        $debug and $debug & 1024 and _debug "io3 mloop, cin: " . ($cin || 0) .
            ", cout: " . ($cout || 0) . ", cerr: " . ($cerr || 0);
        my ($rv, $wv);

        if ($cout or $cerr) {
            $rv = '';
            if ($cout) {
                $fnoout = fileno $out;
                vec($rv, $fnoout, 1) = 1;
            }
            if ($cerr) {
                $fnoerr = fileno $err;
                vec($rv, $fnoerr, 1) = 1
            }
        }

        if ($cin) {
            $fnoin = fileno $in;
            $wv = '';
            vec($wv, $fnoin, 1) = 1;
        }

        my $recalc_vecs;
    FAST: until ($recalc_vecs) {
            $debug and $debug & 1024 and
                _debug "io3 fast, cin: " . ($cin || 0) .
                    ", cout: " . ($cout || 0) . ", cerr: " . ($cerr || 0);
            my ($rv1, $wv1) = ($rv, $wv);
            my $n = select ($rv1, $wv1, undef, $timeout);
            if ($n > 0) {
                if ($cout and vec($rv1, $fnoout, 1)) {
                    my $offset = length $bout;
                    my $read = sysread($out, $bout, 20480, $offset);
                    $debug and $debug & 1024 and _debug "stdout, bytes read: ", $read, " at offset $offset";
                    unless ($read or grep $! == $_, @retriable) {
                        close $out;
                        undef $cout;
                        $recalc_vecs = 1;
                    }
                }
                if ($cerr and vec($rv1, $fnoerr, 1)) {
                    my $read = sysread($err, $berr, 20480, length($berr));
                    $debug and $debug & 1024 and _debug "stderr, bytes read: ", $read;
                    unless ($read or grep $! == $_, @retriable) {
                        close $err;
                        undef $cerr;
                        $recalc_vecs = 1;
                    }
                }
                if ($cin and vec($wv1, $fnoin, 1)) {
                    my $written = syswrite($in, $data[0], 20480);
                    $debug and $debug & 64 and _debug "stdin, bytes written: ", $written;
                    if ($written) {
                        substr($data[0], 0, $written, '');
                        while (@data) {
                            next FAST
                                if (defined $data[0] and length $data[0]);
                            shift @data;
                        }
                        # fallback when stdin queue is exhausted
                    }
                    elsif (grep $! == $_, @retriable) {
                        next FAST;
                    }
                    close $in;
                    undef $cin;
                    $recalc_vecs = 1;
                }
            }
            else {
                next if $n < 0 and grep $! == $_, @retriable;
                $any->_set_error(SSHA_TIMEOUT_ERROR, 'slave command timed out');
                last MLOOP;
            }
        }
    }
    close $out if $cout;
    close $err if $cerr;
    close $in if $cin;

    $any->_waitpid($pid, $timeout);

    $debug and $debug & 1024 and _debug "leaving _io3()";
    return ($bout, $berr);
}

sub _system {
    my ($any, $opts, $cmd) = @_;
    my ($pid, @pipes) = __fork_cmd($any, $opts, $cmd) or return;
    __io3($any, $pid, $opts->{timeout}, $opts->{stdin_data}, @pipes);
}

sub _capture {
    my ($any, $opts, $cmd) = @_;
    $opts->{stdout_pipe} = 1;
    my ($pid, @pipes) = __fork_cmd($any, $opts, $cmd) or return;
    __io3($any, $pid, $opts->{timeout}, $opts->{stdin_data}, @pipes);
}

sub _capture2 {
    my ($any, $opts, $cmd) = @_;
    $opts->{stdout_pipe} = 1;
    $opts->{stderr_pipe} = 1;
    my ($pid, @pipes) = __fork_cmd($any, $opts, $cmd) or return;
    __io3($any, $pid, $opts->{timeout}, $opts->{stdin_data}, @pipes);
}

sub _pipe {
    my ($any, $opts, $cmd) = @_;
    $opts->{stdinout_socket} = 1;
    my ($pid, $socket) = __fork_cmd($any, $opts, $cmd) or return;
    require Net::SSH::Any::Backend::_Cmd::Pipe;
    Net::SSH::Any::Backend::_Cmd::Pipe->_upgrade_socket($socket, $pid, $any);
}

sub _sftp {
    my ($any, $opts) = @_;
    $opts->{subsystem} = 1;
    $opts->{stdin_pipe} = 1;
    $opts->{stdout_pipe} = 1;
    my ($pid, $in, $out) = __fork_cmd($any, $opts, 'sftp') or return;
    Net::SFTP::Foreign->new(transport => [$in, $out, $pid], %$opts);
}

1;

