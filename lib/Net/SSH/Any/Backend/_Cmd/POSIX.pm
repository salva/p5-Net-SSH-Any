package Net::SSH::Any::Backend::_Cmd::POSIX;

use strict;
use warnings;

use Exporter;
our @ISA = qw(Exporter);
our @EXPORT = qw(__io3 __waitpid __socketpair __pipe __pty __open4);

use Carp;
our @CARP_NOT = qw(Net::SSH::Any::_Cmd);

use POSIX ();
use Socket;
use Net::SSH::Any::Util qw($debug _debug _debug_hexdump _first_defined _array_or_scalar_to_list);
use Net::SSH::Any::Constants qw(:error);
use File::Spec;
use Time::HiRes ();
use Errno;

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

sub __socketpair {
    my $any = shift;
    my ($a, $b);
    unless (socketpair($a, $b, AF_UNIX, SOCK_STREAM, PF_UNSPEC)) {
        $any->_set_error(SSHA_LOCAL_IO_ERROR, "socketpair failed: $!");
        return;
    }
    ($a, $b);
}

sub __pipe {
    my $any = shift;
    my ($r, $w);
    unless (pipe $r, $w) {
        $any->__set_error(SSHA_LOCAL_IO_ERROR, "Unable to create pipe: $!");
        return
    }
    ($r, $w);
}

sub __pty {
    my $any = shift;
    $any->_load_module('IO::Pty') or return;
    IO::Pty->new;
}

sub __open4 {
    my ($any, $fhs, $close, $pty, $stderr_to_stdout, @cmd) = @_;

    my $pid = fork;
    unless ($pid) {
        unless (defined $pid) {
            $any->__set_error(SSHA_CONNECTION_ERROR, "unable to fork new process: $!");
            return;
        }

        $pty->make_slave_controlling_terminal if $pty;

        my @fds = map __fileno_dup_over(3 => $_), @$fhs;
        close $_ for grep defined, @$close;

        for (0..2) {
            my $fd = $fds[$_];
            POSIX::dup2($fd, $_) if defined $fd;
        }

        POSIX::dup2(1, 2) if $stderr_to_stdout;

        do { exec @cmd };
        POSIX::_exit(255);
    }
    $pid;
}

sub __waitpid {
    my ($any, $pid, $timeout, $force_kill) = @_;
    $? = 0;

    my $time_limit;
    if ($force_kill or $any->{_kill_ssh_on_timeout}) {
        $timeout = $any->{_timeout} unless defined $timeout;
        if (defined $timeout) {
            $timeout = 0 if $any->error == SSHA_TIMEOUT_ERROR;
            $time_limit = time + $timeout;
        }
    }
    local $SIG{CHLD} = sub {};
    while (1) {
        my $r;
        if (defined $time_limit) {
            while (1) {
                # TODO: we assume that all OSs return 0 when the
                # process is still running, that may be false!
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
        $debug and $debug & 1024 and _debug "__waitpid($pid) => pid: $r, rc: $!";
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

    __waitpid($any, $pid, $timeout);

    $debug and $debug & 1024 and _debug "leaving __io3()";
    return ($bout, $berr);
}

1;
