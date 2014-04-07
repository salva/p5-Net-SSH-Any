package Net::SSH::Any::Backend::_Cmd::MSWin;

use strict;
use warnings;

use Exporter;
our @ISA = qw(Exporter);
our @EXPORT = qw(__io3 __waitpid __socketpair __pipe __pty __open4);

use Carp;
our @CARP_NOT = qw(Net::SSH::Any::_Cmd);

use Socket;
use Errno;
use Net::SSH::Any::Util qw($debug _debug _debug_hexdump _first_defined _array_or_scalar_to_list);
use Net::SSH::Any::Constants qw(:error);
use IPC::Open3 qw(open3);

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
    croak "PTYs are not supported on Windows";
}

# sub __open4 {
#     my ($any, $fhs, $pty, $stderr_to_stdout, @cmd) = @_;
#     my ($in, $out, $err) = @$fhs;
#     $in = \*STDIN unless defined $in;
#     $out = \*STDOUT unless defined $out;
#     $err = ($stderr_to_stdout ? $out : \*STDERR) unless defined $err;

#     local ($@, $SIG{__DIE__}, $SIG{__WARN__});
#     my $pid = eval { open3($in, $out, $err, @cmd) };
#     $@ and warn $@;
#     $pid;
# }

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
    waitpid($pid, 0);
}

my @retriable = (Errno::EINTR, Errno::EAGAIN);
push @retriable, Errno::EWOULDBLOCK if Errno::EWOULDBLOCK != Errno::EAGAIN;

sub __io3 {
    my ($any, $pid, $timeout, $data, $in, $out, $err) = @_;
    my @data = _array_or_scalar_to_list $data;
    $timeout = $any->{timeout} unless defined $timeout;

    if (defined $in) {
        for my $data (grep { defined and length } @data) {
            print $in $data; # FIXME: print may fail to send all the data
        }
        close $in;
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

    __waitpid($any, $pid, $timeout);

    $debug and $debug & 1024 and _debug "leaving __io3()";
    return ($bout, $berr);
}

1;
