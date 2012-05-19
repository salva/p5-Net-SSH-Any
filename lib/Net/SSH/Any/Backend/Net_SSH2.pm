package Net::SSH::Any::Backend::Net_SSH2;

use strict;
use warnings;

use Carp;
our @CARP_NOT = qw(Net::SSH::Any);

use Net::SSH::Any::Util;
use Net::SSH::Any::Constants qw(:error);

use Net::SSH2;
use File::Spec;
use Errno ();

sub _backend_api_version { 1 }

my ($block_inbound, $block_outbound, $eagain);
do {
    local ($@, $SIG{__DIE__});
    $block_inbound  = (eval { Net::SSH2::LIBSSH2_SOCKET_BLOCK_INBOUND()  } ||   1);
    $block_outbound = (eval { Net::SSH2::LIBSSH2_SOCKET_BLOCK_OUTBOUND() } ||   2);
    $eagain         = (eval { Net::SSH2::LIBSSH2_ERROR_EAGAIN()          } || -37);
};

sub __copy_error {
    my $any = shift;
    my $ssh2 = $any->{be_ssh2}
        or die "internal error: __copy_error called, but there is no ssh2 object";
    my $error = $ssh2->error
        or die "internal error: __copy_error called, but there is no error";
    $any->_set_error(shift || SSHA_CHANNEL_ERROR, ($ssh2->error)[2]);
    ()
}

sub _connect {
    my $any = shift;
    my $ssh2 = $any->{be_ssh2} = Net::SSH2->new;
    unless ($ssh2) {
        $any->_set_error(SSHA_CONNECTION_ERROR, "Unable to create Net::SSH2 object");
        return;
    }
    $debug and $debug & 2048 and $ssh2->trace(1);

    my @args = ($any->{host}, $any->{port} || 22);
    push @args, Timeout => $any->{timeout} if defined $any->{timeout};
    $ssh2->connect(@args) or
        return __copy_error($any, SSHA_CONNECTION_ERROR);

    my %aa;
    $aa{username} = $any->{user} if defined $any->{user};
    $aa{password} = $any->{password} if defined $any->{password};
    $aa{password} = $any->{passphrase} if defined $any->{passphrase};
    @aa{'privatekey', 'publickey'} = ($any->{key_path}, "$any->{key_path}.pub") if defined $any->{key_path};
    # TODO: use default user keys on ~/.ssh/id_dsa and ~/.ssh/id_rsa

    $ssh2->auth(%aa);
    unless ($ssh2->auth_ok) {
        $any->_set_error(SSHA_CONNECTION_ERROR, "Authentication failed");
        return;
    }
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

sub __parse_fh_opts {
    my ($any, $opts, $channel) = @_;
    my @name = qw(stdout stderr);
    my @fh;
    for my $stream (qw(stdout stderr)) {
        my $fh = delete $opts->{"${stream}_fh"};
        unless ($fh) {
            my $file = ( delete($opts->{"stdout_discard"}) # first pass may delete element, second never does
                         ? File::Spec->devnull
                         : delete $opts->{"${stream}_file"} );
            if (defined $file) {
                $fh = __open_file($any, $file) or return;
            }
            if ($stream eq 'stderr' and not defined $fh) {
                if (delete $opts->{stderr_to_stdout}) {
                    $channel->ext_data('merge');
                }
                elsif (delete $opts->{stderr_discard}) {
                    $channel->ext_data('ignore');
                }
            }
        }
        push @fh, $fh;
    }
    grep /^std(?:out|err)_/, keys %$opts and
        croak "invalid option(s) '" . join("', '", grep /^std(?:out|err)_/, keys %$opts) . "'";
    return @fh;
}

sub _system {
    my ($any, $opts, $cmd) = @_;
    my $ssh2 = $any->{be_ssh2} or return;
    my $channel = $ssh2->channel;
    my ($out_fh, $err_fh) = __parse_fh_opts($any, $opts, $channel) or return;
    $channel->exec($cmd);
    __io3($any, $ssh2, $channel, $opts->{stdin_data}, $out_fh || \*STDOUT, $err_fh || \*STDERR);
    not $?;
}

sub _capture {
    my ($any, $opts, $cmd) = @_;
    my $ssh2 = $any->{be_ssh2} or return;
    my $channel = $ssh2->channel;
    my ($out_fh, $err_fh) = __parse_fh_opts($any, $opts, $channel) or return;
    $out_fh and die 'Internal error: $out_fh is not undef';
    $channel->exec($cmd);
    (__io3($any, $ssh2, $channel, $opts->{stdin_data}, undef, $err_fh || \*STDERR))[0];
}

sub _capture2 {
    my ($any, $opts, $cmd) = @_;
    my $ssh2 = $any->{be_ssh2} or return;
    my $channel = $ssh2->channel;
    $channel->exec($cmd);
    __io3($any, $ssh2, $channel, $opts->{stdin_data});
}

sub __write_all {
    my $any = shift;
    my $fh = shift;
    my $off = 0;
    while (length($_[0]) > $off) {
        if (my $bytes = syswrite $fh, $_[0], 40000, $off) {
            $off += $bytes;
        }
        elsif ($! == Errno::EAGAIN()) {
            select undef, undef, undef, 0.05;
        }
        else {
            $any->_set_error(SSHA_LOCAL_IO_ERROR, "Couldn't write to pipe", $!);
            return;
        }
    }
    return 1;
}

sub __check_channel_error {
    my $any = shift;
    my $error = $any->{be_ssh2}->error;
    return 1 unless $error and $error != $eagain;
    __copy_error($any, SSHA_CHANNEL_ERROR);
}

sub __io3 {
    my ($any, $ssh2, $channel, $stdin_data, @fh) = @_;
    my $fn = fileno($ssh2->sock);
    my $bm = '';
    vec ($bm, $fn, 1) = 1;
    $channel->blocking(0);
    my $in = '';
    my @cap = ('', '');
    my $eof_sent;
    while (1) {
        #$debug and $debug and 1024 and _debug("looping...");
        $in .= shift @$stdin_data while @$stdin_data and length $in < 36000;
        if (length $in) {
            if (my $bytes = $channel->write($in)) {
                substr($in, 0, $bytes, '');
            }
            else {
                __check_channel_error($any) or last;
            }
        }
        elsif (!$eof_sent) {
            $channel->send_eof;
            $eof_sent = 1;
        }
        for my $ext (0, 1) {
            if (my $bytes = $channel->read(my($buf), 36000, $ext)) {
                if ($fh[$ext]) {
                    __write_all($any, $fh[$ext], $buf) or last;
                }
                else {
                    $cap[$ext] .= $buf;
                }
            }
            else {
                __check_channel_error($any) or last;
            }
        }
        last if $channel->eof;

        my $dir = $ssh2->block_directions;
        my $wr = ($dir & $block_inbound  ? $bm : '');
        my $ww = ($dir & $block_outbound ? $bm : '');
        select($wr, $ww, undef, 2);
    }

    $channel->blocking(1);
    $channel->send_eof unless $eof_sent;
    $channel->wait_closed;

    my $code = $channel->exit_status || 0;
    my $signal = $channel->exit_signal || 0;

    $channel->close or __copy_error($any, SSHA_CONNECTION_ERROR);

    $? = (($code << 8) | $signal);
    return @cap;
}

1;
