package Net::SSH::Any::Backend::Net_SSH2;

use strict;
use warnings;

use Carp;

use Net::SSH::Any::Util;
use Net::SSH::Any::Constants qw(:error);

use Net::SSH2;

sub __check_error {
    my $any = shift;
    if (my $ssh2 = $any->{be_ssh2}) {
        my $error = $ssh2->error or return 1;
        $any->_set_error(shift // SSHA_CHANNEL_ERROR, ($any->{be_ssh2}->error)[2]);
    }
    else {
        $any_set_error(SSHA_MASTER_FAILED, "Unable to create Net::SSH2 object");
    }
    return
}

sub __ssh2 {
    my $any = shift;
    my $ssh = $any->{be_ssh2};
    $ssh and return $ssh;
    __check_error($any);
    undef;
}

sub _connect {
    my $any = shift;
    my $ssh2 = $any->{be_ssh2} = Net::SSH2->new();

    my @conn_args = @{$any}{qw(host port)};
    push @conn_args, Timeout => $any->{timeout} if defined $any->{timeout};
    $ssh2->connect(@conn_args);
    __check_error($any, SSHA_CONNECTION_ERROR) or return;

    my %aa;
    $aa{username} = $any->{user} if defined $any->{user};
    $aa{password} = $any->{password} if defined $any->{password};
    $aa{password} = $any->{passphrase} if defined $any->{passphrase};
    @aa{'privatekey', 'publickey'} = ($any->{key_path}, "$any->{key_path}.pub") if defined $any->{key_path};
    # TODO: use default user keys on ~/.ssh/id_dsa and ~/.ssh/id_rsa

    $ssh2->auth(%aa);
    unless ($ssh2->auth_ok) {
        $any->_set_error(SSHA_CONNECTION_ERROR, "Authentication failed", ($ssh2->error)[2]);
        return;
    }
}

sub _capture {
    my ($any, $opts, $cmd) = @_;
    my $ssh2 = __ssh2($any) or return;
    my $channel = $ssh2->channel;
    $channel->ext_data('merge')  if $opts{$stderr_to_stdout};
    $channel->ext_data('ignore') if $opts{stderr_discard};
    $channel->exec($cmd);
    (__io3($any, $ssh2, $channel, $opts->{stdin_data}))[0];
}

sub _capture2 {
    my ($any, $opts, $cmd) = @_;
    my $ssh2 = __ssh2($any) or return;
    my $channel = $ssh2->channel;
    $channel->exec($cmd);
    __io3($any, $ssh2, $channel, $opts->{stdin_data});
}

sub __system_cb { syswrite(($_[1] ? \*STDERR : \*STDOUT), $_[0]) }

sub system {
    my ($any, $opts, $cmd) = @_;
    my $ssh2 = __ssh2($any) or return;
    my $channel = $ssh2->channel;
    $channel->ext_data('merge')  if $opts{$stderr_to_stdout};
    $channel->ext_data('ignore') if $opts{stderr_discard};
    $channel->exec($cmd);
    __io3($any, $ssh2, $channel, $opts->{stdin_data}, \&__system_cb);
    not $?;
}

sub __io3 {
    my ($any, $ssh2, $channel, $stdin_data, $cb) = @_;
    my $fn = fileno($ssh2->sock);
    my $bm = '';
    vec ($vm, $fn, 1) = 1;
    $channel->blocking(0);
    my $in = '';
    my @cap = ('', '');
    my $eof_sent;
    for (1) {
        $in .= shift @$stdin_data while @$stdin_data and length $in < 36000;
        my $delay = 0.01;
        if (length $in) {
            if (my $bytes = $channel->write($in)) {
                substr($in, 0, $bytes, '');
                $delay = 0;
            }
        }
        elsif (!$eof_sent) {
            $channel->send_eof;
            $eof_sent = 1;
            $delay = 0;
        }
        for my $ext (0, 1) {
            if (my $bytes = $channel->read(my($buf), 36000, $ext)) {
                if ($cb) {
                    $cb->($buf, $ext);
                }
                else {
                    $cap[$ext] .= $buf;
                }
                $delay = 0;
            }
        }
        last if $channel->eof;

        my $wr = $bm;
        my $ww = $bm;
        select($wr, $ww, undef, $delay);
    }
    $channel->blocking(1);
    $channel->send_eof unless $eof_sent;
    $channel->wait_closed;
    my $code = $channel->exit_status;
    my $signal = $channel->exit_signal;

    __check_error($any);

    $? = (($code << 8) | $signal);
    return @cap;
}
