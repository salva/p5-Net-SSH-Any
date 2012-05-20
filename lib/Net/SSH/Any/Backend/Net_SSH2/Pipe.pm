package Net::SSH::Any::Backend::Net_SSH2::Pipe;

use strict;
use warnings;

use Carp;
our @CARP_NOT = qw(Net::SSH::Any::Backend::Net_SSH2);

require qw(Net::SSH::Any::Pipe);
our @ISA = qw(Net::SSH::Any::Pipe);

sub _new {
    my ($class, $any, $channel) = @_;
    $class->SUPER::_new($any,
                        __channel  => $channel,

}

sub wait_for_data { shift->{any}->_wait_for_data(@_);

sub __copy_error {
    Net::SSH::Any::Backend::Net_SSH2::__copy_error(shift->{any});
}

# offset is always length($_[3]) and so, not passed
sub _sysread {
    my ($pipe, $len, $ext) = @_;
    my $channel = $pipe->{channel};
    $channel->blocking($pipe->{blocking});
    my $bytes = $channel->read(my($buf), $len, $ext);
    if ($bytes) {
        $_[3] .= $buf;
    }
    else {
        __copy_error($pipe);
    }
    $channel->blocking(1);
    return $bytes;
}

sub _syswrite {
    my ($pipe, $len, $off) = @_;
    my $channel = $pipe->{channel};
    $channel->blocking($pipe->{blocking});
    my $buf = substr($_[3], $off, $len);
    my $bytes = $channel->write($buf) or __copy_error($pipe);
    $channel->blocking(1);
    return $bytes;
}

sub _send_eof { shift->{channel}->send_eof }
sub _eof      { shift->{channel}->eof      }

sub _close    {
    my $pipe = shift;
    my $channel = $pipe->{channel};
    $channel->close or __copy_error($pipe);
    my $status = $channel->exit_status || 0;
    my $signal = $channel->exit_signal || 0;
    $? = (($status << 8) | $signal);
    $pipe->{any}->_check_child_error;
}

