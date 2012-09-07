package Net::SSH::Any::Backend::Net_SSH2::Pipe;

use strict;
use warnings;

use Carp;
our @CARP_NOT = qw(Net::SSH::Any::Backend::Net_SSH2);

require Net::SSH::Any::Pipe;
our @ISA = qw(Net::SSH::Any::Pipe);

sub _new {
    my ($class, $any, $channel) = @_;
    $class->SUPER::_new($any,
                        __channel  => $channel);
}

sub wait_for_data { shift->{any}->_wait_for_more_data(@_) }

sub _syswrite {
    my $pipe = shift;
    my $channel = $pipe->{__channel};
    $channel->blocking($pipe->{blocking});
    my $bytes = $pipe->{any}->_syswrite($pipe->{__channel}, $_[0]);
    $channel->blocking(1);
    return $bytes;
}

# offset is always length($_[1]) and so, not passed
sub _sysread {
    my ($pipe, undef, $len, $ext) = @_;
    my $channel = $pipe->{__channel};
    $channel->blocking($pipe->{blocking});
    my $bytes = $pipe->{any}->_sysread($pipe->{__channel}, $_[1], $len, $ext);
    $channel->blocking(1);
    return $bytes;
}

sub _send_eof { shift->{__channel}->send_eof }
sub _eof      { shift->{__channel}->eof      }

sub _close    {
    my $pipe = shift;
    my $channel = $pipe->{__channel};
    $channel->close or __copy_error($pipe);
    my $status = $channel->exit_status || 0;
    my $signal = $channel->exit_signal || 0;
    $? = (($status << 8) | $signal);
    $pipe->{any}->_check_child_error;
}

1;
