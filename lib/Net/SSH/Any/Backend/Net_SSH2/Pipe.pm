package Net::SSH::Any::Backend::Net_SSH2::Pipe;

use strict;
use warnings;

use Carp;
our @CARP_NOT = qw(Net::SSH::Any::Backend::Net_SSH2);

use Net::SSH::Any::Util qw($debug _debug);

require Net::SSH::Any::Pipe;
our @ISA = qw(Net::SSH::Any::Pipe);

sub _new {
    my ($class, $any, $channel) = @_;
    $class->SUPER::_new($any,
                        _be_channel  => $channel);
}

sub wait_for_data { shift->{any}->_wait_for_more_data(@_) }

sub _syswrite {
    my $pipe = shift;
    my $channel = $pipe->{_be_channel};
    $channel->blocking($pipe->{blocking});
    my $bytes = $pipe->{any}->_syswrite($pipe->{_be_channel}, $_[0]);
    $channel->blocking(1);
    $debug and $debug & 8192 and _debug("$pipe->_syswrite() => $bytes bytes written");
    return $bytes;
}

# offset is always length($_[1]) and so, not passed
sub _sysread {
    my ($pipe, undef, $len, $ext) = @_;
    my $channel = $pipe->{_be_channel};
    $debug and $debug & 8192 and _debug("$pipe->_sysread($len, blocking => $pipe->{blocking})...");
    my $bytes = $pipe->{any}->_sysread($pipe->{_be_channel}, $pipe->{blocking}, $_[1], $len, $ext);
    $debug and $debug & 8192 and _debug($bytes, " bytes read");
    return $bytes;
}

sub _send_eof { shift->{_be_channel}->send_eof }
sub _eof      { shift->{_be_channel}->eof      }

sub _close    {
    my $pipe = shift;
    my $channel = $pipe->{_be_channel};
    $channel->close or __copy_error($pipe);
    my $status = $channel->exit_status || 0;
    my $signal = $channel->exit_signal || 0;
    $? = (($status << 8) | $signal);
    $pipe->{any}->_check_child_error;
}

1;
