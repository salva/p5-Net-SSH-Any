package Net::SSH::Any::Backend::_Cmd::Pipe;

use strict;
use warnings;

use Net::SSH::Any::Constants ();
use Net::SSH::Any::Util qw($debug _debug _debug_hexdump);

require IO::Handle;
our @ISA = qw(IO::Handle);

use Data::Dumper;

sub _upgrade_socket {
    my ($class, $socket, $pid, $any) = @_;
    bless $socket, $class;
    ${*$socket}{_ssha_be_pid} = $pid;
    ${*$socket}{_ssha_be_any} = $any;
    $socket->autoflush(1);
    $socket
}

sub close {
    my $socket = shift;
    my $any = ${*$socket}{_ssha_be_any};
    my $pid = ${*$socket}{_ssha_be_pid};
    my $ok = 1;
    unless ($socket->SUPER::close(@_)) {
	$any->_or_set_error(Net::SSH::Any::Constants::SSHA_CHANNEL_ERROR,
			    "Socket close failed", $!);
	undef $ok;
    }
    if (defined $pid) {
	$any->_waitpid($pid) or undef $ok;
	delete ${*$socket}{_ssha_be_pid};
    }
    return $ok;
}

sub syswrite {
    my $socket = shift;
    my (undef, $len, $offset) = @_;
    $len ||= "<undef>";
    $offset ||= "<undef>";
    $debug and $debug & 8192 and
	_debug_hexdump("$socket->syswrite(..., $len, $offset)", $_[0]);
    $socket->SUPER::syswrite(@_);
}

sub send_eof {
    my $socket = shift;
    shutdown $socket, 1;
}

sub error {
    my $socket = shift;
    ${*$socket}{_ssha_be_any}->error;
}

1;
