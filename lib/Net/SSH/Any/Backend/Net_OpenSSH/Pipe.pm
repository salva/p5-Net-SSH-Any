package Net::SSH::Any::Backend::Net_OpenSSH::Pipe;

use strict;
use warnings;

use Net::SSH::Any::Constants ();
use Net::SSH::Any::Util qw($debug _debug);

require IO::Socket;
our @ISA = qw(IO::Socket);

use Data::Dumper;

sub _upgrade_socket {
    my ($class, $socket, $pid, $any) = @_;
    bless $socket, $class;
    ${*$socket}{_pid} = $pid;
    ${*$socket}{_any} = $any;
    $socket
}

sub close {
    my $socket = shift;
    my $any = ${*$socket}{_any};
    my $pid = ${*$socket}{_pid};
    my $ok = 1;
    unless ($socket->SUPER::close(@_)) {
	$any->_or_set_error(Net::SSH::Any::Constants::SSHA_CHANNEL_ERROR,
			    "Socket close failed", $!);
	undef $ok;
    }
    if (defined $pid) {
	$any->{be_ssh}->_waitpid($pid) or undef $ok;
	delete ${*$socket}{_pid};
    }
    return $ok;
}

1;
