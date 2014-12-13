package Net::SSH::Any::Backend::_Cmd::OS::POSIX::DPipe;

use strict;
use warnings;

use Net::SSH::Any::Constants qw(SSHA_CHANNEL_ERROR);
use Net::SSH::Any::Util qw($debug _debug _debug_hexdump);

require Net::SSH::Any::Backend::_Cmd::DPipe;
our @ISA = qw(Net::SSH::Any::Backend::_Cmd::DPipe);

sub _upgrade_fh_to_dpipe {
    my ($class, $pipe, $os, $any, $proc) = @_;
    $class->SUPER::_upgrade_fh_to_dpipe($pipe, $os, $any, $proc);
    $pipe->autoflush(1);
    $pipe;
}

sub _close_fhs {
    my $pipe = shift;
    close $pipe and return 1;
    $pipe->_any->_set_error(SSHA_CHANNEL_ERROR, "Unable to close socket: $!");
    undef
}

sub syswrite {
    my $pipe = shift;
    my (undef, $len, $offset) = @_;
    $len ||= "<undef>";
    $offset ||= "<undef>";
    $debug and $debug & 8192 and
	_debug_hexdump("$pipe->syswrite(..., $len, $offset)", $_[0]);
    $pipe->SUPER::syswrite(@_);
}

sub send_eof {
    my $pipe = shift;
    shutdown $pipe, 1;
}

1;
