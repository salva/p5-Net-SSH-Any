package Net::SSH::Any::Backend::_Cmd::OS::MSWin::Pipe;

use strict;
use warnings;

use Carp;
use Socket;
use Errno;
use Net::SSH::Any::Util qw($debug _debug _debug_hexdump _first_defined _array_or_scalar_to_list);
use Net::SSH::Any::Constants qw(SSHA_CHANNEL_ERROR);
use Time::HiRes qw(sleep);

require Net::SSH::Any::Backend::_Cmd::Pipe;
our @ISA = qw(Net::SSH::Any::Backend::_Cmd::Pipe);

sub _in { ${*{shift()}}{_ssha_be_in} }

for my $method (qw(syswrite print printf say)) {
    my $m = $method;
    no strict 'refs';
    *{$m} = sub { shift->_in->$m(@_) }
}

sub _upgrade_fh_to_pipe {
    my ($class, $pipe, $os, $any, $proc, $in) = @_;
    $class->SUPER::_upgrade_fh_to_pipe($pipe, $os, $any, $proc);
    bless $in, 'IO::Handle';
    ${*$pipe}{_ssha_be_in} = $in;
    $pipe;
}

sub _close_fhs {
    my $pipe = shift;
    my $ok = $pipe->send_eof;
    unless (close $pipe) {
        $pipe->_any->_set_error(SSHA_CHANNEL_ERROR, "unable to close dpipe reading side: $!");
        undef $ok;
    }
    return $ok;
}

sub send_eof {
    my $pipe = shift;
    if (defined (my $in = delete ${*$pipe}{_ssha_be_in})) {
        unless (close $in) {
            $pipe->_any->_set_error(SSHA_CHANNEL_ERROR, "unable to close dpipe writing side: $!");
            return undef
        }
    }
    1
}

1;
