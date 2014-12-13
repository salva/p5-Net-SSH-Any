package Net::SSH::Any::OS::MSWin::DPipe;

use strict;
use warnings;

use Carp;
use Socket;
use Errno;
use Net::SSH::Any::Util qw($debug _debug _debug_hexdump _first_defined _array_or_scalar_to_list);
use Net::SSH::Any::Constants qw(SSHA_CHANNEL_ERROR);
use Time::HiRes qw(sleep);

require Net::SSH::Any::Backend::_Cmd::DPipe;
our @ISA = qw(Net::SSH::Any::Backend::_Cmd::DPipe);

sub _in { ${*{shift()}}{_ssha_be_in} }

for my $method (qw(syswrite print printf say)) {
    my $m = $method;
    no strict 'refs';
    *{$m} = sub { shift->_in->$m(@_) }
}

sub _upgrade_fh_to_dpipe {
    my ($class, $dpipe, $os, $any, $proc, $in) = @_;
    $class->SUPER::_upgrade_fh_to_dpipe($dpipe, $os, $any, $proc);
    bless $in, 'IO::Handle';
    ${*$dpipe}{_ssha_be_in} = $in;
    $dpipe;
}

sub _close_fhs {
    my $dpipe = shift;
    my $ok = $dpipe->send_eof;
    unless (close $dpipe) {
        $dpipe->_any->_set_error(SSHA_CHANNEL_ERROR, "unable to close dpipe reading side: $!");
        undef $ok;
    }
    return $ok;
}

sub send_eof {
    my $dpipe = shift;
    if (defined (my $in = delete ${*$dpipe}{_ssha_be_in})) {
        unless (close $in) {
            $dpipe->_any->_set_error(SSHA_CHANNEL_ERROR, "unable to close dpipe writing side: $!");
            return undef
        }
    }
    1
}

1;
