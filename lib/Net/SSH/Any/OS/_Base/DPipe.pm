package Net::SSH::Any::Backend::_Cmd::DPipe;

use strict;
use warnings;

use Net::SSH::Any::Constants ();
use Net::SSH::Any::Util qw($debug _debug _debug_hexdump);

require Net::SSH::Any::Backend::DPipe;
require IO::Handle;
our @ISA = qw(Net::SSH::Any::Backend::DPipe
              IO::Handle);

sub _any { ${*{shift()}}{_ssha_os_any} }
sub _proc { ${*{shift()}}{_ssha_os_proc} }

sub _upgrade_fh_to_dpipe {
    my ($class, $dpipe, $any, $proc) = @_;
    bless $dpipe, $class;
    ${*$dpipe}{_ssha_os_any} = $any;
    ${*$dpipe}{_ssha_os_proc} = $proc;
    $dpipe
}

sub close {
    my $dpipe = shift;
    my $ok = 1;
    $dpipe->_close_fhs or undef $ok;

    my $proc = delete ${*$dpipe}{_ssha_os_proc};
    $dpipe->_any->wait_proc($proc) or undef $ok;
    return $ok;
}

sub error { shift->_any->error }

1;
