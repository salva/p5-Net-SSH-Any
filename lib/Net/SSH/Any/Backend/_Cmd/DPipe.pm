package Net::SSH::Any::Backend::_Cmd::DPipe;

use strict;
use warnings;

use Net::SSH::Any::Constants ();
use Net::SSH::Any::Util qw($debug _debug _debug_hexdump);

require IO::Handle;
our @ISA = qw(IO::Handle);

use Data::Dumper;

sub _os { ${*{shift()}}{_ssha_be_os} }
sub _any { ${*{shift()}}{_ssha_be_any} }
sub _proc { ${*{shift()}}{_ssha_be_proc} }

sub _upgrade_fh_to_dpipe {
    my ($class, $dpipe, $os, $any, $proc) = @_;
    bless $dpipe, $class;
    ${*$dpipe}{_ssha_be_os} = $os;
    ${*$dpipe}{_ssha_be_any} = $any;
    ${*$dpipe}{_ssha_be_proc} = $proc;
    $dpipe
}

sub close {
    my $dpipe = shift;
    my $ok = 1;
    $dpipe->_close_fhs or undef $ok;

    my $os = delete ${*$dpipe}{_ssha_be_os};
    my $proc = delete ${*$dpipe}{_ssha_be_proc};
    $os->wait_proc($dpipe->_any, $proc) or undef $ok;
    return $ok;
}

sub error { shift->_any->error }

1;
