package Net::SSH::Any::Backend::_Cmd::Pipe;

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

sub _upgrade_fh_to_pipe {
    my ($class, $pipe, $os, $any, $proc) = @_;
    bless $pipe, $class;
    ${*$pipe}{_ssha_be_os} = $os;
    ${*$pipe}{_ssha_be_any} = $any;
    ${*$pipe}{_ssha_be_proc} = $proc;
    $pipe
}

sub close {
    my $pipe = shift;
    my $ok = 1;
    $pipe->_close_fhs or undef $ok;

    my $os = delete ${*$pipe}{_ssha_be_os};
    my $proc = delete ${*$pipe}{_ssha_be_proc};
    $os->wait_proc($pipe->_any, $proc) or undef $ok;
    return $ok;
}

sub error { shift->_any->error }

1;
