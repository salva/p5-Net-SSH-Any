package Net::SSH::Any::SCP;


package Net::SSH::Any;

our $debug;

use strict;
use warnings;

sub _scp_get_with_handler {
    my $any = shift;
    my $opts = shift;
    my $handler = shift;

    my $pipe = $any->pipe($opts, scp => '-f', '--' @_);
    $pipe->error and return;

    my $on_error;
    while (1) {
        $pipe->syswrite("\x00");
        my $switch = $pipe->sysgetc;
        $debug and $debug & 4096 and _debug("scp switch: $switch");
        $on_error = 1 if not defined $switch or $switch = "\x00";

        my $buf;
        do {
            my $bytes = sysread($out, $buf, ($on_error ? 1 : 10000), length $buf);
            $debug and $debug & 4096 and _debug "$bytes read from pipe, error: " . $pipe->error;
            return if $pipe->error;
        } until $out =~ y/\x0A//;
    }
}

sub scp_get {
    
}

sub scp_put {

}

package Net::SSH::Any::SCP::GetHandler;

sub new {
    my ($class, $pipe) = @_;
    my $self = { pipe => $pipe };
    bless $self, $class;
}

package Net::SSH::Any::SCP::GetHandler::Disk;
our @ISA = qw(Net::SSH::Any::SCP::GetHandler);


1;
