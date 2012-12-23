package Net::SSH::Any::SCP;

use Net::SSH::Any;
package Net::SSH::Any;

use strict;
use warnings;
use Fcntl ();

our $debug;


sub scp_get {
    my $any = shift;
    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());
    require Net::SSH::Any::SCP::Getter::Standard;
    my $g = Net::SSH::Any::SCP::Getter::Standard->_new($any, \%opts, @_)
 	or return;
    $g->run(\%opts);
}


sub scp_put {
    my $any = shift;
    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());
    require Net::SSH::Any::SCP::Putter::Standard;
    my $p = Net::SSH::Any::SCP::Putter::Standard->_new($any, \%opts, @_)
	or return;
    $p->run(\%opts);
}

1;
