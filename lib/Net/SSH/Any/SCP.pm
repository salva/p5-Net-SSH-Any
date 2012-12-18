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
    require Net::SSH::Any::SCP::PutHandle::DiskLoader;
    my $h = Net::SSH::Any::SCP::PutHandle::DiskLoader->new($any, \%opts, \@_)
	or return;
    $any->scp_put_with_handler(\%opts, $h, @_);
}

1;
