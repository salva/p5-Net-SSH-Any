package Net::SSH::Any::Expecter;

use strict;
use warnings;

use Carp;
our @CARP_NOT = qw(Net::SSH::Any);

sub _new {
    my ($class, $any, $dpipe, %opts) = @_;
    my $self = { any => $any, dpipe => $dpipe, opts => \%opts };
    bless $self, $class;
    $self;
}



1;
