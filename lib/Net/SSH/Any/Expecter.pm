package Net::SSH::Any::Expecter;

use strict;
use warnings;

use Carp;
our @CARP_NOT = qw(Net::SSH::Any);

sub _new {
    my ($class, $any, $dpipe, %opts) = @_;
    my $self = { any => $any, dpipe => $dpipe, bin => '', opts => \%opts };
    bless $self, $class;
    $self;
}

sub dpipe { shift->{dpipe} }

sub expect {
    my $self = shift;
    my $timeout = shift;

    my @matchers = $self->_parse_matchers(@_);

    while (1) {
        for my $matcher (@matchers) {
            my ($action, $match) = $
        }
    }
    
}

1;
