package Net::SSH::Any::Test::Backend::Remote;

use strict;
use warnings;

sub validate_backend_opts {
    my $any = shift;
    if (defined $any->{password}) {
        
    }
}

sub start { 1 }

1;
