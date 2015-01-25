package Net::SSH::Any::Test::Backend::Remote;

use strict;
use warnings;

sub start_and_check {
    my $tssh = shift;

    for my $uri (@{$tssh->{uris}}) {
        $tssh->_check_and_set_uri($uri) and return 1;
        for my $key_path (@{$tssh->{key_paths}}) {
            my $uri2 = Net::SSH::Any::URI->new($uri->uri);
            $uri2->set(password => ());
            $uri2->set(key_path => $key_path);
            $tssh->_check_and_set_uri($uri2) and return 1;
        }
        for my $password (@{$tssh->{passwords}) {
            
        }
    }
}

sub start { 1 }

1;
