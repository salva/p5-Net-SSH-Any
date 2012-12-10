package Net::SSH::Any::SCP::GetHandler;

use strict;
use warnings;

use Net::SSH::Any::Util qw($debug _debug _first_defined);

require Net::SSH::Any::SCP::Handler;
our @ISA = qw(Net::SSH::Any::SCP::Handler);

for my $method (qw(on_file on_data on_end_of_file on_dir on_end_of_dir on_end_of_get)) {
    no strict;
    *{$method} = sub {
        if ($debug and $debug and 4096) {
            my $args = (@_ == 4                ? "perm: $_[1], size: $_[2], name: $_[3]" :
                        $method eq 'on_data'   ? length($_[1]) . " bytes"                :
                        '' );
            Net::SSH::Any::_debug "called $_[0]->$method($args)";
        }
    };
}

sub on_remote_error {
    my ($h, $path, $error) = @_;
    $debug and $debug & 4096 and Net::SSH::Any::_debug("$h->on_remote_error(path: $path, error: $error)");
    $h->_push_action( type => 'remote_error',
                      remote => $path,
                      error => $error );
    1
}

sub on_matime {
    my ($h, $mtime, $atime) = @_;
    $debug and $debug & 4096 and Net::SSH::Any::_debug("$h->on_matime($mtime, $atime)");
    $h->{mtime} = $mtime;
    $h->{atime} = $atime;
    1;
}

1;
