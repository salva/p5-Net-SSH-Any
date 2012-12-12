package Net::SSH::Any::SCP::PutHandle;

use strict;
use warnings;

use Net::SSH::Any::Util qw($debug _debug _first_defined);

require Net::SSH::Any::SCP::Handle;
our @ISA = qw(Net::SSH::Any::SCP::Handle);

sub on_next {}

sub on_send_data {}

sub on_end_of_file {}

1;
