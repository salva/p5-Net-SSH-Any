package Net::SSH::Any::Test::Backend::OpenSSH_Daemon;

use strict;
use warnings;

use Net::SSH::Any;
use Net::SSH::Any::Constants qw();

sub start_and_check {
    my $tssh = shift;

    unless ($sshd->{run_server}) {
        $tssh->_log("Skipping OpenSSH_Daemon backend as run_server is unset");
        return
    }

    my $wdir = $tssh->_backend_wd // return;
    ()
}




1;
