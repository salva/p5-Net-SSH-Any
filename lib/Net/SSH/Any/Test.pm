package Net::SSH::Any::Test;

use strict;
use warnings;

use Net::SSH::Any::Util qw(_array_or_scalar_to_list);
use Net::SSH::Any::_Base;
our @ISA = qw(Net::SSH::Any::_Base);

my @default_backends = qw(Remote OpenSSH);

sub new {
    my ($class, %opts) = @_;
    return $self->_new(\%opts);
}

sub _new {
    my ($class, $opts) = @_;
    my $test = $class->SUPER::_new($opts);

    $test->{timeout} = delete $opts->{timeout} // 10;
    $test->{port} = delete $opts->{port} // 22;
    $test->{user} = delete $opts->{user} // $self->_os_current_user;

    $test->{run_server} = delete $opts->{run_server} // 1;

    my @backends = _array_or_scalar_to_list(delete $opts->{backend} //
                                            delete $opts->{backends} //
                                            \@default_backends);
    $test->{backends} = \@backends;

    for my $backend (@backends) {
        if ($test->_load_backend_module(__PACKAGE__, $backend)) {
            if ($test->validate_backend_opts) {
                $test->start;
                $test;
            }
        }
    }
    $test->_set_error(SSHA_NO_BACKEND_ERROR, "no backend available");
    $test;
}

1;
