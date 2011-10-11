package Net::SSH::Any::Backend::Net_SSH2;

use strict;
use warnings;

use Net::SSH::Any::Util;
use Net::SSH::Any::Constants qw(:error);

use Net::SSH2;

sub _connect {
    my $self = shift;
    my $ssh2 = $self->{be_ssh2} = Net::SSH2->new();

    my @conn_args = @{$self}{qw(host port)};
    push @conn_args, Timeout => $self->{timeout} if defined $self->{timeout};
    $ssh2->connect(@conn_args);
    if ($self->error) {
        $self->_set_error(SSHA_CONNECITON_ERROR, ($ssh2->error)[2]);
        return
    }

    my ($user, $passwd, $passphrase, $key_path) = @{$self}{qw(user passwd passphrase key_path)};
    my @auth_args;
    push @auth_args, username => $self->{user} if defined $self->{user};
    push @auth_args, password => $self->{passwd} if defined $self->{passwd};
    push @auth_args, privatekey => $self->{key_path}, publickey => $self->{key_path}.".pub"
        if defined $self->{key_path};
    # TODO: use default user keys on ~/.ssh/id_dsa and ~/.ssh/id_rsa

    if ($self->error) {
        $self->_set_error(SSHA_AUTHENTICATION_ERROR, ($ssh2->error)[2]);
        return;
    }

}
