package Net::SSH::Any::Backend::SSH_Cmd;

use strict;
use warnings;
use Carp;
use Net::SSH::Any::Util qw(_first_defined _array_or_scalar_to_list);

use parent 'Net::SSH::Any::Backend::_Cmd';

sub _validate_connect_opts {
    my ($any, %opts) = @_;


    defined $opts{host} or croak "host argument missing";
    my $auth_type;

    if (defined $opts{password}) {
        $auth_type = 'password';
        if (my @too_more = grep defined($opts{$_}), qw(public_key passphrase)) {
            croak "option(s) '".join("', '", @too_more)."' can not be used together with 'password'"
        }
    }
    elsif (defined $opts{key_path}) {
        $auth_type = 'public_key';
        if (defined $opts{passphrase}) {
            $auth_type .= 'with passphrase';
        }
    }
    else {
        $auth_type = 'default';
    }

    $opts{auth_type} = $auth_type;
    $opts{local_ssh_cmd} = _first_defined $opts{local_ssh_cmd}, $any->{local_cmd}{ssh}, 'ssh';
    $any->{be_connect_opts} = \%opts;
    1;
}

sub _make_cmd {
    my ($any, $opts, $cmd) = @_;
    my $connect_opts = $any->{be_connect_opts};

    my @args = ( $connect_opts->{local_ssh_cmd},
                 $connect_opts->{host} );
    push @args, -l => $connect_opts->{user} if defined $connect_opts->{user};
    push @args, -p => $connect_opts->{port} if defined $connect_opts->{port};
    push @args, -i => $connect_opts->{key_path} if defined $connect_opts->{key_path};

    push @args, _array_or_scalar_to_list($connect_opts->{ssh_opts})
        if defined $connect_opts->{ssh_opts};

    return (@args, '--', $cmd);
}

1;
