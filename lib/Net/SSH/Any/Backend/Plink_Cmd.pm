package Net::SSH::Any::Backend::Plink_Cmd;

use strict;
use warnings;
use Carp;
use Net::SSH::Any::Util qw(_first_defined _array_or_scalar_to_list);
use Net::SSH::Any::Constants qw(SSHA_CONNECTION_ERROR);

use parent 'Net::SSH::Any::Backend::_Cmd';

sub _validate_connect_opts {
    my ($any, %opts) = @_;


    defined $opts{host} or croak "host argument missing";
    my ($auth_type, $interactive_login);

    if (defined $opts{password}) {
        $auth_type = 'password';
        if (my @too_more = grep defined($opts{$_}), qw(key_path passphrase)) {
            croak "option(s) '".join("', '", @too_more)."' can not be used together with 'password'"
        }
    }
    elsif (defined (my $key = $opts{key_path})) {
        $auth_type = 'publickey';
        my $ppk = "$key.ppk";
        $opts{ppk_path} = $ppk;
        unless (-e $ppk) {
            local $?;
            my $cmd = _first_defined $opts{local_puttygen_cmd},
                $any->{local_cmd}{puttygen}, 'puttygen';
            unless (system($cmd, -O 'private', -o => $ppk, $key)) {
                $any->_set_error(SSHA_CONNECTION_ERROR, 'puttygen failed, rc: ' . ($? >> 8));
                return
            }
        }
    }
    else {
        $auth_type = 'default';
    }

    $opts{local_plink_cmd} = _first_defined $opts{local_plink_cmd}, $any->{local_cmd}{plink}, 'plink';
    $any->{be_connect_opts} = \%opts;
    $any->{be_auth_type} = $auth_type;
    $any->{be_interactive_login} = 0;
    1;
}

sub _make_cmd {
    my ($any, $opts, $cmd) = @_;
    my $connect_opts = $any->{be_connect_opts};

    my @args = ( $connect_opts->{local_plink_cmd},
                 '-ssh',
                 '-batch',
                 '-C' );

    push @args, -l => $connect_opts->{user} if defined $connect_opts->{user};
    push @args, -P => $connect_opts->{port} if defined $connect_opts->{port};
    push @args, -i => $connect_opts->{ppk_path} if defined $connect_opts->{ppk_path};

    if ($any->{be_auth_type} eq 'password') {
        push @args, -pw => $connect_opts->{password};
    }

    push @args, _array_or_scalar_to_list($connect_opts->{plink_opts})
        if defined $connect_opts->{plink_opts};

    push @args, '-s' if delete $opts->{subsystem};
    push @args, $connect_opts->{host};

    return (@args, $cmd);
}

1;
