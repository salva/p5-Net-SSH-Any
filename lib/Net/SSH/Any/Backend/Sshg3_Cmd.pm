package Net::SSH::Any::Backend::Sshg3_Cmd;

use strict;
use warnings;
use Carp;
use Net::SSH::Any::Util qw(_first_defined _array_or_scalar_to_list $debug _debug);
use Net::SSH::Any::Constants qw(SSHA_CONNECTION_ERROR SSHA_CHANNEL_ERROR SSHA_REMOTE_CMD_ERROR);

use parent 'Net::SSH::Any::Backend::_Cmd';

sub _validate_connect_opts {
    my ($any, %opts) = @_;


    $opts{local_sshg3_cmd} //=
        $any->_find_cmd(sshg3 => undef,
                        { POSIX => 'tectia',
                          MSWin => 'SSH Communications Security\\SSH Tectia\\SSH Tectia Client' });
    $opts{local_ssh_broker_g3_cmd} //=
        $any->_find_cmd('ssh-broker-g3', $opts{local_sshg3_cmd},
                        { POSIX => 'tectia',
                          MSWin => 'SSH Communications Security\\SSH Tectia\\SSH Tectia Broker' });

    defined $opts{host} or croak "host argument missing";

    my @auth_type;
    if (defined $opts{password}) {
        push @auth_type, 'password';
    }
    elsif (defined (my $key = $opts{key_path})) {
        push @auth_type, 'publickey';
        croak "pubkey authentication not support yet by Sshg3_Cmd backend";
    }

    # running in non-exclusive mode is unreliable :-(
    $opts{exclusive} //= 1;
    $opts{run_broker} //= 0;

    $any->{be_connect_opts} = \%opts;
    $any->{be_auth_type} = join(',', @auth_type);
    $any->{be_interactive_login} = 0;

    system qq("$opts{local_ssh_broker_g3_cmd}") if $opts{run_broker};

    1;
}

sub _make_cmd {
    my ($any, $opts, $cmd) = @_;
    my $connect_opts = $any->{be_connect_opts};

    my @args = ( $connect_opts->{local_sshg3_cmd},
                 '-B', '-enone', '-q');

    push @args, '--exclusive' if $connect_opts->{exclusive};

    push @args, "-l$connect_opts->{user}" if defined $connect_opts->{user};
    push @args, "-p$connect_opts->{port}" if defined $connect_opts->{port};
    push @args, "-P$connect_opts->{password}" if defined $connect_opts->{password};
    push @args, _array_or_scalar_to_list($connect_opts->{sshg3_opts})
        if defined $connect_opts->{sshg3_opts};

    return (@args,
            ( delete $opts->{subsystem}
              ? (-s => $cmd, $connect_opts->{host})
              : ($connect_opts->{host}, $cmd)));
}

1;
