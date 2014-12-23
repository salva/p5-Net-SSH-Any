package Net::SSH::Any::Backend::Sshg3_Cmd;

use strict;
use warnings;
use Carp;
use Net::SSH::Any::Util qw(_first_defined _array_or_scalar_to_list $debug _debug _debugf);
use Net::SSH::Any::Constants qw(SSHA_CONNECTION_ERROR SSHA_CHANNEL_ERROR SSHA_REMOTE_CMD_ERROR);

use parent 'Net::SSH::Any::Backend::_Cmd';

sub _validate_connect_opts {
    my ($any, %opts) = @_;

    defined $opts{host} or croak "host argument missing";

    $opts{local_sshg3_cmd} //=
        $any->_find_cmd(sshg3 => undef,
                        { POSIX => 'tectia',
                          MSWin => 'SSH Communications Security\\SSH Tectia\\SSH Tectia Client' });
    $opts{local_ssh_broker_g3_cmd} //=
        $any->_find_cmd('ssh-broker-g3', $opts{local_sshg3_cmd},
                        { POSIX => 'tectia',
                          MSWin => 'SSH Communications Security\\SSH Tectia\\SSH Tectia Broker' });

    my @auth_type;
    if (defined $opts{password}) {
        $any->{be_password_path} = # save it here to ensure it can be unlinked on destruction
            $any->_os_create_secret_file("sshg3-pwd.txt", $opts{password}) // return;
        push @auth_type, 'password';
    }
    elsif (defined (my $key = $opts{key_path})) {
        push @auth_type, 'publickey';
        croak "pubkey authentication not supported yet by Sshg3_Cmd backend";
    }

    # Work around bug on Tectia/Windows affecting only old Windows versions, apparently.
    my ($os, $mayor, $minor) = $any->_os_version;
    if ($os eq 'MSWin' and not $opts{exclusive}) {
        $debug and $debug & 1024 and _debug "OS version is $os $mayor.$minor";
        if ($mayor < 6 or ($mayor == 6 and $minor < 1)) { # < Win7
            $opts{exclusive} //= 1;
            $debug and $debug & 1024 and _debug($opts{exclusive}
                                                ? "Exclusive mode enabled"
                                                : "Exclusive mode disabled by user explicitly");
        }
        else {
            $debug and $debug & 1024 and _debug "Leaving exclusive mode disabled";
        }
    }

    $opts{run_broker} //= 0;

    $any->{be_connect_opts} = \%opts;
    $any->{be_auth_type} = join(',', @auth_type);
    $any->{be_interactive_login} = 0;

    if ($opts{run_broker}) {
        my $broker = $opts{local_ssh_broker_g3_cmd} //=
            $any->_find_cmd('ssh-broker-g3', $opts{local_sshg3_cmd},
                            { POSIX => 'tectia',
                              MSWin => 'SSH Communications Security\\SSH Tectia\\SSH Tectia Broker' });
        # FIXME: quote broker properly.
        system qq("$broker");
    }
    1;
}

sub _make_cmd {
    my ($any, $opts, $cmd) = @_;
    my $connect_opts = $any->{be_connect_opts};

    my @args = ( $connect_opts->{local_sshg3_cmd},
                 '-B', '-enone');

    push @args, '--exclusive' if $connect_opts->{exclusive};
    push @args, "-l$connect_opts->{user}" if defined $connect_opts->{user};
    push @args, "-p$connect_opts->{port}" if defined $connect_opts->{port};
    push @args, "-Pfile://$any->{be_password_path}" if defined $any->{be_password_path};

    push @args, _array_or_scalar_to_list($connect_opts->{sshg3_opts})
        if defined $connect_opts->{sshg3_opts};

    return (@args,
            ( delete $opts->{subsystem}
              ? (-s => $cmd, $connect_opts->{host})
              : ($connect_opts->{host}, $cmd)));
}

sub DESTROY {
    my $any = shift;
    if (defined(my $password_path = $any->{be_password_path})) {
        local $!;
        unlink $password_path;
    }
}

1;
