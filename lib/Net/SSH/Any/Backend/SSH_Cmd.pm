package Net::SSH::Any::Backend::SSH_Cmd;

use strict;
use warnings;
use Carp;
use Net::SSH::Any::Util qw(_first_defined _array_or_scalar_to_list);
use Net::SSH::Any::Constants qw(SSHA_CHANNEL_ERROR SSHA_REMOTE_CMD_ERROR);
use parent 'Net::SSH::Any::Backend::_Cmd';

sub _validate_connect_opts {
    my ($any, %opts) = @_;

    $opts{local_ssh_cmd} //= $any->_find_cmd(ssh => undef, { MSWin => 'Cygwin' });

    defined $opts{host} or croak "host argument missing";
    my ($auth_type, $interactive_login);

    if (defined $opts{password}) {
        $auth_type = 'password';
        $interactive_login = 1;
        if (my @too_more = grep defined($opts{$_}), qw(key_path passphrase)) {
            croak "option(s) '".join("', '", @too_more)."' can not be used together with 'password'"
        }
    }
    elsif (defined $opts{key_path}) {
        $auth_type = 'publickey';
        if (defined $opts{passphrase}) {
            $auth_type .= ' with passphrase';
            $interactive_login = 1;
        }
    }
    else {
        $auth_type = 'default';
    }

    $any->{be_connect_opts} = \%opts;
    $any->{be_auth_type} = $auth_type;
    $any->{be_interactive_login} = $interactive_login;
    1;
}

sub _make_cmd {
    my ($any, $opts, $cmd) = @_;
    my $connect_opts = $any->{be_connect_opts};

    my @args = ( $connect_opts->{local_ssh_cmd},
                 $connect_opts->{host} );
    push @args, '-C';
    push @args, -l => $connect_opts->{user} if defined $connect_opts->{user};
    push @args, -p => $connect_opts->{port} if defined $connect_opts->{port};
    push @args, -i => $connect_opts->{key_path} if defined $connect_opts->{key_path};
    push @args, -o => 'BatchMode=yes' unless grep defined($connect_opts->{$_}), qw(password passphrase);
    push @args, -o => 'StrictHostKeyChecking=no' unless $connect_opts->{strict_host_key_checking};
    push @args, -o => "UserKnownHostsFile=$connect_opts->{known_hosts_path}"
        if defined $connect_opts->{known_hosts_path};

    if ($any->{be_auth_type} eq 'password') {
        push @args, ( -o => 'PreferredAuthentications=keyboard-interactive,password',
                      -o => 'NumberOfPasswordPrompts=1' );
    }
    else {
        push @args, -o => 'PreferredAuthentications=publickey';
    }

    push @args, '-s' if delete $opts->{subsystem};

    push @args, _array_or_scalar_to_list($connect_opts->{ssh_opts})
        if defined $connect_opts->{ssh_opts};

    return (@args, '--', $cmd);
}

sub _remap_child_error {
    my ($any, $proc) = @_;
    my $rc = $proc->{rc} // 0;
    if ($rc == (255 << 8)) {
        # A remote command may actually exit with code 255, but it
        # is quite uncommon.
        # SSHA_CONNECTION_ERROR is not recoverable so we use
        # SSHA_CHANNEL_ERROR instead.
        $any->_or_set_error(SSHA_CHANNEL_ERROR, "child command exited with code 255");
        return
    }
    1;
}

1;
