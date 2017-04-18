package Net::SSH::Any::Backend::Sshg3_Cmd;

use strict;
use warnings;
use Carp;
use Net::SSH::Any::Util qw(_first_defined _array_or_scalar_to_list $debug _debug _debugf _debug_dump);
use Net::SSH::Any::Constants qw(SSHA_CONNECTION_ERROR SSHA_CHANNEL_ERROR SSHA_REMOTE_CMD_ERROR);

use parent 'Net::SSH::Any::Backend::_Cmd';

sub _validate_backend_opts {
    my $any = shift;

    $any->SUPER::_validate_backend_opts or return;

    my $be = $any->{be};

    defined $be->{host} or croak "host argument missing";

    $be->{local_sshg3_cmd} //=
        $any->_find_cmd(sshg3 => undef,
                        { POSIX => 'tectia',
                          MSWin => 'SSH Communications Security\\SSH Tectia\\SSH Tectia Client' }) // return;
    my $out = $any->_local_capture($be->{local_sshg3_cmd}, '-V');
    if ($?) {
        $any->_set_error(SSHA_CONNECTION_ERROR, 'sshg3 not found or bad version, rc: ', ($? >> 8));
        return;
    }
    my $out = $any->_local_capture($be->{local_sshg3_cmd});
    if ($out =~ /No valid license files are installed./) {
        $any->_set_error(SSHA_CONNECTION_ERROR, 'missing license for sshg3, rc: ', ($? >> 8));
        return;
    }

    $be->{run_broker} //= 0;

    if ($be->{run_broker}) {
        $be->{local_ssh_broker_g3_cmd} //=
            $any->_find_cmd('ssh-broker-g3', $be->{local_sshg3_cmd},
                            { POSIX => 'tectia',
                              MSWin => 'SSH Communications Security\\SSH Tectia\\SSH Tectia Broker' }) // return;
    }

    $be->{local_sshg3_extra_args} = $any->_find_local_extra_args(sshg3 => $be);
    $be->{local_ssh_broker_g3_extra_args} = $any->_find_local_extra_args(ssh_broker_g3 => $be);

    my @auth_type;
    if (defined $be->{password}) {
        $any->{be_password_path} = # save it here to ensure it can be unlinked on destruction
            $any->_os_create_secret_file("sshg3-pwd.txt", $be->{password}) // return;
        push @auth_type, 'password';
    }
    elsif (defined (my $key = $be->{key_path})) {
        push @auth_type, 'publickey';
        # croak "pubkey authentication not supported yet by Sshg3_Cmd backend";
    }

    if (delete $be->{strict_host_key_checking}) {
        $be->{hostkey_policy} = 'strict';
    }
    else {
        my $known_hosts_path = delete $be->{known_hosts_path};
        if (defined $known_hosts_path and $known_hosts_path eq '/dev/null') {
            $be->{hostkey_policy} = 'advisory';
        }
        else {
            $be->{hostkey_policy} = 'tofu';
        }
    }

    # Work around bug on Tectia/Windows affecting only old Windows versions, apparently.
    my ($os, $mayor, $minor) = $any->_os_version;
    if ($os eq 'MSWin' and not $be->{exclusive}) {
        $debug and $debug & 1024 and _debug "OS version is $os $mayor.$minor";
        if ($mayor < 6 or ($mayor == 6 and $minor < 1)) { # < Win7
            $be->{exclusive} //= 1;
            $debug and $debug & 1024 and _debug($be->{exclusive}
                                                ? "Exclusive mode enabled"
                                                : "Exclusive mode disabled by user explicitly");
        }
        else {
            $debug and $debug & 1024 and _debug "Leaving exclusive mode disabled";
        }
    }

    $debug and $debug & 1024 and _debug_dump be => $be;

    $any->{be_auth_type} = join(',', @auth_type);
    $any->{be_interactive_login} = 0;

    1;
}

sub _connect{
    my $any = shift;
    my $be = $any->{be};

    if ($be->{run_broker}) {
        if (defined (my $broker = $be->{local_ssh_broker_g3_cmd})) {
            local $?; # ignore errors here;
            my @args = @{$be->{local_ssh_broker_g3_extra_args}};
            push @args, -a => $be->{broker_address}
                if defined $be->{broker_address};
            system $broker $broker, @args;
        }
    }
    1;
}

sub _make_cmd {
    my ($any, $cmd_opts, $cmd) = @_;
    my $be = $any->{be};

    # FIXME: the environment variable should only be set when running
    # the sshg3 command, not globally!
    if (defined (my $broker_address = $be->{broker_address})) {
        $any->_os_setenv(SSH_SECSH_BROKER => $broker_address);
    }

    my @args = ( $be->{local_sshg3_cmd},
                 @{$be->{local_sshg3_extra_args}},
                 '-B', '-enone', '-q',
                 "--hostkey-policy=$be->{hostkey_policy}");

    push @args, '--exclusive' if $be->{exclusive};
    push @args, "-l$be->{user}" if defined $be->{user};
    push @args, "-p$be->{port}" if defined $be->{port};
    push @args, "-Pfile://$any->{be_password_path}" if defined $any->{be_password_path};
    push @args, "-K$be->{key_path}" if defined $be->{key_path};

    return (@args,
            ( delete $cmd_opts->{subsystem}
              ? (-s => $cmd, $be->{host})
              : ($be->{host}, $cmd)));
}

sub DESTROY {
    my $any = shift;
    if (defined(my $password_path = $any->{be_password_path})) {
        local $!;
        unlink $password_path;
    }
}

1;

__END__

=head1 NAME

Net::SSH::Any::Backend::Sshg3_Cmd - Backend for Tectia sshg3 client

=head1 SYNOPSIS

  use Net::SSH::Any;
  my $ssh = Net::SSH::Any->new($host, user => $user, password => $password,
                               backend => 'Sshg3_Cmd');
  $ssh->die_on_error("Unable to start SSH");
  my $output = $ssh->capture("echo hello world");

=head1 DESCRIPTION

This module implements a Net::SSH::Any backend using the C<sshg3>
utility distributed as part of the L<Tectia
SSH|http://www.ssh.com/products/tectia-ssh> package.

Note that Tectia SSH is not Open Source or Free Software. If you want
to use it you will have to buy a license from some distributor.

This backend supports password authentication in a secure way*.

Currently, the feature set of this backend is similar to that of the
other backends but it should be possible to add support for other
features specific to the Tectia software. Get in touch with me in case
you need any of them.

The set of options currently supported is as follows:

=over 4

=item local_sshg3_cmd

=item local_ssh_broker_g3_cmd

=item exclusive


=back

=cut
