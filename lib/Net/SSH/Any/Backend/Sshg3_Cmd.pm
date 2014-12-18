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

    system qq("$opts{local_ssh_broker_g3_cmd}") if $opts{run_broker};

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
    if (defined $connect_opts->{password}) {
        # push @args, "-P$connect_opts->{password}";
        # push @args, "-Pfile://$opts->{password_path}";
        
        #push @args, qq|-Pextprog://$^X -MNet::SSH::Any::Backend::Ssshg3_Cmd::Helper=|;
        push @args, qq{-Pextprog://$^X -eprint(q{$connect_opts->{password}})};
    }
    #if (defined $connect_opts->{password}) {
    #    push @args, "-Pextprog://echo $connect_opts->{password}"
    #}

    push @args, _array_or_scalar_to_list($connect_opts->{sshg3_opts})
        if defined $connect_opts->{sshg3_opts};

    return (@args,
            ( delete $opts->{subsystem}
              ? (-s => $cmd, $connect_opts->{host})
              : ($connect_opts->{host}, $cmd)));
}

 # my $pipe_ix = 0;
 # sub _run_cmd {
 #     my ($any, $opts, $cmd) = @_;
 #     my $connect_opts = $any->{be_connect_opts};
 #     if ($any->{be_auth_type} =~ /\bpassword\b/) {
 #         require Win32::Pipe;
 #         my $pn = "lib-net-ssh-any-perl-pipe-$$-".($pipe_ix++);
 #         my $pipe = Win32::Pipe->new($pn) or croak "unable to create pipe";
 #         $opts->{password_path} = "//./pipe/$pn";
 #         #$opts->{password_path} = $pn;
 #         $debug and $debug & 1024 and _debug "pipe created";
 #         #open my $read, "<", $opts->{password_path} or croak "unable to open pipe";
 #         #$debug and $debug & 1024 and _debug "pipe open for reading";
 #         my @r = $any->SUPER::_run_cmd($opts, $cmd);
 #         $debug and $debug & 1024 and _debug "waiting for slave process to connect to pipe...";
 #         $pipe->Connect;
 #         $debug and $debug & 1024 and _debug "connected!";
 #         print $pipe->Write("$connect_opts->{password}\n");
 #         #print scalar(<$read>);
 #         $debug and $debug & 1024 and _debug "disconnecting";
 #         $pipe->Disconnect;
 #         undef $pipe;
 #         #$| = 1;
 #         #$debug and $debug & 1024 and _debug "reading from pipe";
 #         #print STDERR while <$read>;
 #         return @r;
 #     }
 #     else {
 #         return $any->SUPER::_run_cmd($opts, $cmd);
 #     }
 # }

1;
