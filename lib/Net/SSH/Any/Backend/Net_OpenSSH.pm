package Net::SSH::Any::Backend::Net_OpenSSH;

use strict;
use warnings;

BEGIN { die "Net::OpenSSH does not work on Windows" if $^O =~ /Win32|Win64|Cygwin/i }

use Carp;
our @CARP_NOT = qw(Net::SSH::Any);

require Net::SSH::Any::Backend::_Cmd;
our @ISA = qw(Net::SSH::Any::Backend::_Cmd);

use Net::SSH::Any::Util;
use Net::SSH::Any::Constants qw(:error);
use Net::OpenSSH;
use Net::OpenSSH::Constants qw(:error);

sub _backend_api_version { 2 }

my @error_translation;
$error_translation[OSSH_MASTER_FAILED    ] = SSHA_CONNECTION_ERROR;
$error_translation[OSSH_SLAVE_FAILED     ] = SSHA_CHANNEL_ERROR;
$error_translation[OSSH_SLAVE_PIPE_FAILED] = SSHA_LOCAL_IO_ERROR;
$error_translation[OSSH_SLAVE_TIMEOUT    ] = SSHA_TIMEOUT_ERROR;
$error_translation[OSSH_SLAVE_CMD_FAILED ] = SSHA_REMOTE_CMD_ERROR;
$error_translation[OSSH_SLAVE_SFTP_FAILED] = SSHA_CHANNEL_ERROR;
$error_translation[OSSH_ENCODING_ERROR   ] = SSHA_ENCODING_ERROR;

sub __check_and_copy_error {
    my $any = shift;
    if (my $ssh = $any->{be_ssh}) {
        my $error = $ssh->error or return 1;
        $any->_set_error($error_translation[$error] // SSHA_CHANNEL_ERROR, $error);
    }
    else {
        $any->_set_error(SSHA_CONNECTION_ERROR, "Unable to create Net::OpenSSH object");
    }
    return;
}

sub _validate_backend_opts {
    my $any = shift;

    $any->SUPER::_validate_backend_opts or return;

    my $be = $any->{be};
    my $instance = $be->{instance} // do {
        $be->{local_ssh_cmd} //= $any->_find_cmd('ssh', $be->{ssh_cmd}, 'OpenSSH') // return;

        my @master_opts = _array_or_scalar_to_list $be->{master_opts};
        my $shkc = ($be->{strict_host_key_checking} ? 'yes' : 'no');
        push @master_opts, -o => "StrictHostKeyChecking=$shkc";
        push @master_opts, -o => "UserKnownHostsFile=$be->{known_hosts_path}"
            if defined $be->{known_hosts_path};
        push @master_opts, '-C' if $be->{compress};

        my %args = (master_opts => \@master_opts,
                    ssh_cmd => $be->{local_ssh_cmd} );

        for (qw(host port user password passphrase key_path timeout
                batch_mode)) {
            $args{$_} = $be->{$_} if defined $be->{$_};
        }

        for (qw(rsync sshfs scp)) {
            $args{"${_}_cmd"} = $be->{"local_${_}_cmd"} //=
                $any->_find_cmd({relaxed => 1}, $_, $be->{ssh_cmd}, 'OpenSSH');
        }

        Net::OpenSSH->new(%args, connect => 0);
    };

    $any->{be_ssh} = $instance;
    __check_and_copy_error($any);
}

sub _make_cmd { shift->{be_ssh}->make_remote_command(@_) }

sub _check_connection {
    my $any = shift;
    $any->{be_ssh}->wait_for_master;
    __check_and_copy_error($any);
}

sub _connect { shift->_check_connection }



1;

__END__

=head1 NAME

Net::SSH::Any::Backend::Net_OpenSSH

=head1 DESCRIPTION

Custom options supported by this backend:

=over 4

=item instance => $instance

Instead of creating a new Net::OpenSSH reuses the one given.

Example:

  my $ssh = Net::OpenSSH->new($target, ...);

  my $assh = Net::SSH::Any->new($target,
                                backend => 'Net_OpenSSH',
                                backend_opts => {
                                    Net_OpenSSH => { instance => $ssh }
                                } );


=item master_opts => \@master_opts

...

=back

=cut
