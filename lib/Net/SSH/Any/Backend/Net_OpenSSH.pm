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

sub _backend_api_version { 1 }

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

sub _validate_connect_opts {
    my ($any, %opts) = @_;
    my $instance = delete $opts{instance};
    unless (defined $instance) {
        my @master_opts = _array_or_scalar_to_list delete $opts{master_opts};
        my $strict_host_key_checking = delete $opts{strict_host_key_checking};
        push @master_opts, -o => 'StrictHostKeyChecking='.($strict_host_key_checking ? 'yes' : 'no');
        my $known_hosts_path = delete $opts{known_hosts_path};
        push @master_opts, -o => "UserKnownHostsFile=$known_hosts_path"
            if defined $known_hosts_path;
        $instance = Net::OpenSSH->new(map({ defined $opts{$_} ? ( $_ => $opts{$_}) : () } keys %opts),
                                master_opts => \@master_opts);
    }
    $any->{be_ssh} = $instance;
    __check_and_copy_error($any);
}

sub _make_cmd { shift->{be_ssh}->make_remote_command(@_) }

sub _check_connection {
    my $any = shift;
    $any->{be_ssh}->wait_for_master;
    __check_and_copy_error($any);
}

1;
