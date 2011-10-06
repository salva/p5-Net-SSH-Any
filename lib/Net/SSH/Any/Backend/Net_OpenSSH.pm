package Net::SSH::Any::Backend::Net_OpenSSH;

use strict;
use warnings;

use Net::SSH::Any::Util;
use Net::SSH::Any::Constants qw(:error);
use Net::OpenSSH;
use Net::OpenSSH::Constants qw(:error);

sub _connect {
    my $self = shift;
    my %opts = map { $_ => $self->{$_} } qw(host port user passwd passphrase key_path timeout);
    $opts{default_stdin_discard} = 1;
    $opts{default_stdout_discard} = 1;
    $opts{default_stderr_discard} = 1;
    if (my $extra = $self->{backend_opts}{$self->{backend}}) {
        @opts{keys %$extra} = values %$extra;
    }
    $self->{be_ssh} = Net::OpenSSH->new(%opts);
    $self->_be_check_error;
}

sub _make_proxy_method {
    my $name = shift;
    my $sub = sub {
        my ($self, $opts, $cmd) = @_;
        my $ssh = $self->_be_ssh or return undef;
        if (wantarray) {
            my @r = $ssh->$name($opts, $cmd);
            $self->_be_check_error;
            return @r;
        }
        else {
            my $r = $ssh->$name($opts, $cmd);
            $self->_be_check_error;
            return $r;
        }
    };
    no strict 'refs';
    *{"_$name"} = $sub;
}

_make_proxy_method 'capture';
_make_proxy_method 'capture2';
_make_proxy_method 'system';

my @error_tr;
$error_tr[OSSH_MASTER_FAILED    ] = SSHA_CONNECTION_ERROR;
$error_tr[OSSH_SLAVE_FAILED     ] = SSHA_CHANNEL_ERROR;
$error_tr[OSSH_SLAVE_PIPE_FAILED] = SSHA_CHANNEL_ERROR;
$error_tr[OSSH_SLAVE_TIMEOUT    ] = SSHA_TIMEOUT_ERROR;
$error_tr[OSSH_SLAVE_CMD_FAILED ] = SSHA_REMOTE_CMD_ERROR;
$error_tr[OSSH_SLAVE_SFTP_FAILED] = SSHA_CHANNEL_ERROR;
$error_tr[OSSH_ENCODING_ERROR   ] = SSHA_ENCODING_ERROR;

sub _be_check_error {
    my $self = shift;
    my $ssh = $self->{be_ssh} or die "Internal error: be_ssh is undefined";
    my $be_error = $ssh->error or return 1;
    $self->_set_error($error_tr[$be_error] || SSHA_CHANNEL_ERROR, $be_error);
    return undef
}

sub _be_ssh {
    my $self = shift;
    my $ssh = $self->{be_ssh} or die "Internal error: be_ssh is undefined";
    $ssh->wait_for_master and return $ssh;
    $ssh->_be_check_error;
    undef;
}

sub _backend_api_version { 1 }

1;
