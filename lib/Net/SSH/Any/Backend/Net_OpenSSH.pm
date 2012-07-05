package Net::SSH::Any::Backend::Net_OpenSSH;

use strict;
use warnings;

BEGIN { die "Net::OpenSSH does not work on Windows" if $^O =~ /Win(?:32|64)/ }

use Carp;
our @CARP_NOT = qw(Net::SSH::Any);

use Net::SSH::Any::Util;
use Net::SSH::Any::Constants qw(:error);
use Net::OpenSSH;
use Net::OpenSSH::Constants qw(:error);

sub _backend_api_version { 1 }

sub _connect {
    my $any = shift;
    my %opts = map { $_ => $any->{$_} } qw(host port user password passphrase key_path timeout);
    $opts{default_stdin_discard} = 1;
    # $opts{default_stdout_discard} = 1;
    # $opts{default_stderr_discard} = 1;
    if (my $extra = $any->{backend_opts}{$any->{backend}}) {
        @opts{keys %$extra} = values %$extra;
    }
    $any->{be_ssh} = Net::OpenSSH->new(%opts);
    __check_error($any);
}

sub __make_proxy_method {
    my $name = shift;
    my $sub = sub {
        my ($any, $opts, $cmd) = @_;
        my $ssh = __ssh($any) or return undef;
        if (wantarray) {
            my @r = $ssh->$name($opts, $cmd);
            __check_error($any);
            return @r;
        }
        else {
            my $r = $ssh->$name($opts, $cmd);
            __check_error($any);
            return $r;
        }
    };
    no strict 'refs';
    *{"_$name"} = $sub;
}

__make_proxy_method 'capture';
__make_proxy_method 'capture2';
__make_proxy_method 'system';

my @error_translation;
$error_translation[OSSH_MASTER_FAILED    ] = SSHA_CONNECTION_ERROR;
$error_translation[OSSH_SLAVE_FAILED     ] = SSHA_CHANNEL_ERROR;
$error_translation[OSSH_SLAVE_PIPE_FAILED] = SSHA_LOCAL_IO_ERROR;
$error_translation[OSSH_SLAVE_TIMEOUT    ] = SSHA_TIMEOUT_ERROR;
$error_translation[OSSH_SLAVE_CMD_FAILED ] = SSHA_REMOTE_CMD_ERROR;
$error_translation[OSSH_SLAVE_SFTP_FAILED] = SSHA_CHANNEL_ERROR;
$error_translation[OSSH_ENCODING_ERROR   ] = SSHA_ENCODING_ERROR;

sub __check_error {
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

sub __ssh {
    my $any = shift;
    my $ssh = $any->{be_ssh};
    $ssh and $ssh->wait_for_master and return $ssh;
    __check_error($any);
    undef;
}

1;
