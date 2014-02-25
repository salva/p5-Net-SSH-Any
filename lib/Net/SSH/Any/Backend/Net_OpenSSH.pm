package Net::SSH::Any::Backend::Net_OpenSSH;

use strict;
use warnings;

BEGIN { die "Net::OpenSSH does not work on Windows" if $^O =~ /Win32|Win64|Cygwin/i }

use Carp;
our @CARP_NOT = qw(Net::SSH::Any);

use Net::SSH::Any::Util;
use Net::SSH::Any::Constants qw(:error);
use Net::OpenSSH;
use Net::OpenSSH::Constants qw(:error);

sub _backend_api_version { 1 }

sub _connect {
    my $any = shift;
    my %opts;
    for (qw(host port user password passphrase key_path timeout)) {
        if (defined(my $v = $any->{$_})) {
            $opts{$_} = $v;
        }
    }
    $opts{default_stdin_discard} = 1;
    # $opts{default_stdout_discard} = 1;
    # $opts{default_stderr_discard} = 1;
    if (my $extra = $any->{backend_opts}{$any->{backend}}) {
        @opts{keys %$extra} = values %$extra;
    }
    my $master_opts = [_array_or_scalar_to_list delete $opts{master_opts}];
    push @$master_opts, ('-o', 'StrictHostKeyChecking='.($any->{strict_host_key_checking} ? 'yes' : 'no'));
    push @$master_opts, ('-o', "UserKnownHostsFile=$any->{known_hosts_path}")
        if defined $any->{known_hosts_path};
    $opts{master_opts} = $master_opts;

    $any->{be_ssh} = Net::OpenSSH->new(%opts);
    __check_error($any);
}

sub __make_proxy_method {
    my $name = shift;
    my $sub = sub {
        my ($any, $opts, $cmd) = @_;
        my $ssh = __ssh($any) or return;
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

sub _capture {
    my ($any, $opts, $cmd) = @_;
    my $ssh = __ssh($any) or return;
    # Net::OpenSSH capture has to be called in scalar context
    my $out = $ssh->capture($opts, $cmd);
    __check_error($any);
    return $out;
}

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

sub _pipe {
    my ($any, $opts, $cmd) = @_;
    my $ssh = __ssh($any) or return undef;
    my ($socket, $pid) = $ssh->open2socket($opts, $cmd);
    __check_error($any) or return;
    require Net::SSH::Any::Backend::_Cmd::Pipe;
    Net::SSH::Any::Backend::_Cmd::Pipe->_upgrade_socket($socket, $pid, $any);
}

sub _sftp {
    my ($any, $opts) = @_;
    my $ssh = __ssh($any) or return undef;
    my $sftp = $ssh->sftp(%$opts);
    __check_error($any);
    return $sftp;
}

sub _waitpid {
    my ($any, $pid) = @_;
    $any->{be_ssh}->_waitpid($pid);
    __check_error($any);
}

1;
