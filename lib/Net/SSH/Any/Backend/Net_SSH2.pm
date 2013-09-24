package Net::SSH::Any::Backend::Net_SSH2;

use strict;
use warnings;

use Carp;
our @CARP_NOT = qw(Net::SSH::Any);

use Net::SSH::Any::Util qw($debug _debug _debug_hexdump _first_defined);
use Net::SSH::Any::Constants qw(:error);

use Net::SSH2;
use File::Spec;
use Errno ();
use Time::HiRes ();

use Config;
my %sig_name2num;
if (defined($Config{sig_name})) {
    my $i = 0;
    $sig_name2num{$_} = $i++ for split //, $Config{sig_name};
}

sub _sig_name2num {
    my $signal = shift;
    return 0 unless defined $signal and length $signal;
    my $num = $sig_name2num{$signal};
    (defined $num ? $num : 254);
}

sub _backend_api_version { 1 }

our ($block_inbound, $block_outbound, $eagain);
do {
    local ($@, $SIG{__DIE__});
    $block_inbound  = (eval { Net::SSH2::LIBSSH2_SOCKET_BLOCK_INBOUND()  } ||   1);
    $block_outbound = (eval { Net::SSH2::LIBSSH2_SOCKET_BLOCK_OUTBOUND() } ||   2);
    $eagain         = (eval { Net::SSH2::LIBSSH2_ERROR_EAGAIN()          } || -37);
};

sub __set_error_from_ssh_error_code {
    my ($any, $ssh_error_code, $error) = @_;
    $error = ($ssh_error_code == $eagain ? SSHA_EAGAIN : ($error || SSHA_CHANNEL_ERROR));
    $any->_set_error($error, "libssh2 error $ssh_error_code");
    return;
}

sub __copy_error {
    my $any = shift;
    my $ssh2 = $any->{be_ssh2}
        or die "internal error: __copy_error called, but there is no ssh2 object";
    my $error = $ssh2->error
        or die "internal error: __copy_error called, but there is no error";
    my $code = ($error == $eagain ? SSHA_EAGAIN : (shift || SSHA_CHANNEL_ERROR));
    $any->_set_error($code, ($ssh2->error)[2]);
    return;
}

sub _connect {
    my $any = shift;
    my $ssh2 = $any->{be_ssh2} = Net::SSH2->new;
    unless ($ssh2) {
        $any->_set_error(SSHA_CONNECTION_ERROR, "Unable to create Net::SSH2 object");
        return;
    }
    $debug and $debug & 2048 and $ssh2->trace(-1);

    my @args = ($any->{host}, $any->{port} || 22);
    push @args, Timeout => $any->{timeout} if defined $any->{timeout};
    $ssh2->connect(@args) or
        # return __copy_error($any, SSHA_CONNECTION_ERROR); # Net::SSH2::connect does not set error
        return $any->_set_error(SSHA_CONNECTION_ERROR, "Unable to connect to remote host");

    my %aa;
    $aa{username} = _first_defined($any->{user},
                                   eval { (getpwuid $<)[0] },
                                   eval { getlogin() });
    $aa{password} = $any->{password} if defined $any->{password};
    $aa{password} = $any->{passphrase} if defined $any->{passphrase};
    @aa{'privatekey', 'publickey'} = ($any->{key_path}, "$any->{key_path}.pub") if defined $any->{key_path};
    # TODO: use default user keys on ~/.ssh/id_dsa and ~/.ssh/id_rsa

    $ssh2->auth(%aa);
    unless ($ssh2->auth_ok) {
        $any->_set_error(SSHA_CONNECTION_ERROR, "Authentication failed");
        return;
    }

    my $bm = '';
    vec ($bm, fileno($ssh2->sock), 1) = 1;
    $any->{__select_bm} = $bm;
    1;
}

sub __open_file {
    my ($any, $name_or_args) = @_;
    my ($mode, @args) = (ref $name_or_args
			 ? @$name_or_args
			 : ('>', $name_or_args));
    if (open my $fh, $mode, @args) {
        return $fh;
    }
    $any->_set_error(SSHA_LOCAL_IO_ERROR, "Unable to open file '@args': $!");
    return undef;
}

sub __parse_fh_opts {
    my ($any, $opts, $channel) = @_;
    my @name = qw(stdout stderr);
    my @fh;
    for my $stream (qw(stdout stderr)) {
        my $fh = delete $opts->{"${stream}_fh"};
        unless ($fh) {
            my $file = ( delete($opts->{"stdout_discard"}) # first pass may delete element, second never does
                         ? File::Spec->devnull
                         : delete $opts->{"${stream}_file"} );
            if (defined $file) {
                $fh = __open_file($any, $file) or return;
            }
            if ($stream eq 'stderr' and not defined $fh) {
                if (delete $opts->{stderr_to_stdout}) {
                    $channel->ext_data('merge');
                }
                elsif (delete $opts->{stderr_discard}) {
                    $channel->ext_data('ignore');
                }
            }
        }
        push @fh, $fh;
    }
    grep /^std(?:out|err)_/, keys %$opts and
        croak "invalid option(s) '" . join("', '", grep /^std(?:out|err)_/, keys %$opts) . "'";
    return @fh;
}

sub __open_channel_and_exec {
    my ($any, $opts, $cmd) = @_;
    my $ssh2 = $any->{be_ssh2} or return;
    if (my $channel = $ssh2->channel) {
	my @fhs = __parse_fh_opts($any, $opts, $channel) or return;
	if ($channel->process((defined $cmd and length $cmd) 
			      ? ('exec' => $cmd)
			      : 'shell')) {
	    return ($channel, @fhs);
	}
    }
    __copy_error($any, SSHA_CHANNEL_ERROR);
    return;
}

sub _system {
    my ($any, $opts, $cmd) = @_;
    my ($channel, $out_fh, $err_fh) = __open_channel_and_exec($any, $opts, $cmd) or return;
    __io3($any, $channel, $opts->{timeout},
	  $opts->{stdin_data}, $out_fh || \*STDOUT, $err_fh || \*STDERR);
}

sub _capture {
    my ($any, $opts, $cmd) = @_;
    my ($channel, $out_fh, $err_fh) = __open_channel_and_exec($any, $opts, $cmd) or return;
    die 'Internal error: $out_fh is not undef' if $out_fh;
    (__io3($any, $channel, $opts->{timeout},
	   $opts->{stdin_data}, undef, $err_fh || \*STDERR))[0];
}

sub _capture2 {
    my ($any, $opts, $cmd) = @_;
    my ($channel, $out_fh, $err_fh) = __open_channel_and_exec($any, $opts, $cmd) or return;
    die 'Internal error: $out_fh is not undef' if $out_fh;
    die 'Internal error: $err_fh is not undef' if $err_fh;
    __io3($any, $channel, $opts->{timeout}, $opts->{stdin_data});
}

sub __write_all {
    my $any = shift;
    my $fh = shift;
    my $off = 0;
    while (length($_[0]) > $off) {
        if (my $bytes = syswrite $fh, $_[0], 40000, $off) {
            $off += $bytes;
        }
        elsif ($! == Errno::EAGAIN()) {
            select undef, undef, undef, 0.05;
        }
        else {
            $any->_set_error(SSHA_LOCAL_IO_ERROR, "Couldn't write to pipe", $!);
            return;
        }
    }
    return 1;
}

sub __check_channel_error_nb {
    my $any = shift;
    my $error = $any->{be_ssh2}->error;
    return 1 unless $error and $error != $eagain;
    __copy_error($any, SSHA_CHANNEL_ERROR);
}

sub __check_channel_error {
    my $any = shift;
    my $error = $any->{be_ssh2}->error;
    return 1 unless $error;
    __copy_error($any, SSHA_CHANNEL_ERROR);
}

sub _wait_for_more_data {
    my ($any, $timeout) = @_;
    my $ssh2 = $any->{be_ssh2};
    if (my $dir = $ssh2->block_directions) {
        my $wr = ($dir & $block_inbound  ? $any->{__select_bm} : '');
        my $ww = ($dir & $block_outbound ? $any->{__select_bm} : '');
        select($wr, $ww, undef, $timeout);
    }
}

sub __io3 {
    my ($any, $channel, $timeout, $stdin_data, @fh) = @_;
    my $ssh2 = $any->{be_ssh2} or return;
    $channel->blocking(0);
    my $in = '';
    my @cap = ('', '');
    my $eof_sent;
    $timeout = $any->{timeout} unless defined $timeout;
    my $start;
    while (1) {
        my $delay = 1;
        #$debug and $debug and 1024 and _debug("looping...");
        $in .= shift @$stdin_data while @$stdin_data and length $in < 36000;
        if (length $in) {
            my $bytes = $channel->write($in);
            if (not $bytes) {
                __check_channel_error_nb($any) or last;
            }
            elsif ($bytes < 0) {
                if ($bytes != $eagain) {
                    $any->_set_error(SSHA_CHANNEL_ERROR, $bytes);
                    last;
                }
            }
            else {
                $delay = 0;
                substr($in, 0, $bytes, '');
            }
        }
        elsif (!$eof_sent) {
            $channel->send_eof;
            $eof_sent = 1;
        }
        for my $ext (0, 1) {
            my $bytes = $channel->read(my($buf), 36000, $ext);
            if (not $bytes) {
                __check_channel_error_nb($any) or last;
            }
            elsif ($bytes < 0) {
                if ($bytes != $eagain) {
                    $any->_set_error(SSHA_CHANNEL_ERROR, $bytes);
                    last;
                }
            }
            else {
                $delay = 0;
                if ($fh[$ext]) {
                    __write_all($any, $fh[$ext], $buf) or last;
                }
                else {
                    $cap[$ext] .= $buf;
                }
            }
        }
        last if $channel->eof;

	if ($timeout) {
	    if ($delay) {
		my $now = Time::HiRes::time();
		$start ||= $now;
		if ($now - $start > $timeout) {
		    $any->_set_error(SSHA_TIMEOUT_ERROR, "command timed out");
		    last;
		}
	    }
	    else {
		undef $start;
	    }
	}

        $any->_wait_for_more_data(0.2) if $delay;
    }

    $channel->blocking(1);
    $channel->send_eof unless $eof_sent;
    $channel->wait_closed;

    my $code = $channel->exit_status || 0;
    my $signal = _sig_name2num($channel->exit_signal) || 0;

    $channel->close or __copy_error($any, SSHA_CONNECTION_ERROR);

    $? = (($code << 8) | $signal);
    return @cap;
}

sub _pipe {
    my ($any, $opts, $cmd) = @_;
    my ($channel) = __open_channel_and_exec($any, $opts, $cmd) or return;
    # TODO: do something with the parsed options?
    require Net::SSH::Any::Backend::Net_SSH2::Pipe;
    Net::SSH::Any::Backend::Net_SSH2::Pipe->_make($any, $channel);
}

sub _syswrite {
    my ($any, $channel) = @_;
    my $bytes = $channel->write($_[2]);
    if (not $bytes) {
        __check_channel_error($any) or return undef;
    }
    elsif ($bytes < 0) {
        __set_error_from_ssh_error_code($any, $bytes);
        return undef;
    }
    $bytes;
}

# appends at the end of $_[2] always!
sub _sysread {
    my ($any, $channel, undef, $len, $ext) = @_;
    $debug and $debug & 8192 and _debug("trying to read $len bytes from channel");
    my $bytes = $channel->read(my($buf), $len, $ext || 0);
    if (not $bytes) {
        __check_channel_error($any) or return undef;
    }
    elsif ($bytes < 0) {
        __set_error_from_ssh_error_code($any, $bytes);
        return undef;
    }
    else {
        $debug and $debug & 8192 and _debug_hexdump("data read", $buf);
        no warnings;
        $_[2] .= $buf;
    }
    $bytes;
}

sub _sftp {
    my ($any, $opts) = @_;
    my $ssh2 = $any->{be_ssh2} or return;
    $any->_load_module("Net::SFTP::Foreign::Backend::Net_SSH2") or return;
    my $sftp = Net::SFTP::Foreign->new(ssh2 => $ssh2,
                                       backend => 'Net_SSH2',
                                       autodisconnect => 2,
                                       %$opts);
    if ($sftp->error) {
        $any->_set_error(SSHA_CHANNEL_ERROR, $sftp->error);
    }
    $sftp;
}

1;
