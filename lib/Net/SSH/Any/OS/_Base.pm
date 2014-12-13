package Net::SSH::Any::OS::_Base;

use strict;
use warnings;

use Carp;
our @CARP_NOT = ('Net::SSH::Any::Backend::_Cmd');

use Net::SSH::Any::Util qw($debug _debug _array_or_scalar_to_list);
use Net::SSH::Any::Constants qw(:error);

sub loaded { 1 } # helper method to ensure the module has been correctly loaded

sub pty {
    my ($os, $any) = @_;
    $any->_load_module('IO::Pty') or return;
    IO::Pty->new;
}

sub unset_pipe_inherit_flag { 1 }

sub has_working_socketpair { }

sub io3_check_and_clean_data {
    my ($any, $in, $data) = @_;
    my @data = grep { defined and length } _array_or_scalar_to_list $data;
    if (@data and not $in) {
        croak "remote input channel is not defined but data is available for sending"
    }
    \@data
}

sub export_proc {
    my ($any, $proc) = @_;
    $proc->{pid}
}

sub run_cmd {
    my ($any, $opts, $cmd) = @_;

    my $data = $opts->{stdin_data};
    $opts->{stdin_pipe} = 1 if defined $data;

    my $dpipe = delete $opts->{stdinout_dpipe};
    if ($dpipe) {
        if ($any->_os_has_working_socketpair('socketpair')) {
            $opts->{stdinout_socket} = 1;
        }
        else {
            $opts->{stdin_pipe} = 1;
            $opts->{stdout_pipe} = 1;
        }
    }

    my $socket = delete $opts->{stdinout_socket};

    my (@fhs, @pipes);
    if ($socket) {
        ($fhs[0], $pipes[0]) = $any->_os_socketpair($fhs[0], $pipes[0]) or return;
        $fhs[1] = $fhs[0];
        $pipes[1] = undef;
    }

    for my $stream (($socket ? () : ('stdin', 'stdout')), 'stderr') {
        my ($fh, $pipe);
        if (delete $opts->{"${stream}_pipe"}) {
            ($pipe, $fh) = $any->_os_pipe($any) or return;
            ($pipe, $fh) = ($fh, $pipe) if $stream eq 'stdin';
        }
        else {
            $fh = delete $opts->{"${stream}_fh"};
            unless ($fh) {
                my $file = (delete($opts->{"${stream}_discard"})
                            ? File::Spec->devnull
                            : delete $opts->{"${stream}_file"} );
                if (not defined $file and $stream eq 'stdin') {
                    # stdin is redirected from /dev/null by default
                    $file = File::Spec->devnull;
                }
                if (defined $file) {
                    my $dir = ($stream eq 'stdin' ? '<' : '>');
                    $fh = $any->_open_file($dir, $file) or return;
                }
            }
        }

        push @fhs, $fh;
        push @pipes, $pipe;
    }

    $any->_os_unset_pipe_inherit_flag($_)
        for grep defined, @pipes;

    my $stderr_to_stdout = (defined $fhs[2] ? 0 : delete $opts->{stderr_to_stdout});

    my @too_many = grep { /^std(?:in|out|err)_/ and
                          $_ ne 'stdin_data'    and
                          defined $opts->{$_} } keys %$opts;
    @too_many and croak "unsupported options or bad combination ('".join("', '", @too_many)."')";

    my @cmd = $any->_make_cmd($opts, $cmd) or return;

    $debug and $debug & 1024 and _debug("launching cmd: '", join("', '", @cmd), "'");
    my $pty = ($any->{be_interactive_login} ? $any->_os_pty($any) : undef);
    my $proc = $any->_os_open4(\@fhs, \@pipes, $pty, $stderr_to_stdout, @cmd) or return;

    $debug and $debug & 1024 and _debug("pid: $proc->{pid}");

    if ($pty) {
        $any->_os_interactive_login($pty, $stderr_to_stdout, $proc) or return undef;
        $any->{be_pty} = $pty;
        $pty->close_slave;
    }

    if ($dpipe) {
        $pipes[0] = $any->_os_make_dpipe($proc, @pipes[0, 1]) or return;
        $pipes[1] = undef;
        $debug and $debug & 1024 and _debug "fh upgraded to dpipe $pipes[0]";
    }

    return ($proc, @pipes);
}

sub interactive_login {
    my ($os, $any, $pty, $proc) = @_;

    my $opts = $any->{be_connect_opts};
    my $user = $opts->{user};
    my $password = $opts->{password};
    my $password_prompt = $opts->{password_prompt};
    my $asks_username_at_login = $opts->{asks_username_at_login};

    if (defined $password_prompt) {
        unless (ref $password_prompt eq 'Regexp') {
            $password_prompt = quotemeta $password_prompt;
            $password_prompt = qr/$password_prompt\s*$/i;
        }
    }

    if ($asks_username_at_login) {
         croak "ask_username_at_login set but user was not given" unless defined $user;
         croak "ask_username_at_login set can not be used with a custom password prompt"
             if defined $password_prompt;
    }

    local ($ENV{SSH_ASKPASS}, $ENV{SSH_AUTH_SOCK});

    my $rv = '';
    vec($rv, fileno($pty), 1) = 1;
    my $buffer = '';
    my $at = 0;
    my $password_sent;
    my $start_time = time;
    while(1) {
        if ($any->{_timeout}) {
            $debug and $debug & 1024 and _debug "checking timeout, max: $any->{_timeout}, ellapsed: " . (time - $start_time);
            if (time - $start_time > $any->{_timeout}) {
                $any->_set_error(SSHA_TIMEOUT_ERROR, "timed out while login");
                $any->_os_wait_proc($proc, 0, 1);
                return;
            }
        }

        unless ($any->_os_check_proc($proc)) {
            my $err = ($? >> 8);
            $any->_set_error(SSHA_CONNECTION_ERROR,
                             "slave process exited unexpectedly with error code $err");
            return;
        }

        $debug and $debug & 1024 and _debug "waiting for data from the pty to become available";

        my $rv1 = $rv;
        select($rv1, undef, undef, 1) > 0 or next;
        if (my $bytes = sysread($pty, $buffer, 4096, length $buffer)) {
            $debug and $debug & 1024 and _debug "$bytes bytes readed from pty";

            if ($buffer =~ /^The authenticity of host/mi or
                $buffer =~ /^Warning: the \S+ host key for/mi) {
                $any->_set_error(SSHA_CONNECTION_ERROR,
                                  "the authenticity of the target host can't be established, " .
                                  "the remote host public key is probably not present on the " .
                                  "'~/.ssh/known_hosts' file");
                $any->_os_wait_proc($proc, 0, 1);
                return;
            }
            if ($password_sent) {
                $debug and $debug & 1024 and _debug "looking for password ok";
                last if substr($buffer, $at) =~ /\n$/;
            }
            else {
                $debug and $debug & 1024 and _debug "looking for user/password prompt";
                my $re = ( defined $password_prompt
                           ? $password_prompt
                           : qr/(user|name|login)?[:?]\s*$/i );

                $debug and $debug & 1024 and _debug "matching against $re";

                if (substr($buffer, $at) =~ $re) {
                    if ($asks_username_at_login and
                        ($asks_username_at_login ne 'auto' or defined $1)) {
                        $debug and $debug & 1024 and _debug "sending username";
                        print $pty "$user\n";
                        undef $asks_username_at_login;
                    }
                    else {
                        $debug and $debug & 1024 and _debug "sending password";
                        print $pty "$password\n";
                        $password_sent = 1;
                    }
                    $at = length $buffer;
                }
            }
        }
        else {
            $debug and $debug & 1024 and _debug "no data available from pty, delaying until next read";
            sleep 0.02;
        }

    }
    $debug and $debug & 1024 and _debug "password authentication done";
    return 1;
}

1;
