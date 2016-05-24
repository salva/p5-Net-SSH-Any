package Net::SSH::Any::Test::Backend::OpenSSH_Daemon;

use strict;
use warnings;

use Net::SSH::Any;
use Net::SSH::Any::Constants qw(SSHA_BACKEND_ERROR);

sub _validate_backend_opts {
    my ($tssh, %be_opts) = @_;
    # $tssh->SUPER::_validate_backend_opts(%be_opts) or return;

    for my $cmd (qw(ssh ssh-keygen sshd)) {
        my $name = $cmd; $name =~ s/\W/_/g;
        my $sub = ($cmd eq 'sshd' ? 'sbin' : 'bin');
        $be_opts{"local_${name}_cmd"} //= $tssh->_find_cmd($cmd,
                                                           $be_opts{"local_ssh_cmd"},
                                                           'OpenSSH',
                                                           "/usr/$sub/$cmd");

    }

    $be_opts{"${_}_key_path"} //= $tssh->_backend_wfile("${_}_key")
        for qw(user host);

    $be_opts{sshd_config_file} //= $tssh->_backend_wfile('sshd_config');

    $be_opts{user} //= $tssh->_os_current_user;

    $tssh->{be_opts} = \%be_opts;
    1;
}

sub _create_all_keys {
    my $tssh = shift;
    my $be_opts = $tssh->{be_opts};
    $tssh->_create_key($be_opts->{"${_}_key_path"}) or return
        for qw(user host);
    1;
}

sub _create_key {
    my ($tssh, $path) = @_;
    my $path_pub = "$path.pub";
    -f $path and -f $path_pub and return 1;
     my $tmppath = join('.', $path, $$, int(rand(9999999)));
    if ($tssh->_run_cmd({}, 'ssh_keygen', -t => 'rsa', -b => 1024, -f => $tmppath, -P => '')) {
        unlink $path;
        unlink $path_pub;
        if (rename $tmppath, $path and
            rename "$tmppath.pub", $path_pub) {
            $tssh->_log("key generated $path");
            return 1;
        }
    }
    $tssh->_set_error(SSHA_BACKEND_ERROR, "key generation failed");
    return;
}

sub _run_cmd {
    my ($tssh, $opts, $cmd, @args) = @_;
    my $be_opts = $tssh->{be_opts};
    my $async = $opts->{async};
    my $out_fn = $tssh->_backend_wfile($opts->{out_name} // $cmd);
    my $resolved_cmd = $be_opts->{"local_${cmd}_cmd"};
    # warn "resolved_cmd: $resolved_cmd, was $cmd";
    if (defined $resolved_cmd            and
        open my ($out_fh), '>>', $out_fn and
        open my ($in_fh), '<', $tssh->_dev_null) {
        if (my $proc = $tssh->_os_open4([$in_fh, $out_fh], [], undef, 1,
                                        $resolved_cmd => @args)) {
            $async and return $proc;
            $tssh->_os_wait_proc($proc, $opts->{timeout}, $opts->{force_kill}) and return 1;
        }
        $tssh->_set_error(SSHA_BACKEND_ERROR, "Can't execute command $cmd: $!");
    }
    ()
}

sub _find_unused_tcp_port {
    my $tssh = shift;
    $tssh->_log("looking for an unused TCP port");
    for (1..32) {
        my $port = 5000 + int rand 27000;
        unless (IO::Socket::INET->new(PeerAddr => "localhost:$port",
                                      Proto => 'tcp',
                                      Timeout => $tssh->{timeout})) {
            $tssh->_log("port $port is available");
            return $port;
        }
    }
    $tssh->_set_error(SSHA_BACKEND_ERROR, "Can't find free TCP port for SSH server");
    return;
}

sub _path_to_unix {
    my ($tssh, $path) = @_;
    # FIXME: _w32path_to_cygwin is not implemented yet!
    ( $^O =~ /^MSWin/
      ? $tssh->_w32path_to_cygwin($path)
      : $path );
}

sub _user_key_path_quoted {
    my $tssh = shift;
    my $be_opts = $tssh->{be_opts};
    my $key = $tssh->_path_to_unix($be_opts->{user_key_path});
    $key =~ s/%/%%/g;
    $key;
}

sub _escape_config {
    my ($tssh, $v) = @_;
    $v =~ s/([\\\s])/\\$1/g;
    return $v;
}

sub _write_config {
    my $tssh = shift;
    my $be_opts = $tssh->{be_opts};
    my $fn = $be_opts->{sshd_config_file};
    -f $fn and return 1;
    if (open my $fn, '>', $fn) {
        while (@_) {
            print "k: $_[0], v: $_[1]\n";
            my $k = $tssh->_escape_config(shift);
            my $v = $tssh->_escape_config(shift);
            print $fn "$k=$v\n";
        }
        close $fn and return 1
    }
    $tssh->_set_error(SSHA_BACKEND_ERROR, "unable to create sshd configuration file at '$fn': $!");
    ()
}

sub _start_and_check {
    my $tssh = shift;

    unless ($tssh->{run_server}) {
        $tssh->_log("Skipping OpenSSH_Daemon backend as run_server is unset");
        return
    }

    my $be_opts = $tssh->{be_opts};

    $tssh->_create_all_keys;
    my $port = $tssh->_find_unused_tcp_port;
    $tssh->_write_config(HostKey            => $tssh->_path_to_unix($be_opts->{host_key_path}),
                         AuthorizedKeysFile => $tssh->_user_key_path_quoted . ".pub",
                         AllowUsers         => $be_opts->{user}, # only user running the script can log
                         AllowTcpForwarding => 'yes',
                         GatewayPorts       => 'no', # bind port forwarder listener to localhost only
                         ChallengeResponseAuthentication => 'no',
                         PasswordAuthentication => 'no',
                         Port               => $port,
                         ListenAddress      => "localhost:$port",
                         LogLevel           => 'INFO',
                         PermitRootLogin    => 'yes',
                         PidFile            => $tssh->_backend_wfile("sshd.pid"),
                         PrintLastLog       => 'no',
                         PrintMotd          => 'no',
                         UseDNS             => 'no',
                         StrictModes        => 'no',
                         UsePrivilegeSeparation => 'no') or return;

    $tssh->_log("Starting sshd at localhost:$port");
    $tssh->{sshd_proc} = $tssh->_run_cmd({out_name => 'server',
                                          async => 1 },
                                         'sshd',
                                         '-D', # no daemon
                                         '-e', # send output to STDEE
                                         '-f', $be_opts->{sshd_config_file}) or return;

    my $uri = Net::SSH::Any::URI->new(host => "localhost",
                                      port => $port,
                                      user => $be_opts->{user},
                                      key_path => $be_opts->{user_key_path});

    $tssh->_check_and_set_uri($uri) and return 1;

    $tssh->_set_error(SSHA_BACKEND_ERROR, "unable to launch sshd");
    ()
}




1;
