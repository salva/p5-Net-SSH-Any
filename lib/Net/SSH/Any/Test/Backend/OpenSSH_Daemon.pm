package Net::SSH::Any::Test::Backend::OpenSSH_Daemon;

use strict;
use warnings;

use Net::SSH::Any;
use Net::SSH::Any::Constants qw(SSHA_BACKEND_ERROR);

sub _validate_backend_opts {
    my ($tssh, %opts) = @_;
    # $tssh->SUPER::_validate_backend_opts(%opts) or return;

    $tssh->{be_opts} = \%opts;

    $opts{"${_}_key_path"} //= $tssh->_backend_wfile("${_}_key") for qw(user host);
    $opts{sshd_config_file} //= $tssh->_backend_wfile('sshd_config');
    $opts{user} //= $tssh->_os_current_user;

    # ssh and sshd are resolved here so that they can be used as
    # friends by any other commands
    $opts{local_ssh_cmd} //= $tssh->_resolve_cmd('ssh');
    $opts{local_sshd_cmd} //= $tssh->_resolve_cmd('sshd');
    1;
}

sub _create_all_keys {
    my $tssh = shift;
    $tssh->_create_key($tssh->{be_opts}{"${_}_key_path"}) or return
        for qw(user host);
    1;
}

sub _create_key {
    my ($tssh, $path) = @_;
    my $path_pub = "$path.pub";
    -f $path and -f $path_pub and return 1;
     my $tmppath = join('.', $path, $$, int(rand(9999999)));
    if ($tssh->_run_cmd({}, 'ssh-keygen', -t => 'rsa', -b => 1024, -f => $tmppath, -P => '')) {
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

my $log_ix;

sub _log_fn {
    my ($tssh, $name) = @_;
    my $fn = sprintf "%d-%s.log", ++$log_ix, $name;
    $tssh->_backend_wfile($fn);
}

sub _resolve_cmd {
    my ($tssh, $name) = @_;
    my $opts = $tssh->{be_opts};
    my $safe_name = $name;
    $safe_name =~ s/\W/_/g;
    $opts->{"local_${safe_name}_cmd"} //=
        $tssh->_find_cmd($name,
                         $opts->{local_ssh_cmd},
                         'OpenSSH');
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
    my $key = $tssh->_path_to_unix($tssh->{be_opts}{user_key_path});
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
    my $fn = $tssh->{be_opts}{sshd_config_file};
    -f $fn and return 1;
    if (open my $fn, '>', $fn) {
        while (@_) {
            my $k = $tssh->_escape_config(shift);
            my $v = $tssh->_escape_config(shift);
            print $fn "$k=$v\n";
        }
        close $fn and return 1
    }
    $tssh->_set_error(SSHA_BACKEND_ERROR, "unable to create sshd configuration file at '$fn': $!");
    ()
}

sub _override_config {
    my $tssh = shift;
    my %override = %{ $tssh->{be_opts}{override_config} // {} };
    my @cfg;
    while (@_) {
        my $k = shift;
        my $v = shift;
        if (exists $override{$k}) {
            $v = delete $override{$k};
            next unless defined $v;
        }
        push @cfg, $k, $v;
    }
    (@cfg, %override);
}

sub _start_and_check {
    my $tssh = shift;

    unless ($tssh->{run_server}) {
        $tssh->_log("Skipping OpenSSH_Daemon backend as run_server is unset");
        return
    }

    my $opts = $tssh->{be_opts};
    my $port = $opts->{port} //= $tssh->_find_unused_tcp_port;
    my $sftp_server = $tssh->_resolve_cmd('sftp-server');

    $tssh->_create_all_keys;

    my @cfg = $tssh->_override_config( HostKey            => $tssh->_path_to_unix($opts->{host_key_path}),
                                       AuthorizedKeysFile => $tssh->_user_key_path_quoted . ".pub",
                                       AllowUsers         => $opts->{user}, # only user running the script can log
                                       AllowTcpForwarding => 'yes',
                                       GatewayPorts       => 'no', # bind port forwarder listener to localhost only
                                       ChallengeResponseAuthentication => 'no',
                                       PasswordAuthentication => 'no',
                                       Port               => $port,
                                       ListenAddress      => "localhost:$port",
                                       LogLevel           => 'INFO',
                                       PermitRootLogin    => 'yes',
                                       PidFile            => $tssh->_backend_wfile('sshd.pid'),
                                       PrintLastLog       => 'no',
                                       PrintMotd          => 'no',
                                       UseDNS             => 'no',
                                       StrictModes        => 'no',
                                       UsePrivilegeSeparation => 'no',
                                       Subsystem          => "sftp $sftp_server");
    $tssh->_write_config(@cfg) or return;

    $tssh->_log("Starting sshd at localhost:$port");
    $tssh->{sshd_proc} = $tssh->_run_cmd({out_name => 'sshd',
                                          async => 1 },
                                         'sshd',
                                         '-D', # no daemon
                                         '-e', # send output to STDEE
                                         '-f', $opts->{sshd_config_file}) or return;

    my $uri = Net::SSH::Any::URI->new(host => "localhost",
                                      port => $port,
                                      user => $opts->{user},
                                      key_path => $opts->{user_key_path});

    $tssh->_check_and_set_uri($uri) and return 1;

    $tssh->_set_error(SSHA_BACKEND_ERROR, "unable to launch sshd");
    ()
}




1;
