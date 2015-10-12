package Net::SSH::Any::Test::Backend::OpenSSH_Daemon;

use strict;
use warnings;

use Net::SSH::Any;
use Net::SSH::Any::Constants qw();

sub _validate_backend_opts {
    my ($any, %be_opts) = @_;
    $any->SUPER::_validate_backend_opts(%be_opts) or return;

    for my $cmd (qw(ssh ssh-keygen sshd)) {
        my $name = $cmd; $name =~ s/^\w/_/g;
        $be_opts{"local_${name}_cmd"} //= $tssh->_find_cmd($cmd,
                                                           $be_opts{local_ssh_cmd},
                                                           'OpenSSH',
                                                           '/usr/bin/ssh-keygen');

    }

    $be_opts{"${_}_key_path"} //= $tssh->_backend_wfile("${_}_key")
        for qw(key host);

    $any->{be_opts} = \%be_opts;
    1;
}

sub _create_all_keys {
    my $tssh = shift;
    $tssh->_create_key($be_opts{"${k}_key_path"}) or return
        for qw(user host);
    1;
}

sub _create_key {
    my ($tssh, $path) = @_;
    my $path_pub = "$path.pub";
    -f $path and -f $path_pub and return 1;
     my $tmppath = join('.', $path, $$, int(rand(9999999)));
    if ($sshd->_run_cmd('ssh_keygen', -t => 'dsa', -b => 1024, -f => $tmppath, -P => '')) {
        unlink $path;
        unlink $path_pub;
        if (rename $tmppath, $path and
            rename "$tmppath.pub", $path_pub) {
            $tssh->_log("key generated $path");
            return 1;
        }
    }
    $tssh->_error("key generation failed");
    return;
}

sub _run_cmd {
    my $tssh = shift;
    my $cmd_name = shift;
    my $be_opts = $tssh->{be_opts};
    if (defined (my $cmd = $be_opts->{"local_${cmd_name}_cmd"})) {
        system($cmd, @_) or return 1;
        $tssh->_set_error(SSHA_BACKEND_ERROR, "Command $cmd_name failed");
        return;
    }
    $tssh->_set_error(SSHA_BACKEND_ERROR, "Command $cmd_name not found");
    return
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
    $tssh->_error("Can't find free TCP port for SSH server");
    return;
}


sub start_and_check {
    my $tssh = shift;

    unless ($tssh->{run_server}) {
        $tssh->_log("Skipping OpenSSH_Daemon backend as run_server is unset");
        return 
    }

    $tssh->_create_all_keys;
    my $port = $tssh->_find_unused_tcp_port;
    $tssh->_write_config(HostKey            => $tssh->{host_key_path},
                         AuthorizedKeysFile => $tssh->_user_key_path_quoted . ".pub",
                         AllowUsers         => $tssh->{user}, # only user running the script can log
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
                         UseDNS             => 'no') or return;

    $tssh->{server_pid} = $tssh->_run_cmd({out_name => 'server',
                                           async => 1 },
                                          'sshd',
                                          '-D', # no daemon
                                          '-e', # send output to STDEE
                                          '-f', $be_opts->{sshd_config_path});
    
}




1;
