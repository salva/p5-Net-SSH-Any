package Net::SSH::Any::Test::Backend::Dropbear_Daemon;

use strict;
use warnings;

use Net::SSH::Any;
use Net::SSH::Any::Constants qw(SSHA_BACKEND_ERROR);

use parent 'Net::SSH::Any::Test::Backend::_Daemon';

sub _validate_backend_opts {
    my $tssh = shift;

    $tssh->SUPER::_validate_backend_opts or return;

    # dropbear and dbclient are resolved here so that they can be used
    # as friends by any other commands
    my $opts = $tssh->{current_opts};
    $opts->{local_dropbear_cmd} //= $tssh->_resolve_cmd('dropbear');
    $opts->{local_dbclient_cmd} //= $tssh->_resolve_cmd('dbclient');
    1;
}

my $key_type = 'rsa';

sub _extract_publickey_from_log {
    my ($self, $log, $filename) = @_;
    my $pubkey;
    if (open my($in), '<', $log_fn) {
        while (<$in>) {
            if (/^ssh-$key_type\s+/) {
                if (open my($out), '>', $filename) {
                    print $out $_;
                    close $out and return 1;
                }
                last;
            }
        }
    }
    $tssh->_set_error(SSHA_BACKEND_ERROR, "unable to extract publickey from dropbearkey log");
    return;
}

sub _create_key {
    my ($tssh, $path) = @_;
    my $path_pub = "$path.pub";
    -f $path and -f $path_pub and return 1;
    my $tmppath = join('.', $path, $$, int(rand(9999999)));
    my $log_fn = $tssh->_log_fn('dropbearkey');
    if ($tssh->_run_cmd({stdout_file => $log_fn}, 'dropbearkey', -t => $key_type, -s => 1024, -f => $tmppath)) {
        $tssh->_extract_publickey_from_log($log_fn, "$tmppath.pub") or return;
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

sub _resolve_cmd {
    my ($tssh, $name) = @_;
    my $opts = $tssh->{current_opts};
    my $safe_name = $name;
    $safe_name =~ s/\W/_/g;
    $opts->{"local_${safe_name}_cmd"} //=
        $tssh->_find_cmd($name,
                         $opts->{local_dropbear_cmd},
                         { POSIX => 'Dropbear',
                           MSWin => 'Cygwin' });
}

sub _start_and_check {
    my $tssh = shift;

    $tssh->_create_all_keys or return;

    my $opts = $tssh->{current_opts};
    $tssh->{daemon_proc} = $tssh->_run_cmd({async => 1},
                                           'dropbear', '-E', '-s',
                                           -r => $tssh->{host_key_path},
                                           -p => "localhost:$opts->{port}",
                                           -P => $tssh->_backend_wfile('dropbear.pid'));

    $tssh->_check_daemon_and_set_uri and return 1;
    $tssh->_stop;
    ()
}

sub _daemon_name { 'dropbear' }

1;
