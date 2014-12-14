package Net::SSH::Any::Backend::Dropbear_Cmd;

use strict;
use warnings;
use Carp;

use Net::SSH::Any::Util qw(_first_defined _array_or_scalar_to_list $debug _debug);
use Net::SSH::Any::Constants qw(SSHA_CONNECTION_ERROR);

use parent 'Net::SSH::Any::Backend::_Cmd';

sub _validate_connect_opts {
    my ($any, %opts) = @_;

    defined $opts{host} or croak "host argument missing";
    my ($auth_type, $interactive_login);

    $opts{local_dbclient_cmd} = _fist_defined($opts{local_dbclient_cmd},
                                              $any->{local_cmd}{dbclient},
                                              'dbclient');
    $opts{local_dropbearconvert_cmd} = _first_defined($opts{local_dropbearconvert_cmd},
                                                      $any->{local_cmd}{dropbearconvert},
                                                      '/usr/lib/dropbear/dropbearconvert');

    if (defined $opts{password}) {
        croak "password authentication is not supported yet by the dropbear backend";
    }
    elsif (defined (my $key_path = $opts{key_path})) {
        $auth_type = 'publickey';
        my $dbk = "$key.dbk";
        $opts{dbk_path} = $dbk;
        unless (-e $dbk) {
            local $?;
            my @cmd = ($opts{local_dropbearconvert_cmd},
                       'openssh', 'dropbear',
                       $key_path, $dbk);
            $debug and $debug & 1024 and _debug "generating dbk file with command '".join("', '", @cmd)."'";
            if (system @cmd) {
                $any->_set_error(SSHA_CONNECTION_ERROR, 'dropbearconvert failed, rc: ' . ($? >> 8));
                return
            }
            unless (-e $ppk) {
                $any->_set_error(SSHA_CONNECTION_ERROR, 'dropbearconvert failed to convert key to dropbear format');
                return
            }
    }

    $any->{be_connect_opts} = \%opts;
    $any->{be_auth_type} = $auth_type;
    $any->{be_interactive_login} = 0;
    1;
}

sub _make_cmd {
    my ($any, $opts, $cmd) = @_;
    my $connect_opts = $any->{be_connect_opts};

    my @args = ( $connect_opts->{local_dbclient_cmd} );

    push @args, -l => $connect_opts->{user} if defined $connect_opts->{user};
    push @args, -p => $connect_opts->{port} if defined $connect_opts->{port};
    push @args, -i => $connect_opts->{dbk_path} if defined $connect_opts->{dbk_path};

    push @args, _array_or_scalar_to_list($connect_opts->{dbclient_opts})
        if defined $connect_opts->{dbclient_opts};

    push @args, '-s' if delete $opts->{subsystem};
    push @args, $connect_opts->{host};

    if ($any->{be_auth_type} eq 'password') {
        croak "password authentication is not supported yet by the dropbear backend";
    }

    return (@args, $cmd);

}

1;
