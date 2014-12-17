package Net::SSH::Any::Backend::Dbclient_Cmd;

use strict;
use warnings;
use Carp;

use Net::SSH::Any::Util qw(_first_defined _array_or_scalar_to_list $debug _debug);
use Net::SSH::Any::Constants qw(SSHA_CONNECTION_ERROR SSHA_UNIMPLEMENTED_ERROR);

require Net::SSH::Any::Backend::_Cmd;
our @ISA = qw(Net::SSH::Any::Backend::_Cmd);

sub _validate_connect_opts {
    my ($any, %opts) = @_;

    defined $opts{host} or croak "host argument missing";
    my ($auth_type, $interactive_login);

    $opts{local_dbclient_cmd} //= $any->_find_cmd('dbclient');
    $opts{local_dropbearconvert_cmd} //= $any->_find_cmd(dropbearconvert => defined $opts{host}, undef,
                                                         '/usr/lib/dropbear/dropbearconvert');
    if (defined $opts{password}) {
        # $auth_type = 'password';
        # $interactive_login = 1;
        # if (my @too_more = grep defined($opts{$_}), qw(key_path passphrase)) {
        #    croak "option(s) '".join("', '", @too_more)."' can not be used together with 'password'"
        # }
        $any->_set_error(SSHA_UNIMPLEMENTED_ERROR,
                         "password authentication is not supported by the Dbclient_Cmd backend");
        return
    }
    elsif (defined (my $key = $opts{key_path})) {
        $auth_type = 'publickey';
        my $dbk = "$key.dbk";
        $opts{dbk_path} = $dbk;
        unless (-e $dbk) {
            local $?;
            my @cmd = ($opts{local_dropbearconvert_cmd},
                       'openssh', 'dropbear',
                       $key, $dbk);
            $debug and $debug & 1024 and _debug "generating dbk file with command '".join("', '", @cmd)."'";
            if (system @cmd) {
                $any->_set_error(SSHA_CONNECTION_ERROR, 'dropbearconvert failed, rc: ' . ($? >> 8));
                return
            }
            unless (-e $dbk) {
                $any->_set_error(SSHA_CONNECTION_ERROR, 'dropbearconvert failed to convert key to dropbear format');
                return
            }
        }
    }
    else {
        $auth_type = 'default';
    }

    $any->{be_connect_opts} = \%opts;
    $any->{be_auth_type} = $auth_type;
    $any->{be_interactive_login} = $interactive_login;
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
        # croak "password authentication is not supported yet by the dropbear backend";
    }

    return (@args, $cmd);

}

1;
