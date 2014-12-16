package Net::SSH::Any::Backend::Plink_Cmd;

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

    if (defined $opts{password}) {
        $auth_type = 'password';
        if (my @too_much = grep defined($opts{$_}), qw(key_path passphrase)) {
            croak "option(s) '".join("', '", @too_much)."' can not be used together with 'password'"
        }
    }
    elsif (defined (my $key = $opts{key_path})) {
        $auth_type = 'publickey';
        my $ppk = "$key.ppk";
        $opts{ppk_path} = $ppk;
        unless (-e $ppk) {
            local $?;
            my $cmd = _first_defined $opts{local_puttygen_cmd},
                $any->{local_cmd}{puttygen}, 'puttygen';
            my @cmd = ($cmd, -O => 'private', -o => $ppk, $key);
            $debug and $debug & 1024 and _debug "generating ppk file with command '".join("', '", @cmd)."'";
            if (system @cmd) {
                $any->_set_error(SSHA_CONNECTION_ERROR, 'puttygen failed, rc: ' . ($? >> 8));
                return
            }
            unless (-e $ppk) {
                $any->_set_error(SSHA_CONNECTION_ERROR, 'puttygen failed to convert key to PPK format');
                return
            }
        }
    }
    else {
        $auth_type = 'default';
    }

    $opts{local_plink_cmd} = _first_defined $opts{local_plink_cmd}, $any->{local_cmd}{plink}, 'plink';
    $any->{be_connect_opts} = \%opts;
    $any->{be_auth_type} = $auth_type;
    $any->{be_interactive_login} = 0;
    1;
}

sub _make_cmd {
    my ($any, $opts, $cmd) = @_;
    my $connect_opts = $any->{be_connect_opts};

    my @args = ( $connect_opts->{local_plink_cmd},
                 '-ssh',
                 '-batch',
                 '-C' );

    push @args, -l => $connect_opts->{user} if defined $connect_opts->{user};
    push @args, -P => $connect_opts->{port} if defined $connect_opts->{port};
    push @args, -i => $connect_opts->{ppk_path} if defined $connect_opts->{ppk_path};

    if ($any->{be_auth_type} eq 'password') {
        push @args, -pw => $connect_opts->{password};
    }

    push @args, _array_or_scalar_to_list($connect_opts->{plink_opts})
        if defined $connect_opts->{plink_opts};

    push @args, '-s' if delete $opts->{subsystem};
    push @args, $connect_opts->{host};

    return (@args, $cmd);
}

1;

__END__

=head1 NAME

Net::SSH::Any::Backend::Plink_Cmd - Backend for PuTTY's plink

=head1 SYNOPSIS

  use Net::SSH::Any;
  my $ssh = Net::SSH::Any->new($host, user => $user, password => $password,
                               backends => ['Plink_Cmd'],
                               local_plink_cmd => 'C:\\PuTTY\\plink.exe');
  my $output = $ssh->capture("echo hello world");

=head1 DESCRIPTION

This module implements a Net::SSH::Any backend using PuTTY's plink
utility.

It is probably the easiest way to get a working, password
authenticated SSH connection on Windows. Unfortuntelly, it is not
completely secure as the password is passed to plink on the command
line and anybody with access to the local computer may eavesdrop it.

Also, a new connection is established for every command run, so this
backend is not particularly efficient when running several commands
in the target host.

=head2 Public key aithentication

When public key authentication is requested, the module looks first for
the key in a file with the extension C<ppk>.

In case that file does not exist, it looks for the private key in
OpenSSH format and if found, it tries to convert it to PuTTY format
using the companion utility C<puttygen>.

For instance:

  $ssh = Net::SSH::Any->new($host, key_path => 'C:\\OpenSSH\\keys\\my_key',
                            backends => ['Plimk_Cmd']);
                            local_plink_cmd => 'C:\\PuTTY\\plink.exe',
                            local_puttygen_cmd => 'C:\\PuTTY\\puttygen.exe');

  # Looks for "C:\OpenSSH\keys\my_key.ppk". In case that file doesn't
  # exist, it looks for "C:\OpenSSH\keys\my_key" and tries to convert
  # it using the program "C:\PuTTY\puttygen.exe".

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2011-2014 by Salvador Fandiño, E<lt>sfandino@yahoo.comE<gt>

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.12.4 or,
at your option, any later version of Perl 5 you may have available.

=cut
