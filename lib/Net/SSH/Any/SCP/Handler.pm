package Net::SSH::Any::SCP::Handler;

use strict;
use warnings;

use Net::SSH::Any::Constants ();
use Net::SSH::Any::Util qw($debug _debug _first_defined);

sub _new {
    my ($class, $any, $opts, $files) = @_;
    my $h = { any => $any,
              action_log => delete $opts->{action_log},
            };

    bless $h, $class;
}

sub set_local_error {
    my ($h, $path, $error) = @_;
    $error = $! unless defined $error;
    $h->{last_error} = $error;
    $h->{any}->_set_error(Net::SSH::Any::Constants::SSHA_SCP_ERROR, $path, $error);
    local ($@, $SIG{__DIE__}, $SIG{__WARN__});
    eval {
        my $action = $h->{action_log}[-1];
        $action->{error} = $error;
    };
    return;
}

sub push_action {
    my ($h, %action) = @_;
    my $action = \%action;
    local ($@, $SIG{__WARN__}, $SIG{__DIE__});
    eval { push @{$h->{action_log}}, $action };
    $action
}

sub last_error {
    my $h = shift;
    _first_defined $h->{last_error}, "unknown error"
}

sub abort { shift->{aborted} = 1 }

sub aborted { shift->{aborted} }

1;
