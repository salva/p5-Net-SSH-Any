package Net::SSH::Any::SCP::GetHandler;

use strict;
use warnings;

use Net::SSH::Any::Util qw($debug _debug _first_defined);

sub _new {
    my ($class, $any, $opts, $files) = @_;
    my $h = { any => $any,
              action_log => delete $opts->{action_log},
            };

    bless $h, $class;
}

for my $method (qw(on_file on_data on_end_of_file on_dir on_end_of_dir)) {
    no strict;
    *{$method} = sub {
        if ($debug and $debug and 4096) {
            my $args = (@_ == 4                ? "perm: $_[1], size: $_[2], name: $_[3]" :
                        $method eq 'on_data'   ? length($_[1]) . " bytes"                :
                        '' );
            Net::SSH::Any::_debug "called $_[0]->$method($args)";
        }
    };
}

sub _scp_local_error {
    my $h = shift;
    $h->{any}->_set_error(@_, $!);

    local ($@, $SIG{__DIE__}, $SIG{__WARN__});
    eval {
        my $action = $h->{action_log}[-1];
        $action->{error} = $_[0];
        $action->{errno} = $!;
    };
    return;
}

sub _push_action {
    my ($h, %action) = @_;
    my $action = \%action;
    local ($@, $SIG{__WARN__}, $SIG{__DIE__});
    eval { push @{$h->{action_log}}, $action };
    $action
}

sub on_remote_error {
    my ($h, $path, $error) = @_;
    $debug and $debug & 4096 and Net::SSH::Any::_debug("$h->on_remote_error(@_)");
    $h->_push_action( type => 'remote_error',
                      remote => $path,
                      error => $error );
    1
}

sub on_end_of_get {
    my $h = shift;
    $debug and $debug & 4096 and Net::SSH::Any::_debug("$h->on_end_of_get(@_)");
    1
}

sub on_matime {
    my ($h, $mtime, $atime) = @_;
    $debug and $debug & 4096 and Net::SSH::Any::_debug("$h->on_matime($mtime, $atime)");
    $h->{mtime} = $mtime;
    $h->{atime} = $atime;
    1;
}

1;
