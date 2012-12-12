package Net::SSH::Any::SCP::Handle;

use strict;
use warnings;

use Net::SSH::Any::Constants ();
use Net::SSH::Any::Util qw($debug _debugf _first_defined _gen_wanted);

sub _new {
    my ($class, $any, $opts, $files) = @_;

    my $h = { any        => $any,
              action_log => _first_defined(delete($opts->{action_log}), []),
	      wanted     => _gen_wanted(delete @{$opts}{qw(wanted not_wanted)}),
    };
    bless $h, $class;
}

sub set_local_error {
    my ($h, $error) = @_;
    $h->{action_log}[-1]{error} = $h->{last_error} = (defined $error ? $error : $!);
    $h->{errors}++;
}

sub check_wanted {
    my $h = shift;
    if (my $wanted = $h->{wanted}) {
	my $action = $h->{action_log}[-1];
	unless ($wanted->($action)) {
	    $debug and $debug & 4096 and
		_debugf("%s->set_not_wanted, %s -> %s", $h, @{$action}{qw(remote local)});
	    $action->{not_wanted} = 1;
	    return;
	}
    }
    1;
}

sub set_skipped {
    my $h = shift;
    my $action = $h->{action_log}[-1];
    $debug and $debug & 4096 and
	_debugf("%s->set_skipped, %s -> %s", $h, @{$action}{qw(remote local)});
    $action->{skipped} = 1;
}

sub push_action {
    my ($h, %action) = @_;
    my $action = \%action;
    push @{$h->{action_log}}, $action;
    $action
}

sub last_error {
    my $h = shift;
    _first_defined $h->{last_error}, "unknown error"
}

sub abort { shift->{aborted} = 1 }

sub aborted { shift->{aborted} }

1;
