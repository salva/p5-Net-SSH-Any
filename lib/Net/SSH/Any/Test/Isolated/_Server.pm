package Net::SSH::Any::Test::Isolated::_Server;

use strict;
use warnings;
use feature qw(say);

$0 = "$^X (Net::SSH::Any::Test::Isolated::Server)";
$| = 1;

use parent 'Net::SSH::Any::Test::Isolated::_Base';
BEGIN { *debug = \$Net::SSH::Any::Test::Isolated::debug };
our $debug;

sub run {
    my $class = shift;
    $class->_new(@_)->_run;
}

sub _new {
    my $class = shift;
    $debug = $dbg;
    $class->SUPER::_new('server', \*STDIN, \*STDOUT);
}

sub _run {
    my $self = shift;
    while (1) {
        $self->_send_prompt;
        if (my ($head, @args) = $self->_recv_packet) {
            if (my $method = $self->can("_do_$head")) {
                $self->_debug("calling $method(@args)");
                my @r = eval { $self->$method(@args) };
                if ($@) {
                    $self->_send_packet(exception => $@)
                }
                else {
                    $self->_send_packet(response => @r)
                }
            }
            else {
                $self->_send_packet(exception => "Internal error: invalid method $head");
            }
        }
        else {
            # connection close;
            return;
        }
    }
}

sub _send_prompt { shift->_send('go!') }

sub _do_start {
    my ($self, @opts) = @_;
    require Net::SSH::Any::Test;
    $self->{tssh} = Net::SSH::Any::Test->new(@opts);
    1;
}

sub _do_forward {
    my $self = shift;
    my $method = shift;
    my $wantarray = shift;
    if ($wantarray) {
        return $self->{tssh}->$method(@_);
    }
    else {
        return scalar $self->{tssh}->$method(@_);
    }
}


1;
