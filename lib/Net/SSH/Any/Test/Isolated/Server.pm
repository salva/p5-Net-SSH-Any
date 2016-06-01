package Net::SSH::Any::Test::Isolated::Server;

use strict;
use warnings;
use feature qw(say);

use parent 'Net::SSH::Any::Test::Isolated::_Base';
BEGIN { *debug = \$Net::SSH::Any::Test::Isolated::debug };
our $debug;

sub run {
    my $class = shift;
    $class->_new(@_)->_run;
}

sub _new {
    my ($class, $dbg) = @_;
    $| = 1;
    $debug = $dbg;
    $class->SUPER::_new('server', \*STDIN, \*STDOUT);
}

sub _run {
    my $self = shift;

    print STDERR "server starting, debug: $debug!!!\n";

    while (1) {
        $self->_send_prompt;
        my ($head, @args) = $self->_recv_packet;
        if (my $method = $self->can("_do_$head")) {
            my @r = eval { $self->$method(@args) };
            if ($@) {
                $self->_send_packet(exception => $@)
            }
            else {
                $self->_send_packet(response => @r)
            }
        }
        else {
            $self->_send_packet(error => "Internal error: invalid method $head");
        }
    }
}

sub _send_prompt { shift->_send('go!') }

sub do_start {
    my ($self, @opts) = @_;
    require Net::SSH::Any::Test;
    $self->{tssh} = Net::SSH::Any::Test->new(@opts);
    1;
}

sub do_forward {
    my $self = shift;
    my $method = shift;
    $self->{tssh}->$method(@_);
}


1;
