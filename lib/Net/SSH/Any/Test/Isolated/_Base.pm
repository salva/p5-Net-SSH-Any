package Net::SSH::Any::Test::Isolated::_Base;

use strict;
use warnings;
use feature 'say';

BEGIN { *debug = \$Net::SSH::Any::Test::Isolated::debug }
our $debug;

sub _debug {
    my $self = shift;
    say STDERR "$self->{side}> ", join(': ', @_) if $debug;
}

sub _new {
    my ($class, $side, $in, $out) = @_;
    my $self = { side => $side,
                 in => $in,
                 out => $out };
    bless $self, $class;
}

sub _send {
    my ($self, $packet) = @_;
    $self->_debug(send => $packet);
    say {$self->{out}} $packet;
}

sub _recv {
    my $self = shift;
    $self->_debug("waiting for data");
    my $in = $self->{in};
    chomp(my $packet = <$in>);
    $self->_debug(recv => $packet);
    $packet;
}

sub _serialize {
    shift;
    my $dump = Data::Dumper->new([@_], ['D']);
    $dump->Terse(1)->Purity(1)->Indent(0)->Useqq(1);
    return $dump->Dump;
}

sub _deserialize {
    shift;
    my ($r, $err);
    do {
        local ($@, $SIG{__DIE__});
        $r = eval $_[1];
        $err = $@;
    };
    die $err if $err;
    wantarray ? @$r : $r->[0];
}

sub _recv_packet {
    my $self = shift;
    my $packet = $self->_recv;
    while (1) {
        if (my ($head, $args) = $packet =~ /^(\w+):\s+(.*)$/) {
            my @args = $self->_deserialize($args);
            if ($head eq 'log') {
                $self->_log(@args);
                redo;
            }
            return ($head, @args);
        }
        elsif ($packet eq 'go!') {
            return 'go!'
        }
        elsif ($packet =~ /^\s*(?:#.*)?$/) {
            # Ignore blank lines and comments.
        }
        else {
            die "Internal error: unexpected data packet $packet";
        }
    }
}

sub _send_packet {
    my $self = shift;
    my $head = shift;
    my $args = $self->_serialize(@_);
    $self->_send("$head: $args");
}

sub _log {
    my $self = shift;
    say STDERR join(': ', log => @_);
}

1;
