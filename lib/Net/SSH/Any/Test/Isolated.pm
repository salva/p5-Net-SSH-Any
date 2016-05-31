package Net::SSH::Any::Test::Isolated;

use strict;
use warnings;
use feature qw(say);
use Carp;

use Data::Dumper;
use IPC::Open2 qw(open2);

use Net::SSH::Any::URI;

sub new {
    my ($class, %opts) = @_;
    my $perl = $opts{local_perl_cmd} // $^X // 'perl';

    my $self = { perl => $perl };
    bless $self, $class;

    $self->_bootstrap;

    $self;
}

sub _serialize {
    my $dump = Data::Dumper->new([@_], ['DATA']);
    $dump->Terse(1)->Purity(1)->Indent(0)->Useqq(1);
    return $dump->Dump;
}

sub _rpc {
    my $self = shift;
    my $method = shift;
    my $args = _serialize(@_);
}

sub _bootstrap {
    my $self = shift;
    my $perl = $self->{perl} or return;
    $self->{pid} = open2($self->{cout}, $self->{cin}, $^X);

    my $old = select($self->{cin});
    $| = 1;
    select $old;

    my $inc = Data::Dumper::Dumper([grep defined && !ref, @INC]);

    my $code = <<EOC;

use lib \@{$inc};

use strict;
use warnings;

use Net::SSH::Any::Test::Isolated::Server;
Net::SSH::Any::Test::Isolated::Server->run;

__DATA__
EOC

    $self->_send($code);

    for (qw(foo bar doz)) {
        $self->_wait_for_prompt;
        $self->_send($_);
    }
}

sub _wait_for_prompt {
    my $self = shift;
    my $out = $self->_read;
    return $out eq 'ok!';
}

sub _send {
    my ($self, $packet) = @_;
    my $cin = $self->{cin};
    say STDERR "master send: $packet";
    say {$cin} $packet;
}

sub _read {
    my $self = shift;
    say STDERR "master waiting for data";
    my $cout = $self->{cout};
    chomp(my $packet = <$cout>);
    say STDERR "master recv: $packet";
    $packet;
}


1;

__DATA__

1;
