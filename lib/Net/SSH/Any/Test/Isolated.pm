package Net::SSH::Any::Test::Isolated;

use strict;
use warnings;
use feature qw(say);
use Carp;

use Data::Dumper;
use IPC::Open2 qw(open2);

our $debug;

use parent qw(Net::SSH::Any::Test::Isolated::_Base);

sub new {
    my ($class, %opts) = @_;
    my $self = $class->SUPER::_new('client');

    $self->{perl} = $opts{local_perl_cmd} // $^X // 'perl';
    $self->_bootstrap;

    $self->_start(%opts);

    $self;
}

sub _bootstrap {
    my $self = shift;
    my $perl = $self->{perl} or return;
    $self->{pid} = open2($self->{in}, $self->{out}, $^X);

    my $old = select($self->{out});
    $| = 1;
    select $old;

    my $inc = Data::Dumper::Dumper([grep defined && !ref, @INC]);
    my $debug_as_str = ($debug ? -1 : 'undef');

    my $code = <<EOC;

use lib \@{$inc};

use strict;
use warnings;

use Net::SSH::Any::Test::Isolated::Server;
Net::SSH::Any::Test::Isolated::Server->run($debug_as_str);

__END__
EOC

    $self->_send($code);
}

sub _start { shift->_rpc(start => @_) }

sub _wait_for_prompt {
    my $self = shift;
    while (1) {
        my $out = $self->_recv_packet;
        return $out eq 'go!';
        die "Unexpected packet $out received";
    }
}

sub _rpc {
    my $self = shift;
    my $method = shift;
    $self->_wait_for_prompt;
    $self->_send_packet($method => @_);
    my ($head, @res) = @_;
    if ($head eq 'response') {
        return @res;
    }
    elsif ($head eq 'exception') {
        die $res[0];
    }
    elsif ($head eq 'error') {
        die $res[0];
    }
    else {
        die "Internal error: unexpected response $head";
    }
}

sub AUTOLOAD {
    our $AUTOLOAD;
    my $name = $AUTOLOAD;
    $name =~ s/.*://;
    if ($name =~ /^[a-z]\w+$/i) {
        my $sub = sub { shift->_rpc(forward => $name, @_) };
        no strict 'refs';
        *{$AUTOLOAD} = $sub;
        goto &$sub;
    }
    die "Can't locate object method $name via package ".__PACKAGE__;
}

1;
