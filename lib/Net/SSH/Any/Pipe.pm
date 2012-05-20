package Net::SSH::Any::Pipe;

use strict;
use warnings;

use Carp;
our @CARP_NOT = qw(Net::SSH::Any);

sub _new {
    my ($class, $any, $blocking, %pipe) = @_;
    $pipe{any} = $any;
    $pipe{blocking} = 1;
    $pipe{bin} = '';
    my $pipe = \%pipe;
    bless $pipe, $class;
}

sub wait_for_data { shift->_wait_for_data }

sub blocking {
    my $pipe = shift;
    $pipe->{blocking} = !!shift if @_;
    $pipe->{blocking};
}

sub sysread {
    my ($pipe, undef, $len, $off, $err) = @_;
    $any = $pipe->{any};
    $any->_clear_error or return;

    if (defined $len) {
        return 0 if $len < 0;
    }
    else {
        $len = 34000;
    }

    $_[1] = '' unless defined $_[1];
    if (defined $off) {
        if ($off < 0) {
            $off += length $_[1];
            croak "Offset outside string" if $off < 0;
        }
        elsif (my $after = length $_[1] - $off) {
            if ($after > 0) {
                $_[1] .= ("\x00" x $after);
            }
            else { # $after < 0
                substr ($_[1], $off) = '';
            }
        }
    }
    else {
        $off = 0;
    }
    $pipe->_sysread($len, $err, $_[1]);
}

sub syswrite {
    my ($pipe, undef, $len, $off, $err) = @_;
    $any = $pipe->{any};
    $any->_clear_error or return;

    if (defined $off) {
        if ($off < 0) {
            $off += length $_[1];
            croak "Offset outside string" if $off < 0;
        }
        elsif ($off >= length $_[1]) {
            return 0;
        }
    }
    else {
        $off = 0;
    }

    my $available = length $_[1] - $off;
    if (defined $len) {
        $len = $available if $len > $available;
        $len or return 0;
    }
    else {
        $len = $available;
    }
    $pipe->_syswrite($len, $off, $_[1]);
}

sub print {
    my $pipe = shift;
    my $any = $pipe->{any};
    local $pipe->{blocking};
    my $buf = shift;
    my $total = 0;
    my $ended;
    while (length $buf or not $ended) {
        while (length $buf < 34000 and not $ended) {
            if (@_) {
                $buf .= "$," . shift @_;
            }
            else {
                $buf .= $\;
                $ended = 1;
                last;
            }
        }
        if (my $bytes = $pipe->_syswrite($buf)) {
            substr($buf, 0, $bytes, '');
            $total += $bytes;
        }
        elsif (my $error = $any->error) {
            last unless $error == SSHA_EAGAIN;
            $any->_clear_error;
            $pipe->wait_for_data(0.2);
        }
        else {
            # and so, what?
        }
    }
    return $total;
}

sub readline {
    my $pipe = shift;
    my $any = $pipe->{any};
    local $pipe->{blocking};
    for my $bin ($pipe->{bin}) {
        while (1) {
            my $ix = index $bin, $/;
            $ix >= 0 and return substr $bin, 0, $ix + length $/, '';

           $pipe->_sysread($bin, 34000);
    }

}

sub send_eof {
    my $pipe = shift;
    $pipe->{eof_sent} ||= $pipe->_send_eof;
}

sub eof {
    my $pipe = shift;
    $pipe->{eof} ||= $pipe->_eof;
}

sub close {
    my $pipe = shift;
    $pipe->{closed} ||= $pipe->_close;
}
1;
