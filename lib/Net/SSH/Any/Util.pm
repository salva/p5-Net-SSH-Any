package Net::SSH::Any::Util;

BEGIN { *debug = \$Net::SSH::Any::debug }

use strict;
use warnings;
use Carp;

require Exporter;
our @ISA = qw(Exporter);
our @EXPORT = qw($debug _debug _debug_dump
                 _sub_options _croak_bad_options
                 _first_defined _array_or_scalar_to_list);

our $debug ||= 0;

sub _debug { print STDERR '# ', (map { defined($_) ? $_ : '<undef>' } @_), "\n" }

sub _debug_dump {
    require Data::Dumper;
    local $Data::Dumper::Terse = 1;
    local $Data::Dumper::Indent = 0;
    my $head = shift;
    _debug("$head: ", Data::Dumper::Dumper(@_));
}

sub _first_defined { defined && return $_ for @_; return }

my %good;

sub _sub_options {
    my $sub = shift;
    my $pkg = caller;
    $good{"${pkg}::$sub"} = { map { $_ => 1 } @_ };
}

sub _croak_bad_options (\%) {
    my $opts = shift;
    if (%$opts) {
        my $sub = (caller 1)[3];
        my $good = $good{$sub};
        my @keys = ( $good ? grep !$good->{$_}, keys %$opts : keys %$opts);
        if (@keys) {
            croak "Invalid or bad combination of options ('" . join("', '", @keys) . "')";
        }
    }
}

sub _array_or_scalar_to_list { map { defined($_) ? (ref $_ eq 'ARRAY' ? @$_ : $_ ) : () } @_ }

1;
