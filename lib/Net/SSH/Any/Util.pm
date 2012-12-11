package Net::SSH::Any::Util;

BEGIN { *debug = \$Net::SSH::Any::debug }

use strict;
use warnings;
use Carp;
use File::Spec;

require Exporter;
our @ISA = qw(Exporter);
our @EXPORT = qw($debug _debug _debug_dump _debug_hexdump
                 _sub_options _croak_bad_options
                 _first_defined _array_or_scalar_to_list
                 _inc_numbered);

our $debug ||= 0;

sub _debug {
    local ($@, $!, $_);
    print STDERR '# ', (map { defined($_) ? $_ : '<undef>' } @_), "\n"
}

sub _debug_dump {
    require Data::Dumper;
    local $Data::Dumper::Terse = 1;
    local $Data::Dumper::Indent = 0;
    my $head = shift;
    _debug("$head: ", Data::Dumper::Dumper(@_));
}

sub _debug_hexdump {
    no warnings qw(uninitialized);
    my $head = shift;
    _debug("$head:");

    my $data = shift;
    while ($data =~ /(.{1,32})/smg) {
        my $line=$1;
        my @c= (( map { sprintf "%02x",$_ } unpack('C*', $line)),
                (("  ") x 32))[0..31];
        $line=~s/(.)/ my $c=$1; unpack("c",$c)>=32 ? $c : '.' /egms;
        print STDERR "#> ", join(" ", @c, '|', $line), "\n";
    }
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

sub _inc_numbered {
    $_[0] =~ s{^(.*)\((\d+)\)((?:\.[^\.]*)?)$}{"$1(" . ($2+1) . ")$3"}e or
    $_[0] =~ s{((?:\.[^\.]*)?)$}{(1)$1};
    $debug and $debug & 128 and _debug("numbering to: $_[0]");
}

# sub _mkpath {
#     my $path = shift;
#     my @start = File::Spec->splitdir(File::Spec->rel2abs($path));
#     my @end;
#     while (@start) {
# 	my $start = File::Spec->join(@start);
# 	last if -d $start;
# 	push @end, pop @start;
#     }
#     while (@end) {
# 	push @start, pop @end;
# 	my $start = File::Spec->join(@start);
# 	return unless -d $start or mkdir $start;
#     }
#     1;
# }

1;
