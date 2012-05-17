package Net::SSH::Any;

our $VERSION = '0.01';

use strict;
use warnings;
use Carp;

use Net::SSH::Any::Util;
use Net::SSH::Any::Constants qw(:error);
use Scalar::Util qw(dualvar);
use Encode ();

my $REQUIRED_BACKEND_VERSION = '1';
our @BACKENDS = qw(Net::OpenSSH Net::SSH2 Net::SSH::Perl Net::SSH);

# regexp from Regexp::IPv6
my $IPv6_re = qr((?-xism::(?::[0-9a-fA-F]{1,4}){0,5}(?:(?::[0-9a-fA-F]{1,4}){1,2}|:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})))|[0-9a-fA-F]{1,4}:(?:[0-9a-fA-F]{1,4}:(?:[0-9a-fA-F]{1,4}:(?:[0-9a-fA-F]{1,4}:(?:[0-9a-fA-F]{1,4}:(?:[0-9a-fA-F]{1,4}:(?:[0-9a-fA-F]{1,4}:(?:[0-9a-fA-F]{1,4}|:)|(?::(?:[0-9a-fA-F]{1,4})?|(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))))|:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})?|))|(?::(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|:[0-9a-fA-F]{1,4}(?::(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[0-9a-fA-F]{1,4}){0,2})|:))|(?:(?::[0-9a-fA-F]{1,4}){0,2}(?::(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[0-9a-fA-F]{1,4}){1,2})|:))|(?:(?::[0-9a-fA-F]{1,4}){0,3}(?::(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[0-9a-fA-F]{1,4}){1,2})|:))|(?:(?::[0-9a-fA-F]{1,4}){0,4}(?::(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[0-9a-fA-F]{1,4}){1,2})|:))));

sub new {
    my $class = shift;
    my %opts = (@_ & 1 ? (host => @_) : @_);

    my $target = delete $opts{host};
    defined $target or croak "mandatory parameter host missing";

    my ($user, $passwd, $ipv6, $host, $port) =
        $target =~ m{^
                     \s*               # space
                     (?:
                         ([^\@:]+)       # username
                         (?::(.*))?      # : password
                         \@              # @
                     )?
                     (?:               # host
                         (              #   IPv6...
                             \[$IPv6_re\] #     [IPv6]
                         |            #     or
                             $IPv6_re     #     IPv6
                         )
                     |              #   or
                         ([^\[\]\@:]+)  #   hostname / ipv4
                     )
                     (?::([^\@:]+))?   # port
                     \s*               # space
                     $}ix or croak "bad host/target '$target' specification";

    ($host) = $ipv6 =~ /^\[?(.*)\]?$/ if defined $ipv6;

    $user = delete $opts{user} unless defined $user;
    $port = delete $opts{port} unless defined $port;
    $passwd = delete $opts{passwd} unless defined $passwd;
    $passwd = delete $opts{password} unless defined $passwd;
    my ($key_path, $passphrase);
    unless (defined $passwd) {
        $key_path = delete $opts{key_path};
        $passphrase = delete $opts{passphrase};
    }
    my $timeout = delete $opts{timeout};
    my $target_os = _first_defined delete $opts{target_os}, 'unix';
    my $encoding = delete $opts{encoding};
    my $stream_encoding =
        _first_defined delete $opts{stream_encoding}, $encoding, 'utf8';
    my $argument_encoding =
        _first_defined delete $opts{argument_encoding}, $encoding, 'utf8';

    my $backend_opts = delete $opts{backend_opts};

    my $any = { host => $host,
                 user => $user,
                 port => $port,
                 passwd => $passwd,
                 key_path => $key_path,
                 passphrase => $passphrase,
                 timeout => $timeout,
                 target_os => $target_os,
                 stream_encoding => $stream_encoding,
                 argument_encoding => $argument_encoding,
                 backend_opts => $backend_opts,
                 error_prefix => [],
               };
    bless $any, $class;

    my $backends = delete $opts{backends};
    $backends = [@BACKENDS] unless defined $backends;
    $backends = [$backends] unless ref $backends;

    $any->_load_backend(@$backends)
        and $any->_connect;

    $any;
}

sub error { shift->{error} }

sub die_on_error {
    my $ssh = shift;
    $ssh->{error} and croak(join(': ', @_, "$ssh->{error}"));
    1;
}

sub _clear_error {
    my $any = shift;
    my $error = $any->{error};
    $error and $error == SSHA_NO_BACKEND_ERROR and return;
    $any->{error} = 0;
    1;
}

sub _set_error {
    my $any = shift;
    my $code = shift || 0;
    my @msg = grep { defined && length } @_;
    @msg = "Unknown error $code" unless @msg;
    my $err = $any->{error} = ( $code
                                ? Scalar::Util::dualvar($code, join(': ', @{$any->{error_prefix}}, @msg));
                                : 0 );
    $debug and $debug & 1 and _debug "set_error($code - $err)";
    return $err
}

sub _or_set_error {
    my $any = shift;
    $any->{error} or $any->_set_error(@_);
}

sub _load_backend {
    my $any = shift;
    for my $backend (@_) {
        my $module = $backend;
        $module =~ s/::/_/g;
        $module = "Net::SSH::Any::Backend::$module";
        local ($@, $SIG{__DIE__});
        my $ok = eval <<EOE;
no strict;
no warnings;
require $module;
$module->_backend_api_version >= $REQUIRED_BACKEND_VERSION
EOE
        if ($ok) {
            $any->{backend} = $backend;
            $any->{backend_module} = $module;
            return 1;
        }
        elsif ($debug and $debug & 1) {
            _debug "failed to load backend $backend, module $module, error follows...\n$@"
        }
    }
    $any->_set_error(SSHA_NO_BACKEND_ERROR, "no backend available");
    undef;
}

sub _delete_stream_encoding {
    my ($any, $opts) = @_;
    _first_defined(delete $opts->{stream_encoding},
                   $opts->{encoding},
                   $any->{stream_encoding},
                   'bytes');
}

sub _delete_argument_encoding {
    my ($any, $opts) = @_;
    _first_defined(delete $opts->{argument_encoding},
                   delete $opts->{encoding},
                   $any->{argument_encoding},
                   'bytes');
}

sub _find_encoding {
    my ($any, $encoding, $data) = @_;
    my $enc = Encode::find_encoding($encoding)
        or $any->_or_set_error(SSHA_ENCODING_ERROR, "bad encoding '$encoding'");
    return $enc
}

sub _check_error_after_eval {
    if ($@) {
        my ($any, $code) = @_;
        unless ($any->{error}) {
            my $err = $@;
            $err =~ s/(.*) at .* line \d+.$/$1/;
            $any->_set_error($code, $err);
        }
        return 0;
    }
    1
}

sub _encode_data {
    my $any = shift;
    my $encoding = shift;
    if (@_) {
        my $enc = $any->_find_encoding($encoding) or return;
        local $any->{error_prefix} = [@{$any->{error_prefix}}, "data encoding failed"];
        local ($@, $SIG{__DIE__});
        eval { defined and $_ = $enc->encode($_, Encode::FB_CROAK()) for @_ };
        $any->_check_error_after_eval(SSHA_ENCODING_ERROR) or return;
    }
    1
}

sub _decode_data {
    my $any = shift;
    my $encoding = shift;
    my $enc = $any->_find_encoding($encoding) or return;
    if (@_) {
        local ($@, $SIG{__DIE__});
        eval { defined and $_ = $enc->decode($_, Encode::FB_CROAK()) for @_ };
        $any->_check_error_after_eval(SSHA_ENCODING_ERROR) or return;
    }
    1;
}
my $noquote_class = '\\w/\\-=@';
my $glob_class    = '*?\\[\\],{}:!.^~';

sub _arg_quoter {
    sub {
        my $quoted = join '',
            map { ( m|^'$|                  ? "\\'"  :
                    m|^[$noquote_class]*$|o ? $_     :
                                              "'$_'" ) } split /(')/, $_[0];
        length $quoted ? $quoted : "''";
    }
}

sub _arg_quoter_glob {
    sub {
	my $arg = shift;
        my @parts;
        while ((pos $arg ||0) < length $arg) {
            if ($arg =~ m|\G'|gc) {
                push @parts, "\\'";
            }
            elsif ($arg =~ m|\G([$noquote_class$glob_class]+)|gco) {
                push @parts, $1;
            }
            elsif ($arg =~ m|\G(\\[$glob_class\\])|gco) {
                push @parts, $1;
            }
            elsif ($arg =~ m|\G\\|gc) {
                push @parts, '\\\\'
            }
            elsif ($arg =~ m|\G([^$glob_class\\']+)|gco) {
                push @parts, "'$1'";
            }
            else {
                require Data::Dumper;
                $arg =~ m|\G(.+)|gc;
                die "Internal error: unquotable string:\n". Data::Dumper::Dumper($1) ."\n";
            }
        }
        my $quoted = join('', @parts);
        length $quoted ? $quoted : "''";

	# my $arg = shift;
        # return $arg if $arg =~ m|^[\w/\-+=?\[\],{}\@!.^~]+$|;
	# return "''" if $arg eq '';
        # $arg =~ s|(?<!\\)([^\w/\-+=*?\[\],{}:\@!.^\\~])|ord($1) > 127 ? $1 : $1 eq "\n" ? "'\n'" : "\\$1"|ge;
	# $arg;
    }
}

sub _quote_args {
    my $any = shift;
    my $opts = shift;
    ref $opts eq 'HASH' or die "internal error";
    my $quote = delete $opts->{quote_args};
    my $glob_quoting = delete $opts->{glob_quoting};
    $quote = (@_ > 1) unless defined $quote;

    unless ($quote) {
        croak "reference found in argument list when argument quoting is disabled" if (grep ref, @_);
        return wantarray ? @_ : join(" ", @_);
    }

    my $quoter_glob = $any->_arg_quoter_glob;
    my $quoter = ($glob_quoting
                  ? $quoter_glob
                  : $any->_arg_quoter);

    # foo   => $quoter
    # \foo  => $quoter_glob
    # \\foo => no quoting at all and disable extended quoting as it is not safe
    my @quoted;
    for (@_) {
        if (ref $_) {
            if (ref $_ eq 'SCALAR') {
                push @quoted, $quoter_glob->($$_);
            }
            elsif (ref $_ eq 'REF' and ref $$_ eq 'SCALAR') {
                push @quoted, $$$_;
            }
            else {
                croak "invalid reference in remote command argument list"
            }
        }
        else {
            push @quoted, $quoter->($_);
        }
    }
    wantarray ? @quoted : join(" ", @quoted);
}

sub _delete_stream_encoding_and_encode_input_data {
    my ($any, $opts) = @_;
    my $stream_encoding = $any->_delete_stream_encoding($opts) or return;
    my @input = grep defined, _array_or_scalar_to_list delete $opts->{stdin_data};
    $any->_encode_data($stream_encoding => @input) or return;
    $opts->{stdin_data} = \@input;
    $stream_encoding
}

_sub_options capture => qw(timeout stdin_data stderr_to_stdout);
sub capture {
    my $any = shift;
    $any->_clear_error or return undef;
    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());
    my $stream_encoding = $any->_delete_stream_encoding_and_encode_input_data(\%opts) or return;
    my $cmd = $any->_quote_args(\%opts, @_);
    _croak_bad_options %opts;
    my $out = $any->_capture(\%opts, $cmd);
    $any->_decode_data($stream_encoding => $out) or return;
    if (wantarray) {
        my $pattern = quotemeta $/;
        return split /(?<=$pattern)/, $out;
    }
    $out
}

_sub_options capture2 => qw(timeout stdin_data);
sub capture2 {
    my $any = shift;
    $any->_clear_error or return undef;
    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());
    my $stream_encoding = $any->_delete_stream_encoding_and_encode_input_data(\%opts) or return;
    my $cmd = $any->_quote_args(\%opts, @_);
    _croak_bad_options %opts;
    my ($out, $err) = $any->_capture2(\%opts, $cmd);
    $any->_decode_data($stream_encoding => $out) or return;
    $any->_decode_data($stream_encoding => $err) or return;
    wantarray ? ($out, $err) : $out
}

_sub_options system => qw(timeout stdin_data);
sub system {
    my $any = shift;
    $any->_clear_error or return undef;
    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());
    my $stream_encoding = $any->_delete_stream_encoding_and_encode_input_data(\%opts) or return;
    my $cmd = $any->_quote_args(\%opts, @_);
    _croak_bad_options %opts;
    $any->_system(\%opts, $cmd);
}

# transparently delegate method calls to backend packages:
sub AUTOLOAD {
    our $AUTOLOAD;
    my ($name) = $AUTOLOAD =~ /([^:]*)$/;
    no strict 'refs';
    my $sub = sub { goto &{"$_[0]->{backend_module}::$name"} };
    *{$AUTOLOAD} = $sub;
    goto &$sub;
}

1;

__END__

=head1 NAME

Net::SSH::Any - Use any SSH module

=head1 SYNOPSIS

  use Net::SSH::Any;

  my $ssh = Net::SSH::Any->new($host, user => $user, password => $passwd);

  my ($out, $err) = $ssh->capture2("ls -l /");
  $ssh->system("foo");

=head1 DESCRIPTION


=head1 SEE ALSO

L<Net::OpenSSH>, L<Net::SSH2>, L<Net::SSH::Perl>

L<Net::SFTP::Foreign>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2011-2012 by Salvador Fandiño, E<lt>sfandino@yahoo.comE<gt>

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.12.4 or,
at your option, any later version of Perl 5 you may have available.


=cut
