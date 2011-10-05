package Net::SSH::Any;

our $VERSION = '0.01';

use strict;
use warnings;
use Carp;

use Net::SSH::Any::Util;
use Net::SSH::Any::Constants qw(:error);

my $REQUIRED_BACKEND_VERSION = '1';
our @BACKENDS = qw(Net::OpenSSH Net::SSH2 Net::SSH::Perl Net::SSH);

sub new {
    my $class = shift;
    my %opts = (@_ & 1 ? host => @_ : @_);

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
        _first_defined delete $opts{stream_encoding}, $encoding;
    my $argument_encoding =
        _first_defined delete $opts{argument_encoding}, $encoding;

    my $backend_opts = delete $opts{backend_opts};

    my $self = { host => $host,
                 user => $user,
                 port => $port,
                 passwd => $passwd,
                 key_path => $key_path,
                 passphrase => $passphrase,
                 timeout => $timeout,
                 target_os => $target_os,
                 stream_encoding => $stream_encoding,
                 arguments_encoding => $arguments_encoding,
                 backend_opts => $backend_opts,
                 error_prefix => [],
               };
    bless $self, $class;

    my $backends = delete $opts{backends};
    $backends = [@BACKENDS] unless defined $backends;
    $backends = [$backends] unless ref $backends;

    $self->_load_backend(@$backends)
        and $self->_connect;
    }

    $self;
}

sub error { shift->{error} }

sub _set_error {
    my $self = shift;
    my $code = shift || 0;
    my $err = $self->{_error} = ( $code
                                  ? Scalar::Util::dualvar($code, join(': ', @{$self->{_error_prefix}},
                                                                      (@_ ? @_ : "Unknown error $code")))
                                  : 0 );
    $debug and $debug & 1 and _debug "set_error($code - $err)";
    return $err
}

sub _or_set_error {
    my $self = shift;
    $self->{_error} or $self->_set_error(@_);
}

sub die_on_error {
    my $ssh = shift;
    $ssh->{_error} and croak(@_ ? "@_: $ssh->{_error}" : $ssh->{_error});
}

sub _load_backend {
    my $self = shift;
    for my $backend (@_) {
        my $module = $backend;
        $module =~ s/::/_/g;
        $module = "Net::SSH::Any::Backend::$module";
        local $@, $SIG{__DIE__};
        my $ok = eval <<'EOE';
no strict;
no warnings;
require $module;
$module->_backend_api_version >= $REQUIRED_BACKEND_VERSION
EOE
        if ($ok) {
            $self->{backend} = $backend;
            $self->{backend_module} = $module;
            return 1;
        }
    }
    $self->_set_error("no backend available");
    undef;
}

sub _delete_stream_encoding {
    my ($self, $opts) = @_;
    _first_defined(delete $opts->{stream_encoding},
                   $opts->{encoding},
                   $self->{_default_stream_encoding});
}

sub _delete_argument_encoding {
    my ($self, $opts) = @_;
    _first_defined(delete $opts->{argument_encoding},
                   delete $opts->{encoding},
                   $self->{_default_argument_encoding});
}

sub _find_encoding {
    my ($self, $encoding, $data) = @_;
    if (defined $encoding and $encoding ne 'bytes') {
        require Encode;
        my $enc = Encode::find_encoding($encoding);
        unless (defined $enc) {
            $self->_set_error(SSHA_ENCODING_ERROR, "bad encoding '$encoding'");
            return
        }
        return $enc
    }
    return undef
}

sub _eval_to_error {
    if ($@) {
        my ($self, $code) = @_;
        my $err = $@;
        $err =~ s/(.*) at .* line \d+.$/$1/;
        $self->_set_error($code, $err);
    }
}

sub _encode_data {
    my $self = shift;
    my $encoding = shift;
    my $enc = $self->_find_encoding($encoding);
    if ($enc and @_) {
        local $self->{_error_prefix} = [@{$self->{_error_prefix}}, "data encoding failed"];
        local $@;
        eval {
            defined and $_ = $enc->encode($_, Encode::FB_CROAK()) for @_
        };
        $self->_eval_to_error(ASSH_ENCODING_ERROR);
    }
    !$self->error;
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
    my $self = shift;
    my $opts = shift;
    ref $opts eq 'HASH' or die "internal error";
    my $quote = delete $opts->{quote_args};
    my $quote_extended = delete $opts->{quote_args_extended};
    my $glob_quoting = delete $opts->{glob_quoting};
    $quote = (@_ > 1) unless defined $quote;

    if ($quote) {
	my $quoter_glob = $self->_arg_quoter_glob;
	my $quoter = ($glob_quoting
		      ? $quoter_glob
		      : $self->_arg_quoter);

	# foo   => $quoter
	# \foo  => $quoter_glob
	# \\foo => no quoting at all and disable extended quoting as it is not safe
	my @quoted;
	for (@_) {
	    if (ref $_) {
		if (ref $_ eq 'SCALAR') {
		    push @quoted, $quoter_glob->($self->_expand_vars($$_));
		}
		elsif (ref $_ eq 'REF' and ref $$_ eq 'SCALAR') {
		    push @quoted, $self->_expand_vars($$$_);
		    undef $quote_extended;
		}
		else {
		    croak "invalid reference in remote command argument list"
		}
	    }
	    else {
		push @quoted, $quoter->($self->_expand_vars($_));
	    }
	}

	if ($quote_extended) {
	    push @quoted, '</dev/null' if $opts->{stdin_discard};
	    if ($opts->{stdout_discard}) {
		push @quoted, '>/dev/null';
		push @quoted, '2>&1' if ($opts->{stderr_to_stdout} || $opts->{stderr_discard})
	    }
	    else {
		push @quoted, '2>/dev/null' if $opts->{stderr_discard};
	    }
	}
	wantarray ? @quoted : join(" ", @quoted);
    }
    else {
	croak "reference found in argument list when argument quoting is disabled"
	    if (grep ref, @_);

	my @args = $self->_expand_vars(@_);
	wantarray ? @args : join(" ", @args);
    }
}

_sub_options capture => qw(timeout stdin_data);

sub capture {
    my $self = shift;
    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());
    my $stream_encoding = $self->_delete_stream_encoding(\%opts);
    my @input = grep defined, _array_or_scalar_to_list delete $opts{stdin_data};
    $self->_encode_data($stream_encoding => @input) or return ();
    my $cmd = $self->_quote_args(\%opts, @_);
    _croak_bad_options %opts;
    $opts{stdin_data} = \@input;
    my $output = $self->_capture(\%opts, $cmd);
    $self->_decode_data($stream_encoding => $out) or return ();
    if (wantarray) {
        my $pattern = quotemeta $/;
        return split /(?<=$pattern)/, $output;
    }
    $output
}

# transparently delegate method calls to backend packages:
sub AUTOLOAD {
    our $AUTOLOAD;
    my ($name) = $AUTOLOAD =~ /([^:]*)$/;
    my $sub = sub { ( ($_[0]->{backend_module} or croak "Backend module not set" )
                      -> can($name) or croak "Undefined subroutine &$AUTOLOAD called" )
                        -> (@_) };
    no strict refs;
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

Stub documentation for Net::SSH::Any, created by h2xs. It looks like the
author of the extension was negligent enough to leave the stub
unedited.

=head1 SEE ALSO

Mention other useful documentation such as the documentation of
related modules or operating system documentation (such as man pages
in UNIX), or any relevant external documentation such as RFCs or
standards.

If you have a mailing list set up for your module, mention it here.

If you have a web site set up for your module, mention it here.

=head1 AUTHOR

Salvador Fandiño, E<lt>salva@E<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2011 by Salvador Fandiño

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.12.4 or,
at your option, any later version of Perl 5 you may have available.


=cut
