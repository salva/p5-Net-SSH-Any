package Net::SSH::Any;

our $VERSION = '0.03';

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
                 password => $passwd,
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
    return if ( $error and
                ( $error == SSHA_NO_BACKEND_ERROR or
                  $error == SSHA_BACKEND_ERROR or
                  $error == SSHA_CONNECTION_ERROR ) );
    $any->{error} = 0;
    1;
}

sub _set_error {
    my $any = shift;
    my $code = shift || 0;
    my @msg = grep { defined && length } @_;
    @msg = "Unknown error $code" unless @msg;
    my $error = $any->{error} = ( $code
                                  ? Scalar::Util::dualvar($code, join(': ', @{$any->{error_prefix}}, @msg))
                                  : 0 );
    $debug and $debug & 1 and _debug "set_error($code - $error)";
    return $error
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
                   $any->{stream_encoding})
}

sub _delete_argument_encoding {
    my ($any, $opts) = @_;
    _first_defined(delete $opts->{argument_encoding},
                   delete $opts->{encoding},
                   $any->{argument_encoding})
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

sub _encode_args {
    if (@_ > 2) {
        my $any = shift;
        my $encoding = shift;
        local $any->{error_prefix} = [@{$any->{error_prefix}}, "argument encoding failed"];
        if (my $enc = $any->_find_encoding($encoding)) {
            $any->_encode_data($enc, @_);
        }
        return !$any->{_error};
    }
    1;
}

sub _quote_args {
    my $any = shift;
    my $opts = shift;
    ref $opts eq 'HASH' or die "internal error";
    my $quote = delete $opts->{quote_args};
    my $glob_quoting = delete $opts->{glob_quoting};
    my $argument_encoding =  $any->_delete_argument_encoding($opts);
    $quote = (@_ > 1) unless defined $quote;

    my @quoted;
    if ($quote) {
        my $quoter_glob = $any->_arg_quoter_glob;
        my $quoter = ($glob_quoting
                      ? $quoter_glob
                      : $any->_arg_quoter);

        # foo   => $quoter
        # \foo  => $quoter_glob
        # \\foo => no quoting at all and disable extended quoting as it is not safe
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
    }
    else {
        croak "reference found in argument list when argument quoting is disabled" if (grep ref, @_);
        @quoted = @_;
    }
    $any->_encode_args($argument_encoding, @quoted);
    $debug and $debug & 1024 and _debug("command+args: @quoted");
    wantarray ? @quoted : join(" ", @quoted);
}

sub _delete_stream_encoding_and_encode_input_data {
    my ($any, $opts) = @_;
    my $stream_encoding = $any->_delete_stream_encoding($opts) or return;
    $debug and $debug & 1024 and _debug("stream_encoding: "
                                        . ($stream_encoding ? $stream_encoding : '<undef>') );
    my @input = grep defined, _array_or_scalar_to_list delete $opts->{stdin_data};
    $any->_encode_data($stream_encoding => @input) or return;
    $opts->{stdin_data} = \@input;
    $stream_encoding
}

sub _check_child_error {
    my $any = shift;
    $any->error and return;
    if ($?) {
        $any->_set_error(SSHA_REMOTE_CMD_ERROR,
                         "remote command failed with code " . ($? >> 8)
                         . " and signal " . ($? & 255));
        return;
    }
    return 1;
}

_sub_options capture => qw(timeout stdin_data stderr_to_stdout stderr_discard
                           stderr_fh stderr_file);
sub capture {
    my $any = shift;
    $any->_clear_error or return undef;
    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());
    my $stream_encoding = $any->_delete_stream_encoding_and_encode_input_data(\%opts) or return;
    my $cmd = $any->_quote_args(\%opts, @_);
    _croak_bad_options %opts;
    my $out = $any->_capture(\%opts, $cmd);
    if ($stream_encoding) {
        $any->_decode_data($stream_encoding => $out) or return;
    }
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
    if ($stream_encoding) {
        $any->_decode_data($stream_encoding => $out) or return;
        $any->_decode_data($stream_encoding => $err) or return;
    }
    wantarray ? ($out, $err) : $out
}

_sub_options system => qw(timeout stdin_data
                          stdout_fh stdout_file stdout_discard
                          stderr_to_stdout stderr_fh stderr_file stderr_discard);
sub system {
    my $any = shift;
    $any->_clear_error or return undef;
    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());
    my $stream_encoding = $any->_delete_stream_encoding_and_encode_input_data(\%opts) or return;
    my $cmd = $any->_quote_args(\%opts, @_);
    _croak_bad_options %opts;
    $any->_system(\%opts, $cmd);
    $any->_check_child_error;
}

_sub_options pipe => qw(stderr_to_stdout stderr_discard);
sub pipe {
    my $any = shift;
    $any->_clear_error or return undef;
    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());
    my $cmd = $any->_quote_args(\%opts, @_);
    _croak_bad_options %opts;
    $any->_pipe(\%opts, $cmd);
}

_sub_options sftp => qw(fs_encoding timeout block_size queue_size autoflush write_delay
                        read_ahead late_set_perm autodie);
sub sftp {
    my ($any, %opts) = @_;
    $opts{fs_encoding} = $any->_delete_argument_encoding(\%opts)
        unless defined $opts{fs_encoding};
    _croak_bad_options %opts;
    $any->_load_module('Net::SFTP::Foreign') or return;
    $any->_sftp(\%opts)
}

my %loaded;
sub _load_module {
    my ($any, $module) = @_;
    $loaded{$module} ||= eval "require $module; 1" and return 1;
    $any->_set_error(SSHA_UNIMPLEMENTED_ERROR, "Unable to load perl module $module");
    return;
}

# transparently delegate method calls to backend packages:
sub AUTOLOAD {
    our $AUTOLOAD;
    my ($name) = $AUTOLOAD =~ /([^:]*)$/;
    no strict 'refs';
    my $sub = sub {
        goto &{"$_[0]->{backend_module}::$name"}
    };
    *{$AUTOLOAD} = $sub;
    goto &$sub;
}

sub DESTROY {
    my $any = shift;
    my $be = $any->{backend_module};
    if (defined $be) {
        my $sub = $be->can('DESTROY');
        $sub->($any) if $sub;
    }
}

1;

__END__

=head1 NAME

Net::SSH::Any - Use any SSH module

=head1 SYNOPSIS

  use Net::SSH::Any;

  my $ssh = Net::SSH::Any->new($host, user => $user, password => $passwd);

  my @out = $ssh->capture(cat => "/etc/passwd");
  my ($out, $err) = $ssh->capture2("ls -l /");
  $ssh->system("foo");

  my $sftp = $ssh->sftp; # returns Net::SFTP::Foreign object
  $sftp->put($local_path, $remote_path);

=head1 DESCRIPTION

  *******************************************************************
  ***                                                             ***
  *** NOTE: This is a very early release that may contain lots of ***
  *** bugs. The API is not stable and may change between releases ***
  ***                                                             ***
  *******************************************************************

Currently, there are several SSH client modules available from CPAN,
but no one can be used on all the situations.

L<Net::SSH::Any> is an adapter module offering an unified API with a
plugin architecture that allows to use the other modules as
backends.

It will work in the same way across most operating systems and
installations as far as any of the supported backend modules is also
installed.

The currently supported backend modules are L<Net::OpenSSH> and
L<Net::SSH2> and I plan to write a backend module on top of the ssh
binary and maybe another one for L<Net::SSH::Perl>.

The API is mostly a subset of the one from L<Net::OpenSSH>, though
there are some minor deviations in some methods.

=head1 SEE ALSO

L<Net::OpenSSH>, L<Net::SSH2>, L<Net::SSH::Perl>.

L<Net::SFTP::Foreign>

=head1 BUGS AND SUPPORT

To report bugs send an email to the address that appear below or use
the CPAN bug tracking system at L<http://rt.cpan.org>.

B<Post questions related to how to use the module in Perlmonks>
L<http://perlmoks.org/>, you will probably get faster responses than
if you address me directly and I visit Perlmonks quite often, so I
will see your question anyway.

The source code of this module is hosted at GitHub:
L<http://github.com/salva/p5-Net-SSH-Any>.

=head2 Commercial support

Commercial support, professional services and custom software
development around this module are available through my current
company. Drop me an email with a rough description of your
requirements and we will get back to you ASAP.

=head2 My wishlist

If you like this module and you're feeling generous, take a look at my
Amazon Wish List: L<http://amzn.com/w/1WU1P6IR5QZ42>.

Also consider contributing to the OpenSSH project this module builds
upon: L<http://www.openssh.org/donations.html>.

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2011-2012 by Salvador Fandiño, E<lt>sfandino@yahoo.comE<gt>

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.12.4 or,
at your option, any later version of Perl 5 you may have available.

=cut
