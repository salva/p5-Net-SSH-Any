package Net::SSH::Any;

our $VERSION = '0.05';

use strict;
use warnings;
use Carp;

use Net::SSH::Any::Util;
use Net::SSH::Any::Constants qw(:error);
use Scalar::Util qw(dualvar);
use Encode ();

our @CARP_NOT = qw(Net::SSH::Any::Util);

my $REQUIRED_BACKEND_VERSION = '1';
our @BACKENDS = qw(Net::OpenSSH Net::SSH2 Net::SSH::Perl SSH_Cmd);

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
    my $io_timeout = _first_defined delete $opts{io_timeout}, 120;
    my $timeout = delete $opts{timeout};
    my $target_os = _first_defined delete $opts{target_os}, 'unix';
    my $encoding = delete $opts{encoding};
    my $stream_encoding =
        _first_defined delete $opts{stream_encoding}, $encoding, 'utf8';
    my $argument_encoding =
        _first_defined delete $opts{argument_encoding}, $encoding, 'utf8';

    my $known_hosts_path = delete $opts{known_hosts_path};
    my $strict_host_key_checking = _first_defined delete $opts{strict_host_key_checking}, 1;
    my $compress = _first_defined delete $opts{compress}, 1;
    my $backend_opts = delete $opts{backend_opts};

    my (%remote_cmd, %local_cmd);
    for (keys %opts) {
        /^remote_(.*)_cmd$/ and $remote_cmd{$1} = $opts{$_};
        /^local_(.*)_cmd$/ and $local_cmd{$1} = $opts{$_};
    }

    my $any = { host => $host,
                user => $user,
                port => $port,
                password => $passwd,
                key_path => $key_path,
                passphrase => $passphrase,
                timeout => $timeout,
                io_timeout => $io_timeout,
                target_os => $target_os,
                stream_encoding => $stream_encoding,
                argument_encoding => $argument_encoding,
                known_hosts_path => $known_hosts_path,
                strict_host_key_checking => $strict_host_key_checking,
                compress => $compress,
                backend_opts => $backend_opts,
                error_prefix => [],
                remote_cmd => \%remote_cmd,
                local_cmd => \%local_cmd,
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
    if (defined(my $data = $opts->{stdin_data})) {
        my @input = grep defined, _array_or_scalar_to_list $data;
        $any->_encode_data($stream_encoding => @input) or return;
        $opts->{stdin_data} = \@input;
    }
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

sub _open_file {
    my ($any, $def_mode, $name_or_args) = @_;
    my ($mode, @args) = (ref $name_or_args
			 ? @$name_or_args
			 : ($def_mode, $name_or_args));
    if (open my $fh, $mode, @args) {
        return $fh;
    }
    $any->_set_error(SSHA_LOCAL_IO_ERROR, "Unable to open file '@args': $!");
    return undef;
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
    my ($out) = $any->_capture(\%opts, $cmd) or return;
    $any->_check_child_error;
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
    my ($out, $err) = $any->_capture2(\%opts, $cmd) or return;
    $any->_check_child_error;
    if ($stream_encoding) {
        $any->_decode_data($stream_encoding => $out) or return;
        $any->_decode_data($stream_encoding => $err) or return;
    }
    wantarray ? ($out, $err) : $out
}

_sub_options system => qw(timeout stdin_data stdin_file stdin_fh
                          stdout_fh stdout_file stdout_discard
                          stderr_to_stdout stderr_fh stderr_file stderr_discard
                          _window_size);
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

_sub_options pipe => qw(stderr_to_stdout stderr_discard subsystem);
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

sub _scp_delegate {
    my $any = shift;
    my $class = shift;
    $any->_load_module($class) or return;
    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());
    my $obj = $class->_new($any, \%opts, @_) or return;
    $obj->run(\%opts);
}

sub scp_get         { shift->_scp_delegate('Net::SSH::Any::SCP::Getter::Standard', @_) }
sub scp_get_content { shift->_scp_delegate('Net::SSH::Any::SCP::Getter::Content',  @_) }
sub scp_mkdir       { shift->_scp_delegate('Net::SSH::Any::SCP::Putter::DirMaker', @_) }
sub scp_put         { shift->_scp_delegate('Net::SSH::Any::SCP::Putter::Standard', @_) }
sub scp_put_content { shift->_scp_delegate('Net::SSH::Any::SCP::Putter::Content', @_) }

# transparently delegate method calls to backend packages:
sub AUTOLOAD {
    our $AUTOLOAD;
    my ($name) = $AUTOLOAD =~ /([^:]*)$/;
    no strict 'refs';
    my $sub = sub {
        my $backend = $_[0]->{backend_module} or return;
        my $method = $backend->can($name)
            or croak "method '$name' not defined in backend '$backend'";
        goto &$method;
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

  **************************************************************
  ***                                                        ***
  *** NOTE: This is an early release that may contain bugs.  ***
  *** The API is not stable and may change between releases. ***
  ***                                                        ***
  **************************************************************

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

=head1 API

=head2 Optional parameters

Almost all methods in this package accept as first argument a
reference to a hash containing optional parameters. In example:

  $ssh->scp_get({recursive => 1}, $remote_src, $local_target);

The hash reference can be omitted when optional parameters are not
required. In example:

  @out = $ssh->capture("ls ~/");

=head2 Error handling

Most methods return undef or an empty list to indicate
failure. Exceptions to this rule are the constructor, which always
returns and object, and those methods able to generate partial results
as for instance <c>capture</c> or <c>scp_get_content</c>.

The L</error> method can always be used to explicitly check for
errors. For instance:

  my $out = $ssh->capture($cmd);
  $ssh->error and die "capture method failed: " . $ssh->error;

=head2 Shell quoting

By default when calling remote commands, this module tries to mimic
perl C<system> builtin in regard to argument processing.

When calling some method as, for instance, <c>capture</c>:

   $out = $ssh->capture($cmd)

The command line in C<$cmd> is first processed by the remote shell
honoring shell metacharacters, redirections, etc.

If more than one argument is passed, as in the following example:

   $out = $ssh->capture($cmd, $arg1, $arg2)

The module will escape any shell metacharacter so that effectively the
remote call is equivalent to executing the remote command without going
through a shell (the SSH protocol does not allow to do that directly).

All the methods that invoke a remote command (system, capture, etc.)
accept the option C<quote_args> that allows one to force/disable shell
quoting.

For instance, spaces in the command path will be correctly handled in
the following case:

  $ssh->system({quote_args => 1}, "/path with spaces/bin/foo");

Deactivating quoting when passing multiple arguments can also be
useful, for instance:

  $ssh->system({quote_args => 0}, 'ls', '-l', "/tmp/files_*.dat");

When the C<glob> option is set in SCP file transfer methods, it is
used an alternative quoting mechanism which leaves file wildcards
unquoted.

Another way to selectively use quote globing or fully disable quoting
for some specific arguments is to pass them as scalar references or
double scalar references respectively. In practice, that means
prepending them with one or two backslashes. For instance:

  # quote the last argument for globing:
  $ssh->system('ls', '-l', \'/tmp/my files/filed_*dat');

  # append a redirection to the remote command
  $ssh->system('ls', '-lR', \\'>/tmp/ls-lR.txt');

  # expand remote shell variables and glob in the same command:
  $ssh->system('tar', 'czf', \\'$HOME/out.tgz', \'/var/log/server.*.log');

The current shell quoting implementation expects a shell compatible
with Unix C<sh> in the remote side. It will not work as expected if
for instance, the remote machine runs Windows, VMS or if it is a
router exposing an ad-hoc shell.

As a workaround, do any required quoting yourself and pass the quoted
command as a string so that no further quoting is performed. For
instance:

  # for VMS
  $ssh->system('DIR/SIZE NFOO::USERS:[JSMITH.DOCS]*.TXT;0');


=head2 Timeouts

Several of the methods described below support a C<timeout> argument
that aborts the remote command when the given time lapses without any
data arriving via SSH.

In order to stop some remote process when it times out, the ideal
aproach would be to send appropriate signals through the SSH
connection. Unfortunatelly, neither Net::SSH2/libssh2, nor
Net::OpenSSH/OpenSSH ssh support sending arbitrary signals, even if
the SSH standard provides support for it.

As a less than perfect alternative solution, the module closes the
stdio streams of the remote process. That would deliver a SIGPIPE on
the remote process next time it tries to write something.

On the other hand timeouts due to broken connections can be detected
by other means. For instance, enabling C<SO_KEEPALIVE> on the TCP
socket, or using the protocol internal keep alive (currently, only
supported by the Net::OpenSSH backend).

=head2 Net::SSH::Any methods

These are the methods available from the module:

=over 4

=item $ssh = Net::SSH::Any->new($target, %opts)

This method creates a new Net::SSH::Any object representing a SSH
connection to the remote machine as described by C<$target>.

C<$target> has to follow the pattern
<c>user:password@hostname:port</c> where all parts but hostname are
optional. For instance, the following constructor calls are all
equivalent:

   Net::SSH::Any->new('hberlioz:f#nta$71k6@harpe.cnsmdp.fr:22');
   Net::SSH::Any->new('hberlioz@harpe.cnsmdp.fr',
                      password => 'f#nta$71k6', port => 22);
   Net::SSH::Any->new('harpe.cnsmdp.fr',
                      user => 'hberlioz', password => 'f#nta$71k6');

=over 4

=item user => $user_name

Login name

=item port => $port

TCP port number where the remote server is listening.

=item password => $password

Password for user authentication.

=item key_path => $key_path

Path to file containing the private key to be used for
user authentication.

Some backends (i.e. Net::SSH2), require the pulic key to be
stored in a file of the same name with C<.pub> appended.

=item passphrase => $passphrase

Passphrase to be used to unlock the private key.

=item timeout => $seconds

Default timeout.

=item argument_encoding => $encoding

The encoding used for the commands and arguments sent to the remote stream.

=item stream_encoding => $encoding

On operation interchanging data between perl and the remote commands
(as oposed to operations redirecting the remote commands output to the
file system) the encoding to be used.

=item encoding => $encoding

This option is equivalent to setting C<argument_encoding> and
C<stream_encoding>.

=item known_hosts_path => $path

Location of the C<known_hosts> file where host keys are saved.

On Unix/Linux systems defaults to C<~/.ssh/known_hosts>, on Windows to
C<%APPDATA%/libnet-ssh-any-perl/known_hosts>.

=item strict_host_key_checking => $bool

When this flag is set, the connection to the remote host will be
aborted unless the host key is already stored in the C<known_hosts>
file.

Setting this flag to zero, relaxes that condition so that remote keys
are accepted unless a different key exists on the C<known_hosts> file.

=item remote_*_cmd => $remote_cmd_path

Some operations (i.e. SCP operations) execute a remote
command implicitly. By default the corresponding standard command
without any path is invoked (i.e C<scp>).

If any other command is preferred, it can be requested through these
set of options. For instance:

   $ssh = Net::SSH::Any->new($target,
                             remote_scp_cmd => '/usr/local/bin/scp',
                             remote_tar_cmd => '/usr/local/bin/gtar');

=item local_*_cmd => $local_cmd_path

Similar to C<remote_*_cmd> parameters but for local commands.

For instance:

   $ssh = Net::SSH::Any->new($target,
                             remote_ssh_cmd => '/usr/local/bin/ssh');

=item backends => \@preferred_backends

List of preferred backends to be tried.

=item backend_opts => \%backend_opts

Options specific for the backends.

=back

=item $ssh->error

This method returns the error, if any, from the last method.

=item $ssh->system(\%opts, @cmd)

Runs a command on the remote machine redirecting the stdout and stderr
streams to STDOUT and STDERR respectively.

Note than STDIN is not forwarded to the remote command.

The set of options accepted by this method is as follows:

=over 4

=item timeout => $seconds

If there is not any network traffic over the given number of seconds,
the command is aborted. See L</Timeouts>.

=item stdin_data => $data

=item stdin_data => \@data

The given data is sent as the remote command stdin stream.

=item stdout_fh => $fh

The remote stdout stream is redirected to the given file handle.

=item stdout_file => $filename

The remote stdout stream is saved to the given file.

=item stdout_discard => $bool

The remote stdout stream is discarded.

=item stderr_to_stdout => $bool

The remote stderr stream is mixed into the stdout stream.

=item stderr_fh => $fh

The remote stderr stream is redirected to the given file handle.

=item stderr_file => $filename

The remote stderr stream is saved on the given file.

=item stderr_discard => $bool

The remote stderr stream is discarded.

=back

=item $output = $ssh->capture(\%opts, @cmd)

=item @output = $ssh->capture(\%opts, @cmd)

The given command is executed on the remote machine and the output
captured and returned.

When called in list context this method returns the output split in
lines.

In case of error the partial output is returned. The C<error> method
should be used to check that no error hapenned even when output has
been returned.

The set of options accepted by this method is as follows:

=over 4

=item timeout => $seconds

Remote command timeout.

=item stdin_data => $data

=item stdin_data => \@data

Data to be sent through the remote command stdin stream.

=item stderr_to_stdout => $bool

The remote stderr stream is redirected to the stdout stream (and then
captured).

=item stderr_discard => $bool

Remote stderr is discarded.

=item stderr_fh => $fh

Redirect remote stderr stream to the given file handle.

=item stderr_file => $filename

Save the remote stderr stream to the given file.

=back

=item ($stdout, $stderr) = $ssh->capture2(\%opts, @cmd)

Captures both the stdout and stderr streams from the remote command
and returns them.

=over 4

=item timeout => $seconds

Command is aborted after the given numbers of seconds with no activity
elapse.

=item stdin_data => $data

=item stdin_data => \@data

Sends the given data through the stdin stream of the remote process.

Example:

    $ssh->system({stdin_data => \@data}, "cat >/tmp/foo")
        or die "unable to write file: " . $ssh->error;

=back

=item $pipe = $ssh->pipe(\%opts, @cmd)

Returns a bidirectional file handle object (that may be a real
operating system file handle or an emulated tied file handle,
depending on the used backend), connected to the remote command stdin
and stdout streams.

The returned pipe objects provide most of the API of L<IO::Handle>.

=over 4

=item stderr_to_stdout => $bool

Redirects the stderr stream of the remote process into its stdout
stream.

=item stderr_discard => $bool

Discards the stderr stream of the remote process.

=back

=item $ssh->scp_get(\%opts, @srcs, $target)

Copies the given files from the remote host using scp.

The accepted set of options are as follow:

=over

=item glob => $bool

Allows to expand wildcards on the remote machine when selecting the
files to download.

=item recursive => $bool

When this flag is set, the module will descend into directories and
retrieve them recursively.

=item copy_attr => $bool

When this flag is set the attributes of the local files (permissions
and timestamps) are copied from the remote ones.

=item copy_perm => $bool

=item copy_time => $bool

Selectively copy the permissions or the timestamps.

=item update => $bool

If the target file already exists locally, it is only copied when the
timestamp of the remote version is newier. If the file doesn't exist
locally, it is unconditionally copied.

=item numbered => $bool

When for some remote file a local file of the same name already exists
at its destination, a increasing suffix is added just before any
extension.

For instance, C<foo> may become C<foo(1)>, C<foo(2)>, etc.; C<foo.txt>
may become C<foo(1).txt>, C<foo(2).txt>, etc.

=item overwrite => $bool

When a local file of the same name already exist, overwrite it. Set by
default.

=back

=item $ssh->scp_put(\%opts, @srcs, $target)

Copies the set of given files to the remote host.

The accepted options are as follows:

=over 4

=item glob => $bool

Allows willcard expansion when selecting the files to copy.

=item recursive => $bool

Recursively descend into directories.

=item copy_attr => $bool

Copy permission and time attributes from the local files.

=item follow_links => 0

Symbolic links are not supported by SCP. By default, when a symbolic
link is found, the method just copies the file pointed by the link.

If this flag is unset symbolic links are skipped.

=back

=item $data = $ssh->scp_get_content(\%opts, @srcs)

Retrieves the contents of some file or files via SCP.

=over 4

=item glob => $bool

Allows willcard expansion on the remote host when selecting the files
to transfer.

=item recursive => $bool

Recursively descends into directories

=back

=item $ssh->scp_mkdir(\%opts, $dir)

Creates a directory using SCP.

=item $sftp = $ssh->sftp(%opts);

Returns a new L<Net::SFTP::Foreign> object connected to the remote
system.

=over

=item fs_encoding => $encoding

=item timeout => $seconds

=back

=back

=head2 Backends

Currently the available backends are as follows:

=over 4

=item Net_OpenSSH

Uses the perl module Net::OpenSSH which relies on OpenSSH C<ssh>
binary to connect to the remote hosts. As it uses the multiplexing
feature of OpenSSH, it can run several commands (or other operations)
over one single connection, so it is quite fast.

Using OpenSSH client ensures maximum interoperability and a mature an
secure protocol implementation.

The downside is that Net::OpenSSH doesn't work on Windows because OpenSSH
multiplexing feature has not been ported there.

=item Net_SSH2

Uses the perl module Net::SSH2 which is a wrapper for the libssh2 C
library which is a fast and portable implementation of the client side
of the SSH version 2 protocol.

L<Net::SSH2> is an actively maintaned module that works on both
Unix/Linux an Windows systems (don't known about VMS). Compiling it
may be a hard task, specially on Windows, but prepackaged versions are
available from the Internet.

=item SSH_Cmd

Uses the system C<ssh> binary to connect to the remote host.

=back

=head1 FAQ

Frequent questions about this module:

over 4

=item Disabling host key checking

B<Query>: How can host key checking be completely disabled?

B<Answer>: You don't want to do that, disabling host key checking
breaks SSH security model. You will be exposed to man-in-the-middle
attacks, and anything transferred over the SSH connection may be
captured by a third party, including passwords if you are also using
password authentication.

B<Q>: I don't mind about security, can I disable host key checking?

B<A>: You have been warned...

The way to disable host key checking is to unset the
C<strict_host_key_checking> flag and point C<known_hosts> to
C</dev/null> or your preferred OS equivalent.

In example:

  my $ssh = Net::SSH::Any->new($host,
                               strict_host_key_checking => 0,
                               known_hosts_path => ($^O =~ /^Win/
                                                    ? 'NUL:'
                                                    : '/dev/null'));

I have not made that easier on purpose!

=item known_hosts file

B<Q>: How can I manipulate the C<known_hosts> file. I.e, adding and
removing entries?

B<A>: If you have a recent version of OpenSSH installed on your
machine, the companion utility C<ssh-keygen(1)> provides a relatively
easy to use command line interface to such file.

Otherwise, you can just add or remove the entries manually using a
text editor.

If you are on Linux/Unix and using the default C<known_hosts> file, an
easy way to add some host key to it is to just log once manually from
the command line using your system C<ssh> command. It will get the key
from the remote host and ask you if you want to add the key to the
store.

Later versions of L<Net::SSH2> provide basic support for
C<known_hosts> file manipulation in L<Net::SSH2::KnownHosts>.

=item More questions

See also the FAQ from the L<Net::OpenSSH/FAQ> module as most of the
entries there are generic.

=back

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

Copyright (C) 2011-2013 by Salvador Fandiño, E<lt>sfandino@yahoo.comE<gt>

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.12.4 or,
at your option, any later version of Perl 5 you may have available.

=cut
