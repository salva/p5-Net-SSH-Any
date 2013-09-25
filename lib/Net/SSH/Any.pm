package Net::SSH::Any;

our $VERSION = '0.04';

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

    my %remote_cmd;
    for (keys %opts) {
        /^remote_(.*)_cmd$/ and $remote_cmd{$1} = $opts{$_};
    }

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
                remote_cmd => \%remote_cmd,
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
    my ($out) = $any->_capture(\%opts, $cmd) or return;
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

=item remote_*_cmd => $remote_cmd_path

Some operations (i.e. SCP operations) execute a remote
command implicitly. By default the corresponding standard command
without any path is invoked (i.e C<scp>).

If any other command is preferred, it can be requested through these
set of options. For instance:

   $ssh = Net::SSH::Any->new($target,
                             remote_scp_cmd => '/usr/local/bin/scp',
                             remote_tar_cmd => '/usr/local/bin/gtar');

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
the command is aborted.

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

=item stdin_data => $data

=item stdin_data => \@data

=back

=item $pipe = $ssh->pipe(\%opts, @cmd)

=over 4

=item stderr_to_stdout => $bool

=item stderr_discard => $bool

=back

=item $ssh->scp_get(\%opts, @srcs, $target)

=over

=item glob => $bool

=item recursive => $bool

=item copy_attr => $bool

=item copy_perm => $bool

=item copy_time => $bool

=item update => $bool

=item numbered => $bool

=item overwrite => $bool

=back

=item $ssh->scp_put(\%opts, @srcs, $target)

=over 4

=item glob => $bool

=item recursive => $bool

=item copy_attr => $bool

=item follow_links => 0

=back

=item $data = $ssh->scp_get_content(\%opts, @srcs)

=over 4

=item glob => $bool

=item recursive => $bool

=back

=item $ssh->scp_mkdir(\%opts, $dir)

=item $sftp = $ssh->sftp(%opts);

=over

=item fs_encoding => $encoding

=item timeout => $seconds

=back

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
