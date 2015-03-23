package Net::SSH::Any::_Base;

use strict;
use warnings;
use Carp;

use Scalar::Util ();
use Net::SSH::Any::Constants qw(SSHA_BACKEND_ERROR SSHA_LOCAL_IO_ERROR SSHA_UNIMPLEMENTED_ERROR);
use Net::SSH::Any::Util;
our @CARP_NOT = qw(Net::SSH::Any::Util);

sub _new {
    my ($class, $opts) = @_;
    my $os = delete $opts->{os};

    my (%remote_cmd, %local_cmd, %remote_extra_args, %local_extra_args);
    for (keys %$opts) {
        /^remote_(.*)_cmd$/ and $remote_cmd{$1} = $opts->{$_};
        /^local_(.*)_cmd$/ and $local_cmd{$1} = $opts->{$_};
        /^remote_(.*)_extra_args$/ and $remote_extra_args{$1} = $opts->{$_};
        /^local_(.*)_extra_args$/ and $local_extra_args{$1} = $opts->{$_};
    }

    my $self = { os => $os,
                 error => 0,
                 error_prefix => [],
                 backend_log => [],
                 remote_cmd => \%remote_cmd,
                 local_cmd => \%local_cmd,
                 remote_extra_args => \%remote_extra_args,
                 local_extra_args => \%local_extra_args,
               };

    bless $self, $class;
    $self;
}

sub _log_error_and_reset_backend {
    my $self = shift;
    push @{$self->{backend_log}}, "$self->{backend}: [".($self->{error}+0)."] $self->{error}";
    $self->{error} = 0;
    delete $self->{backend};
    delete $self->{backend_module};
    ()
}

sub _load_backend_module {
    my ($self, $class, $backend, $required_version) = @_;
    $backend =~ /^\w+$/ or croak "Bad backend name '$backend' for class '$class'";
    $self->{backend} = $backend;
    my $module = $self->{backend_module} = "${class}::Backend::${backend}";

    local ($@, $SIG{__DIE__});
    my $ok = eval <<EOE;
no strict;
no warnings;
require $module;
1;
EOE
    if ($ok) {
        if ($required_version) {
            if ($module->can('_backend_api_version')) {
                my $version = $module->_backend_api_version;
                if ($version >= $required_version) {
                    return 1;
                }
                else {
                    $self->_set_error(SSHA_BACKEND_ERROR,
                                     "backend API version $version is too old ($required_version required)");
                }
            }
            else {
                $self->_set_error(SSHA_BACKEND_ERROR, 'method _backend_api_version missing');
            }
        }
        else {
            return 1;
        }
    }
    else {
        $self->_set_error(SSHA_BACKEND_ERROR, "unable to load module '$module'", $@);
    }

    $self->_log_error_and_reset_backend;
    ()
}

sub error { shift->{error} }

sub die_on_error {
    my $self = shift;
    $self->{error} and croak(join(': ', @_, "$self->{error}"));
    1;
}

sub _set_error {
    my $self = shift;
    my $code = shift || 0;
    my @msg = grep { defined && length } @_;
    @msg = "Unknown error $code" unless @msg;
    my $error = $self->{error} = ( $code
                                  ? Scalar::Util::dualvar($code, join(': ', @{$self->{error_prefix}}, @msg))
                                  : 0 );
    $debug and $debug & 1 and _debug "set_error($code - $error)";
    return $error
}

sub _or_set_error {
    my $self = shift;
    $self->{error} or $self->_set_error(@_);
}

sub _open_file {
    my ($self, $def_mode, $name_or_args) = @_;
    my ($mode, @args) = (ref $name_or_args
			 ? @$name_or_args
			 : ($def_mode, $name_or_args));
    if (open my $fh, $mode, @args) {
        return $fh;
    }
    $self->_set_error(SSHA_LOCAL_IO_ERROR, "Unable to open file '@args': $!");
    return undef;
}

my %loaded;
sub _load_module {
    my ($self, $module) = @_;
    $loaded{$module} ||= eval "require $module; 1" and return 1;
    $self->_set_error(SSHA_UNIMPLEMENTED_ERROR, "Unable to load perl module $module");
    return;
}

sub _load_os {
    my $self = shift;
    my $os = $self->{os} //= ($^O =~ /^mswin/i ? 'MSWin' : 'POSIX');
    my $os_module = "Net::SSH::Any::OS::$os";
    $self->_load_module($os_module) or return;
    $self->{os_module} = $os_module;
}

# transparently delegate method calls to backend and os packages:
sub AUTOLOAD {
    our $AUTOLOAD;
    my ($name) = $AUTOLOAD =~ /([^:]*)$/;
    my $sub;
    no strict 'refs';
    if (my ($os_name) = $name =~ /^_os_(.*)/) {
        $sub = sub {
            my $os = $_[0]->{os_module} //= $_[0]->_load_os or return;
            my $method = $os->can($os_name)
                or croak "method '$os_name' not defined in OS '$os'";
            goto &$method;
        };
    }
    else {
        $sub = sub {
            my $module = $_[0]->{backend_module} or return;
            my $method = $module->can($name)
                or croak "method '$name' not defined in backend '$module'";
            goto &$method;
        };
    }
    *{$AUTOLOAD} = $sub;
    goto &$sub;
}

sub DESTROY {
    my $self = shift;
    my $module = $self->{backend_module};
    if (defined $module) {
        my $sub = $module->can('DESTROY');
        $sub->($self) if $sub;
    }
}

1;
