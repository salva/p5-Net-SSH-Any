package Net::SSH::Any::Test;

use strict;
use warnings;

use Carp;
use Time::HiRes ();
use Net::SSH::Any::Util qw(_array_or_scalar_to_list);
use Net::SSH::Any::URI;
use Net::SSH::Any::_Base;
use Net::SSH::Any::Constants qw(SSHA_NO_BACKEND_ERROR);
our @ISA = qw(Net::SSH::Any::_Base);

my @default_backends = qw(Remote OpenSSH);

sub new {
    my ($class, %opts) = @_;
    return $class->_new(\%opts);
}

sub _log_at_level {
    local ($@, $!, $?, $^E);
    my $tssh = shift;
    my $level = shift;
    my ($pkg, undef, $line) = caller $level;
    my $time = sprintf "%.2f", Time::HiRes::time - $^T;
    my $text = join(': ', @_);
    my $prefix = "$time $pkg $line|";
    $text =~ s/\n$//;
    my $n;
    $text =~ s/^/$prefix.($n++?'\\':'-')/emg;
    $text .= "\n";
    eval { $tssh->{logger}->($tssh->{logger_fh}, $text) }
}

sub _log { shift->_log_at_level(1, @_) }

sub _log_dump {
    my $tssh = shift;
    my $head = shift;
    require Data::Dumper;
    local $Data::Dumper::Terse = 1;
    local $Data::Dumper::Indent = 0;
    $tssh->_log_at_level(1, $head, Data::Dumper::Dumper(@_));
}

sub _log_error_and_reset_backend {
    my $tssh = shift;
    $tssh->_log_at_level(1, "saving error", $tssh->{error});
    $tssh->SUPER::_log_error_and_reset_backend(@_);
}

sub _default_logger {
    my ($fh, $text) = @_;
    print {$fh} $text;
}

my @uri_keys = qw(host user port password key_path passphrase);

sub _new {
    my ($class, $opts) = @_;
    my $tssh = $class->SUPER::_new($opts);

    my $logger_fh = delete $opts->{logger_fh} // \*STDERR;
    open my $logger_fh_dup, '>>&', $logger_fh;
    $tssh->{logger_fh} = $logger_fh_dup;
    $tssh->{logger} = delete $opts->{logger} // \&_default_logger;

    # This is a bit thorny, but we are trying to support receiving
    # just one uri or an array of them and also uris represented as
    # strings or as hashes. For instance:
    #   uri => 'ssh://localhost:1022'
    #   uri => { host => localhost, port => 1022 }
    #   uri => [ 'ssh://localhost:1022',
    #            { host => localhost, port => 2022} ]
    my @targets = _array_or_scalar_to_list(delete $opts->{targets} //
                                           delete $opts->{target}  //
                                           delete $opts->{uris}    //
                                           delete $opts->{uri});
    # And we also want to support passing the target details as direct
    # arguments to the constructor.
    push @targets, {} unless @targets;
    my @uri_defaults = (port => 22, host => 'localhost');
    for (@uri_keys) {
        if (defined (my $v = delete $opts->{$_})) {
            push @uri_defaults, $_, $v;
        }
    }

    for (@targets) {
        my @args = (@uri_defaults, (ref $_ ? %$_ : (uri => $_)));
        my $uri = Net::SSH::Any::URI->new(@args);
        if ($uri) {
            $tssh->_log("Potential target", $uri->uri(1));
            push @{$tssh->{uris}}, $uri;
        }
        else {
            require Data::Dumper;
            $tssh->_log_dump("Bad target found", {@args});
        }
    }

    use Data::Dumper;
    print Dumper($tssh);

    $tssh->{timeout} = delete $opts->{timeout} // 10;
    $tssh->{run_server} = delete $opts->{run_server} // 1;

    my @backends = _array_or_scalar_to_list(delete $opts->{backend} //
                                            delete $opts->{backends} //
                                            \@default_backends);
    $tssh->{backends} = \@backends;

    for my $backend (@backends) {
        if ($tssh->_load_backend_module(__PACKAGE__, $backend)) {
            if ($tssh->start_and_check) {
                $tssh->_log("Ok, backend $backend can do it!");
                return $tssh;
            }
            else {
                $tssh->_log_error_and_reset_backend
            }
        }
    }
    $tssh->_set_error(SSHA_NO_BACKEND_ERROR, "no backend available");
    $tssh;
}


1;
