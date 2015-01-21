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

sub _log {
    local ($@, $!, $?, $^E);
    my $tssh = shift;
    my ($pkg, undef, $line) = caller;
    my $time = sprintf "%.2f", Time::HiRes::time - $^T;
    my $text = join(': ', @_);
    my $prefix = "$time $pkg $line| ";
    $text =~ s/\n$//;
    $text =~ s/^/$prefix/g;
    $text .= "\n";
    eval { $tssh->{logger}->($tssh->{logger_fh}, $text) }
}

sub _default_logger {
    my ($tssh, $fh, $text) = @_;
    print {$fh} $text;
}

sub _new {
    my ($class, $opts) = @_;
    my $tssh = $class->SUPER::_new($opts);

    my $logger_fh = delete $opts->{logger_fh} // \*STDERR;
    open my $logger_fh_dup, '>>&', $logger_fh;
    $tssh->{logger_fh} = $logger_fh_dup;
    $tssh->{logger} = delete $opts->{logger} // \&_default_logger;

    my @uri_opts = (port => 22, host => 'localhost');
    for (qw(uri host user port password key_path passphrase)) {
        if (defined (my $v = delete $opts->{$_})) {
            push @uri_opts, $_, $v;
        }
    }

    my $uri = $tssh->{uri} = Net::SSH::Any::URI->new(@uri_opts);

    $tssh->{timeout} = delete $opts->{timeout} // 10;
    $tssh->{run_server} = delete $opts->{run_server} // 1;

    my @backends = _array_or_scalar_to_list(delete $opts->{backend} //
                                            delete $opts->{backends} //
                                            \@default_backends);
    $tssh->{backends} = \@backends;

    for my $backend (@backends) {
        if ($tssh->_load_backend_module(__PACKAGE__, $backend)) {
            if ($tssh->validate_backend_opts) {
                $tssh->start;
                if ($tssh->check) {
                    return $tssh;
                }
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
