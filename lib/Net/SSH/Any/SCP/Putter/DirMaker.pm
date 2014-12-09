package Net::SSH::Any::SCP::Putter::DirMaker;

use strict;
use warnings;
use Carp;

use Net::SSH::Any::Util qw($debug _debug _debug_dump _first_defined);

require Net::SSH::Any::SCP::Putter;
our @ISA = qw(Net::SSH::Any::SCP::Putter);

sub _new {
    @_ == 4 or croak 'Usage: $ssh->scp_mkdir(\%opts, $dir)';
    my ($class, $any, $opts, $target) = @_;
    my @parts = grep $_ ne '.', ($target =~ m|[^/]+|g);
    my $absolute = $target =~ m|^/|;

    $opts->{recursive} = 1;
    my $p = $class->SUPER::_new($any, $opts, ($absolute ? '/' : '.'));
    $p->{parts} = \@parts;
    $p->{perm} = _first_defined delete $opts->{perm}, 0777;
    $p;
}

sub read_dir {
    my ($p, $action, $fh) = @_;
    unless ($p->{entry_ix}++) {
        if (defined (my $name = shift @{$p->{parts}})) {
            return { type => 'dir', name => $name };
        }
    }
    return
}

sub do_stat {
    my ($p, $action) = @_;
    $action->{perm} = 0777;
    $action->{size} = 0;
    1;
}

sub open_dir  {
    my ($p, $action) = shift;
    $p->{entry_ix} = 0;
}

sub close_dir { 1 }

1;
