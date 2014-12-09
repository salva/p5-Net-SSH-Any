package Net::SSH::Any::SCP::Putter::Content;

use strict;
use warnings;
use Carp;

use Net::SSH::Any::Util qw($debug _debug _debug_dump _first_defined _croak_bad_options);

require Net::SSH::Any::SCP::Putter;
our @ISA = qw(Net::SSH::Any::SCP::Putter);

sub _new {
    @_ == 5 or croak 'Usage: $ssh->scp_put_content(\%opts, $target, $content)';
    my ($class, $any, $opts, $target, $content) = @_;
    my $perm = _first_defined delete $opts->{perm}, 0666;
    _croak_bad_options %$opts;

    my $p = $class->SUPER::_new($any, $opts, $target);
    $p->{perm} = $perm;
    $p->{content} = $content;
    $p;
}

sub read_dir {
    my ($p, $action) = @_;
    if (defined (my $content = delete $p->{content})) {
        my $file_part = (File::Spec->splitpath($p->{target}))[2];
        return { type => 'file',
                 local_path => $file_part,
                 name => $file_part,
                 perm => $p->{perm},
                 size => length($content),
                 content => $content
               };
    }
    ()
}

sub open_file { 1 }

sub read_file {
    my ($p, $action, $fh, $len) = @_;
    if ($len and not length($action->{content})) {
        $p->set_local_error($action, "premature EOF reached");
        return;
    }
    substr($action->{content}, 0, $len, '');
}

sub close_file {
    my ($action, $handle) = @_;
    return $handle
}

1;
