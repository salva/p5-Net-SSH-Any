package Net::SSH::Any::SCP::GetHandler::DiskSaver;

use strict;
use warnings;

use Net::SSH::Any::Util qw($debug _debug _first_defined _inc_numbered);

require Net::SSH::Any::SCP::GetHandler;
our @ISA = qw(Net::SSH::Any::SCP::GetHandler);

sub new {
    my ($class, $any, $opts, $files) = @_;
    my $h = $class->SUPER::_new($any, $opts, $files);
    my $target = (@$files > 1 ? pop @$files : '.');
    if (-d $target) {
        $h->{target_dir} = $target;
    }
    else {
        $h->{target} = $target;
    }
    $h->{$_} = $opts->{$_} for qw(recursive glob);

    $h->{numbered} = delete $opts->{numbered};
    unless ($h->{numbered}) {
        $h->{overwrite} = _first_defined delete($opts->{overwrite}), 1;
    }
    $h->{copy_perm} = _first_defined delete($opts->{copy_perm}), 1;

    $h->{parent_dir} = [];
    $h->{dir_perms} = [];
    $h->{dir_parts} = [];

    $h;
}

sub on_file {
    my ($h, $perm, $size, $name) = @_;
    $debug and $debug and 4096 and Net::SSH::Any::_debug "on_file(perm: $perm, size: $size, name: $name)";

    my $fn = (defined $h->{target_dir}
              ? File::Spec->join($h->{target_dir}, $name)
              : $h->{target});
    $debug and $debug & 4096 and Net::SSH::Any::_debug "opening file $fn";

    my $action = $h->push_action(type   => 'file',
                                 remote => join('/', @{$h->{dir_parts}}, $name),
                                 local  => $fn,
                                 perm   => $perm,
                                 size   => $size );

    unlink $fn if $h->{overwrite};

    my $flags = Fcntl::O_CREAT|Fcntl::O_WRONLY;
    $flags |= Fcntl::O_EXCL if $h->{numbered} or not $h->{overwrite};
    $perm = 0777 unless $h->{copy_perm};

    my $fh;
    while (1) {
        sysopen $fh, $fn, $flags, $perm and last;
        unless ($h->{numbered} and -e $fn) {
            $h->set_local_error("Unable to create file '$fn'");
            return;
        }
        _inc_numbered($fn);
        $action->{local} = $fn;
    }

    binmode $fh;

    $h->{current_fh} = $fh;
    $h->{current_fn} = $fn;

    1;
}

sub on_data {
    my $h = shift;
    $debug and $debug and 4096 and Net::SSH::Any::_debug length($_[0]) . " bytes received:\n>>>$_[0]<<<\n\n";
    print {$h->{current_fh}} $_[0];
    1;
}

sub on_end_of_file {
    my $h = shift;
    $debug and $debug and 4096 and Net::SSH::Any::_debug "on_end_of_file";
    unless (close $h->{current_fh}) {
        $h->set_local_error("Unable to write to file '$h->{current_fn}'");
        return;
    }
    delete @{$h}{qw(current_fh current_fn)};
    1;
}

sub on_dir {
    my ($h, $perm, $size, $name) = @_;
    $debug and $debug and 4096 and Net::SSH::Any::_debug "on_dir(perm: $perm, size: $size, name: $name)";
    my $dn = (defined $h->{target_dir}
              ? File::Spec->join($h->{target_dir}, $name)
              : $h->{target});
    push @{$h->{parent_dir}}, $h->{target_dir};
    push @{$h->{dir_parts}}, $name;
    push @{$h->{dir_perm}}, $perm;
    $h->{target_dir} = $dn;

    $h->push_action(type   => 'dir',
                    remote => join('/', @{$h->{dir_parts}}),
                    local  => $dn,
                    perm   => $perm);

    $perm = 0777 unless $h->{copy_perm};

    unless (-d $dn or mkdir $dn, 0700 | ($perm & 0777)) {
        $h->set_local_error("Unable to create directory '$dn'");
        return;
    }
    unless (-x $dn) {
        $h->set_local_error("Access forbidden to directory '$dn'");
        return;
    }
    1;
}

sub on_end_of_dir {
    my $h = shift;
    $debug and $debug and 4096 and Net::SSH::Any::_debug "on_end_of_dir";
    pop @{$h->{dir_parts}};
    my $perm = pop @{$h->{dir_perm}};
    $perm = 0777 unless $h->{copy_perm};
    chmod $perm, $h->{target_dir} if defined $perm;
    $h->{target_dir} = pop @{$h->{parent_dir}};
    1;
}

1;
