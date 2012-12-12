package Net::SSH::Any::SCP::GetHandler::DiskSaver;

use strict;
use warnings;

use Net::SSH::Any::Util qw($debug _debug _debugf _debug_hexdump _first_defined _inc_numbered _gen_wanted);

require Net::SSH::Any::SCP::GetHandler;
our @ISA = qw(Net::SSH::Any::SCP::GetHandler);

sub new {
    my ($class, $any, $opts, $files) = @_;
    my $h = $class->SUPER::_new($any, $opts, $files);
    my $target = (@$files > 1 ? pop @$files : '.');

    if (delete $opts->{target_is_dir}) {
	unless (-d $target or mkdir $target) {
	    $any->set_error(Net::SSH::Any::Constants::SSHA_SCP_ERROR,
			    "unable to create directory", $!);
	    return;
	}
    }

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
	$h->{update} = _first_defined delete($opts->{update}), 1;
    }
    $h->{copy_perm} = _first_defined delete($opts->{copy_perm}), 1;

    $h->{parent_dir} = [];
    $h->{dir_perms} = [];
    $h->{dir_parts} = [];

    $h;
}

sub on_file {
    my ($h, $perm, $size, $name) = @_;
    $debug and $debug & 4096 and _debugf '%s->on_file(%s, %s, %s)', $h, $perm, $size, $name;

    my $fn = (defined $h->{target_dir}
              ? File::Spec->join($h->{target_dir}, $name)
              : $h->{target});
    $debug and $debug & 4096 and Net::SSH::Any::_debug "opening file $fn";

    my $action = $h->push_action(type   => 'file',
                                 remote => join('/', @{$h->{dir_parts}}, $name),
                                 local  => $fn,
                                 perm   => $perm,
                                 size   => $size );

    $h->check_wanted or return;
    
    if ($h->{update}) {
	if (my @s = stat $fn) {
	    if ($s[7] == $size and $s[9] == $h->{mtime}) {
		$h->set_skipped;
		return;
	    }
	}
    }

    unlink $fn if $h->{overwrite};
    
    my $flags = Fcntl::O_CREAT|Fcntl::O_WRONLY;
    $flags |= Fcntl::O_EXCL if $h->{numbered} or not $h->{overwrite};
    $perm = 0777 unless $h->{copy_perm};

    my $fh;
    while (1) {
        sysopen $fh, $fn, $flags, $perm and last;
        unless ($h->{numbered} and -e $fn) {
            $h->set_local_error;
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
    $debug and $debug & 4096 and _debug_hexdump('data received', $_[0]);
    print {$h->{current_fh}} $_[0];
    1;
}

sub on_end_of_file {
    my ($h, $failed, $error) = @_;
    $debug and $debug & 4096 and _debugf("%s->on_end_of_file(%s, %s)", $h, $failed, $error);
    $failed and $h->set_remote_error($error);

    my $fh = delete $h->{current_fh};
    my $fn = delete $h->{current_fn};
    unless (close $fh) {
        $h->set_local_error;
	$failed = 1;
    }
    if ($failed) {
	unlink $fn;
	return
    }
    1;
}

sub _pop_dir {
    my $h = shift;
    pop @{$h->{dir_parts}};
    pop @{$h->{dir_perm}};
    $h->{target_dir} = pop @{$h->{parent_dir}};
}

sub on_dir {
    my ($h, $perm, $size, $name) = @_;
    $debug and $debug & 4096 and _debugf '%s->on_dir(%s, %s, %s)', $h, $perm, $size, $name;

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

    unless ($h->check_wanted) {
	$h->_pop_dir;
	return;
    }

    $perm = 0777 unless $h->{copy_perm};

    unless (-d $dn or mkdir($dn, 0700 | $perm & 0777)) {
        $h->set_local_error;
	$h->_pop_dir;
        return;
    }
    1;
}

sub on_end_of_dir {
    my $h = shift;
    $debug and $debug and 4096 and _debug "$h->on_end_of_dir";
    my $perm = $h->{dir_perm}[-1];
    if (defined $perm and $h->{copy_perm}) {
	chmod ($perm & 0777, $h->{target_dir});
    }
    $h->_pop_dir;
    1;
}

1;
