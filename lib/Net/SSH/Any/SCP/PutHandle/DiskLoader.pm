package Net::SSH::Any::SCP::PutHandle::DiskLoader;

use strict;
use warnings;

use File::Spec;

require Net::SSH::Any::SCP::PutHandle;
our @ISA = qw(Net::SSH::Any::SCP::PutHandle);

sub new {
    my ($class, $any, $opts, $files) = @_;
    my $h = $class->SUPER::_new($any, $opts, $files);
    my @srcs = @$files;
    @$files = (@srcs > 1 ? pop @srcs : '.');

    $h->{glob} = delete $opts->{glob};
    $h->{recursive} = $opts->{recursive};

    if ($h->{glob}) {
        require File::Glob;
        @srcs = grep defined, map File::Glob::bsd_glob($_), @srcs;
    }

    $h->{srcs} = \@srcs;
    $h->{dirhandles} = [];
    $h->{dirnames} = [];
    $h->{local_errors} = 0;
    $h;
}

sub push_local_error {
    my ($h, $path, $error) = @_;
    $h->push_action(type => 'local_error',
                    local => $path,
                    error => $error,
                    errno => $!);
    $h->{local_errors}++;
}

sub _pop_dir {
    my $h = shift;
    my $dhs = $h->{dirhandles};
    my $dns = $h->{dirnames};
    if (@$dhs) {
	pop @$dhs;
	pop @$dns;
    }
}

my @ignore_dirs = grep { defined } map { File::Spec->$_ } qw(curdir updir);

sub on_next_action {
    my $h = shift;
    my $dhs = $h->{dirhandles};
    my $dns = $h->{dirnames};
    my $srcs = $h->{srcs};
    my ($rfn, $lfn); # remote and local file/dir names
    while (1) {
        if (@$dhs) {
            $rfn = readdir($dhs->[-1]);
            unless (defined $rfn) {
                pop @$dhs;
                pop @$dns;
                return { type => 'end_of_dir' };
            }
	    redo if grep { $rfn eq $_ } @ignore_dirs;
            $lfn = File::Spec->join(@$dns, $rfn);
        }
        elsif (@$srcs) {
            $lfn = shift @$srcs;
            $rfn = (File::Spec->splitpath($lfn))[2];
        }
        else {
            return
        }

        my $type;
        my ($perm, $size, $atime, $mtime) = (stat $lfn)[2, 7, 8, 9];
        unless (defined $perm) {
            $h->push_local_error($lfn, "unable to stat object");
            next;
        }
        if ($h->{recursive} and -d _) {
            $type = 'dir';
            my $dh;
            unless (opendir($dh, $lfn)) {
                $h->push_local_error($lfn, "unable to open directory");
                next;
            }
            push @$dhs, $dh;
            push @$dns, $lfn;
        }
        elsif (-f _) {
            $type = 'file';
            my $fh;
            unless (open $fh, '<', $lfn) {
                $h->push_local_error($lfn, "unable to open file");
                next;
            }
            binmode $fh;
            $h->{current_fh} = $fh;
	    $h->{current_fn} = $lfn;
        }
        else {
            $h->push_local_error($lfn, "not a regular file");
            next;
        }

        return $h->push_action( type => $type,
                                size => $size,
                                remote => $rfn,
                                local => $lfn,
                                perm => $perm,
                                atime => $atime,
                                mtime => $mtime );
    }
}

sub on_action_refused {
    my ($h, $error_level, $error_msg) = @_;
    my $action = $h->current_action;
    if ($action->{type} eq 'D') {
	$h->_pop_dir;
    }
    else {
	delete @{$h}{qw(current_fh current_fn)};
    }
    1;
}

sub on_end_of_file {
    my $h = shift;
    delete @{$h}{qw(current_fh current_fn)};
    1;
}

sub on_send_data {
    my ($h, $size) = @_;
    my $fh = $h->{current_fh} or return;
    $size = 64 * 1024 if $size > 64 * 1024;
    my $buf = '';
    my $bytes = sysread $fh, $buf, $size;
    unless ($bytes) {
        $h->set_local_error(defined $bytes
			    ? 'unexpected end of file reached'
			    : 'unable to read from file');
        return
    }
    $buf;
}

1;
