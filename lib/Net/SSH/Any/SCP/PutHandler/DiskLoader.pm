package Net::SSH::Any::SCP::PutHandler::DiskLoader;

use strict;
use warnings;

use File::Spec;

require Net::SSH::Any::SCP::PutHandler;
our @ISA = qw(Net::SSH::Any::SCP::PutHandler);

sub new {
    my ($class, $any, $opts, $files) = @_;
    my $h = $class->SUPER::_new($any, $opts, $files);
    my @srcs = @$files;
    @$files = (@srcs > 1 ? pop @srcs : '.');

    $h->{$_} = delete $opts->{$_} for qw(recursive glob);

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

sub on_next {
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
                return { type => 'E' };
            }
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
            $h->push_local_error($lfn, "Unable to stat object");
            next;
        }
        if ($h->{recursive} and -d _) {
            $type = 'D';
            my $dh;
            unless (opendir($dh, $lfn)) {
                $h->push_local_error($lfn, "Unable to open directory");
                next;
            }
            push @$dhs, $dh;
            push @$dns, $lfn;
        }
        else {
            $type = 'C';
            my $fh;
            unless (open $fh, '<', $lfn) {
                $h->push_local_error($lfn, "Unable to open file");
                next;
            }
            binmode $fh;
            $h->{current_fh} = $fh;
        }
        return { type => $type,
                 name => $rfn,
                 perm => $perm,
                 atime => $atime,
                 mtime => $mtime };
    }
}

sub on_send_data {
    my ($h, $size) = @_;
    my $fh = $h->{current_fh} or return;
    $size = 64 * 1024 if $size > 64 * 1024;
    my $buf = '';
    my $bytes = sysread $fh, $buf, $size;
    unless ($bytes) {
        $h->set_local_error(defined $bytes
                            ? 'Unexpected end of file reached'
                            : 'Unable to read from file');
    }
    $buf;
}

sub on_end_of_file {
    my $h = shift;
    delete $h->{current_fh};
    1;
}

1;
