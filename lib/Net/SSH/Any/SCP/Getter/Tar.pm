package Net::SSH::Any::SCP::Getter::Tar;

use strict;
use warnings;
use Carp;
use List::Util qw(sum);

use Net::SSH::Any::Util qw($debug _debug _debugf _debug_hexdump _first_defined);
use Net::SSH::Any::Constants ();

require Net::SSH::Any::SCP::Getter;
our @ISA = qw(Net::SSH::Any::SCP::Getter);

sub _new {
    my ($class, $any, $opts, @srcs) = @_;
    @srcs or croak 'scp source files missing';
    my $target;
    if (@srcs > 1) {
        $target = pop @srcs;
    }
    else {
        ($target) = $srcs[0] =~ m|^(?:.*/)?([^/]+)/*$|;
        $target //= 'scp';
        $target .= '.tar';
    }

    my $uid = delete $opts->{uid} // 0;
    my $gid = delete $opts->{gid} // 0;
    my $uname = delete $opts->{uname} // $any->{uri}->user // 'root';
    my $gname = delete $opts->{gname} // $uname;

    $opts->{request_time} = 1;
    my $g = $class->SUPER::_new($any, $opts, @srcs);
    $g->{target} = $target;
    $g->{uid} = $uid;
    $g->{gid} = $gid;
    $g->{uname} = $uname;
    $g->{gname} = $gname;

    $g
}

sub run {
    my $g = shift;
    my $target = $g->{target};
    open my $tarfh, '>', $target or do {
        $g->_os_set_error(Net::SSH::Any::Constants::SSHA_SCP_ERROR(),
                          "unable to create archive '$target'", $!);
        return;
    };
    binmode $tarfh;
    $g->{tarfh} = $tarfh;
    $g->{parents} = [];
    $g->SUPER::run(@_);
}

sub on_end_of_get {
    my $g = shift;
    unless ($g->{aborted}) {
        print {$g->{tarfh}} scalar("\x00" x 1024);
    }
    # FIXME: check close return value
    close $g->{tarfh};
    1;
}

sub _resolve_local_path {
    my ($g, $name) = @_;
    my $path = join('/', @{$g->{parents}}, $name);
    length $path ? $path : './';
}

sub on_open_before_wanted {
    my ($g, $action) = @_;
    $action->{local_path} = $g->_resolve_local_path($action->{name});
    1;
}

sub _oct_field {
    my ($g, $action, $len, $n) = @_;
    my $len1 = $len - 1;
    my $oct = sprintf("%0${len1}o", $n);
    if ((length $oct > $len) or (oct $oct != $n)) {
        $g->set_local_error($action, "unable to fit number into tar slot");
        return;
    }
    $oct;
}

sub _str_field {
    my ($g, $action, $len, $str) = @_;
    if (length $str > $len) {
        $g->set_local_error($action, "unable to fit string into tar slot");
        return;
    }
    $str;
}

my %type2typeflag = (dir  => '5',
                     file => '0');

sub _output_header {
    my ($g, $action) = @_;
    my $type = $action->{type};
    my $path = $action->{local_path};
    my $prefix = '';
    my $path_len = length $path;
    if ($path_len > 100) {
        my $min_prefix = $path_len - 100;
        ($prefix) = $path =~ s|^(.{$min_prefix}.*?/||s;
        unless (defined $prefix and length $prefix <= 100) {
            $g->set_local_error($action, "path too long");
            return;
        }
    }

    my $size = ($type eq 'file' ? $action->{size} : 0);
    my $typeflag = $type2typeflag{$type} // do {
        $g->set_local_error($action, "Internal error: unknown type $type");
        return;
    };

    my $mode_f  = $g->_oct_field($action, 8 => $action->{perm} & 0777) // return;
    my $uid_f   = $g->_oct_field($action, 8 => $g->{uid}) // return;
    my $gid_f   = $g->_oct_field($action, 8 => $g->{gid}) // return;
    my $size_f  = $g->_oct_field($action, 12 => $size) // return;
    my $mtime_f = $g->_oct_field($action, 12 => $action->{mtime}) // return;

    my $uname_f = $g->_str_field($action, 32 => $g->{uname}) // return;
    my $gname_f = $g->_str_field($action, 32 => $g->{gname}) // return;

    my $header = pack('Z100Z8Z8Z8Z12Z12Z8a1Z100a8Z32Z32Z8Z8Z155',
                      $path, $mode_f, $uid_f, $gid_f, $size_f, $mtime_f,
                      '        ', $typeflag, '', "ustar\x{00}00",
                      $uname_f, $gname_f,
                      $prefix);

    my $checksum_f = $g->_oct_field($action, 8 => sum(unpack 'C*', $header)) // return;
    substr($header, 148, 8, pack(Z8 => $checksum_f));
    my $bytes = print {$g->{tarfh}} $header;
    unless ($bytes == 512) {
        $g->set_local_error($action);
        $g->abort;
        return;
    }
    1;
}

sub on_open_dir {
    my ($g, $action) = @_;
    $g->_output_header($action) or return;
    push @{$g->{parents}}, $action->{name};
    1;
}

sub on_close_dir {
    my ($g, $action) = @_;
    pop @{$g->{parents}};
    1;
}

sub on_open_file {
    my ($g, $action) = @_;
    $g->_output_header($action) or return;
    $action->{remaining} = $action->{size};
    1;
}

sub on_write {
    my ($g, $action) = @_;
    my $len = length $_[2];
    if ($len > $action->{remaining}) {
        $g->set_local_error($action, "Internal error: on_write exceeded reserved size");
        $g->abort;
        return;
    }
    my $bytes = print {$g->{tarfh}} $_[2];
    unless (defined $bytes and $bytes == $len) {
        $g->set_local_error($action);
        $g->abort;
        return;
    }
    $g->{remaining} -= $bytes;
    1;
}

sub on_close_file {
    my ($g, $action) = @_;
    unless ($action->{remaining} == 0) {
        $g->set_local_error($action, "Internal error: premature end of remote file");
        $g->abort;
        return;
    }

    if (my $round_up = $action->{size} % 512) {
        my $len = 512 - $round_up;
        my $bytes = print {$g->{tarfh}} scalar("\x00" x (512 - $len));
        unless (defined $bytes and $bytes == $len) {
            $g->set_local_error($action);
            $g->abort;
            return;
        }
    }

    $action->{remaining} = -1;

    1;
}

1;
