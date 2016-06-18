package Net::SSH::Any::SCP::Putter::Untar;

use strict;
use warnings;

use Net::SSH::Any::Util qw($debug _debug _debug_dump _debug_hexdump _first_defined);

require Net::SSH::Any::SCP::Putter;
our @ISA = qw(Net::SSH::Any::SCP::Putter);

use Carp;

sub _new {
    my ($class, $any, $opts, @srcs) = @_;
    my $target = (@srcs > 1 ? pop @srcs : '.');
    $opts->{recursive} = 1;
    my $p = $class->SUPER::_new($any, $opts, $target);
    $p->{srcs} = \@srcs;
    $p->{queue} = [];
    $p;
}

sub _read_tar_header {
    my ($p, $action, $fh) = @_;
    $p->_read_chunk($action, $fh, 512, 1);
}

sub _read_chunk {
    my ($p, $action, $fh, $size, $zero_ok) = @_;

    # $debug and $debug & 4096 and _debug "_read_chunk size: $size, zero_ok: " . ($zero_ok // 0);

    my $buf = '';
    my $offset = 0;

    unless (defined $fh) {
        $p->set_local_error($action, "Internal error: tar file handler is undefined");
        $p->abort;
        return;
    }

    while ($offset < $size) {
        my $bytes = sysread $fh, $buf, $size - $offset, $offset;
        if (defined $bytes) {
            if ($bytes) {
                $offset = length $buf;
            }
            else {
                if ($offset or !$zero_ok) {
                    $p->set_local_error($action, "Unable to read from tar file: premature EOF");
                    $p->abort;
                }
                return
            }
        }
        else {
            if ($! != Errno::EINTR() and $! != Errno::EAGAIN()) {
                $p->set_local_error($action, "Unable to read from tar file: $!");
                $p->abort;
                return;
            }
        }
    }
    # $debug and $debug & 4096 and _debug_hexdump '_read_chunk' => $buf;
    return $buf;
}

my %typeflag2type = ( "\x00" => 'file',
                      ""     => 'file',
                      0      => 'file',
                      1      => 'hardlink',
                      2      => 'link',
                      3      => 'character-special',
                      4      => 'block-special',
                      5      => 'dir',
                      6      => 'fifo',
                      7      => 'file', # contiguous file
                      g      => 'global-extended-header',
                      x      => 'extended-header',
                    );

sub close_tar { 1 }

sub close_dir { 1 }

sub _compare_dirs {
    my ($a, $b) = @_;
    return 1 if @$a > @$b;
    for my $ix (0..$#$a) {
        return 1 if $a->[$ix] ne $b->[$ix];
    }
    return (@$a < @$b ? -1 : 0);
}

sub read_dir {
    my ($p, $parent_action, $fh) = @_;

    unless ($parent_action) {
        if (defined (my $tar = shift @{$p->{srcs}})) {
            return { type => 'dir',
                     synthetic => 1,
                     name => '',
                     path => '.',
                     perm => 0755,
                     size => 0,
                     only_local => 1,
                     local_path => $tar,
                     eot => 0 };
        }
        return
    }

    while (!$p->{abort}) {

        my $action = pop @{$p->{queue}};
        my $tar_action = $p->tar_action;

        unless ($action) {
            return if $tar_action->{eot} > 1;

            my $header = $p->_read_tar_header($tar_action, $fh) // return;

            my ($path, $mode, $uid, $gid, $size, $mtime,
                $chksum, $typeflag, $linkname, $magic_and_version,
                $uname, $gname, $devmayor, $devminor, $prefix) =
                    unpack 'Z100Z8Z8Z8Z12Z12Z8a1Z100a8Z32Z32Z8Z8Z155' => $header;

            if ($typeflag eq "\x00" and $header =~ /^\x00{512}\z/) {
                $tar_action->{eot}++;
                $debug and $debug & 4096 and _debug "all zeros block found, eot: $tar_action->{eot}";
                next;
            }
            else {
                $tar_action->{eot} = 0
            }

            my ($magic, $version) = unpack 'Z*Z*' => $magic_and_version;

            if ($magic eq 'ustar  ') {
                $magic = 'gnu';
                # FIXME!!!
                $p->set_local_error($tar_action, "Unsupported gnu tar archive");
                return;
            }
            elsif ($magic ne 'ustar' or $version ne '00') {
                $p->set_local_error($tar_action, "Unknown tar format ('$magic' '$version')");
                return;
            }

            $_ = oct $_ for ($mode, $uid, $gid, $size, $mtime, $chksum, $devmayor, $devminor);

            $debug and $debug & 4096 and _debug_dump "tar header" => [ $path, $mode, $uid, $gid, $size,
                                                                       $mtime, $chksum, $typeflag, $linkname,
                                                                       $magic, $version, $uname, $gname,
                                                                       $devmayor, $devminor, $prefix ];

            my $type = $typeflag2type{$typeflag} // "unknown-type-$typeflag";

            if ($type eq 'dir' and $path eq './' and $prefix = '') {
                # SCP doesn't allow us to recreate the root directory,
                # but we can copy its attributes for usage on
                # synthetic subdirs.
                my $tar_action = $p->{tar_action};
                $tar_action->{perm}  = $mode;
                $tar_action->{atime} = $mtime;
                $tar_action->{mtime} = $mtime;
                next;
            }

            $path = "/$prefix/$path";
            $path =~ s|//+|/|g;  # remove repeated slashes
            $path =~ s|/$||;     # no slash at the end
            $path =~ s|^/?|./|;   # force slash at the beginning

            $action =  { path => $path,
                         perm => $mode,
                         size => $size,
                         atime => $mtime,
                         mtime => $mtime,
                         type => $type,
                         typeflag => $typeflag };
        }

        my @parts = split /\/+/, $action->{path};
        my $name = pop @parts;
        my $parent_action = $p->{actions}[-1];
        my @parent_parts = split /\/+/, $parent_action->{path};

        $debug and $debug & 4096 and _debug_dump parts => \@parts;
        $debug and $debug & 4096 and _debug_dump parent_parts => \@parent_parts;
        my $cmp = _compare_dirs(\@parent_parts, \@parts);

        $debug and $debug & 4096 and _debug "$parent_action->{path} <=> $action->{path} => $cmp";

        if ($cmp < 0) { # parent path is an ancestor of my path
            push @{$p->{queue}}, $action;
            my $name = $parts[scalar @parent_parts];
            my $path = "$parent_action->{path}/$name";
            return { synthetic => 1,
                     name => $name,
                     path => $path,
                     perm => $parent_action->{perm},
                     size => 0,
                     atime => $parent_action->{atime},
                     mtime => $parent_action->{mtime},
                     type => 'dir' };
        }

        if ($cmp > 0) { # parent path is not an ancestor of my path
            push @{$p->{queue}}, $action;
            return
        }

        # parent path is actually my parent!
        $action->{name} = $name;

        my $type = $action->{type};
        unless ($type eq 'file' or $type eq 'dir') {
            $action->{skip} = 1;
            $p->set_local_error($action, "unsupported object type '$type'");

            # skip unhandled data
            my $remaining = $action->{size};
            if (my $round = $remaining % 512) {
                $remaining += 512 - $round;
            }
            while ($remaining) {
                my $chunk = ($remaining > 16 * 1024 ? 16 * 1024 : $remaining);
                $p->_read_chunk($tar_action, $fh, $chunk) // return;
                $remaining -= $chunk;
            }
        }
        return $action
    }
    ()
}

sub tar_action { shift->{actions}[0] }

sub open_file {
    my ($p, $action) = @_;
    $action->{remaining} = $action->{size};
    $debug and $debug & 4096 and _debug_dump 'open_file action' => $action;
    $p->tar_action->{_handle};
}

sub open_dir {
    my ($p, $action) = @_;
    $debug and $debug & 4096 and _debug_dump 'open_dir action' => $action;
    my $tar = $action->{local_path};
    if (defined $tar) {
        open my $fh, '<', $tar; # _open_dir will check it later!
        return $fh;
    }

    $p->tar_action->{_handle};
}

sub read_file {
    my ($p, $action, $fh, $len) = @_;
    $action->{remaining} -= $len;
    if ($action->{remaining} < 0) {
        $p->set_local_error($action, "Internal error: trying to read pass file limits");
        $p->abort;
        return;
    }
    $p->_read_chunk($action, $fh, $len)
}

sub close_file {
    my ($p, $action, $fh, $len) = @_;
    if ($action->{remaining}) {
        $p->set_local_error($action, "Internal error: there is remaining data");
        $p->abort;
        return;
    }
    if (my $round = $action->{size} % 512) {
        $p->_read_chunk($action, $fh, 512 - $round) // return;
    }
    1;
}

1;
