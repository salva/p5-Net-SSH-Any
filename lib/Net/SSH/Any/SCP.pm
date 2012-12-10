package Net::SSH::Any::SCP;

use Net::SSH::Any;
package Net::SSH::Any;

use strict;
use warnings;
use Fcntl ();

our $debug;

sub _scp_unescape {
    s/\\\\|\\\^([@-Z])/$1 ? chr(ord($1) - 64) : '\\'/ge for @_;
}

sub _scp_escape {
    for (@_) {
        s/\\/\\\\/;
        s/([\x00-\x1f])/'\\^' . chr(64 + ord($1))/ge;
    }
}

sub _scp_readline {
    my $any = shift;
    my $pipe = shift;
    $debug and $debug & 4096 and _debug("$any->_scp_readline($pipe)...");
    for ($_[0]) {
        $_ = '';
        $pipe->sysread($_, 1) or goto error;
        if ($_ ne "\x00") {
            while (1) {
                $pipe->sysread($_, 1, length $_) or goto error;
                last if /\x0A$/;
            }
        }
        $debug and $debug & 4096 and _debug_hexdump("line read", $_);
        return length $_;
    }
 error:
    $any->_or_set_error(SSHA_SCP_ERROR, 'broken pipe');
    return;
}

sub scp_get_with_handler {
    my $any = shift;
    my $opts = shift;
    my $h = shift;

    my $glob = delete $opts->{glob};
    my $recursive = delete $opts->{recursive};
    my $double_dash = _first_defined delete($opts->{double_dash}), 1;

    my $remote_scp_command =  _first_defined delete($opts->{remote_scp_cmd}), $any->{remote_cmd}{scp}, 'scp';

    my @cmd   = $any->_quote_args({quote_args => 1},
                                  $remote_scp_command,
                                  '-f', '-p',
                                  ($recursive ? '-r' : ()),
                                  ($double_dash ? '--' : ()));
    my @files = $any->_quote_args({quote_args => 1,
                                   glob_quoting => $glob},
                                  @_);

    my $pipe = $any->pipe({ %$opts, quote_args => 0 },
                          @cmd, @files);
    $any->error and return;

    my $buf;
    while (1) {
        $pipe->syswrite("\x00");
        $any->_scp_readline($pipe, $buf) or last;

        $debug and $debug & 4096 and _debug "cmd line: $buf";

        my ($type, $perm, $size, $name, $mtime, $atime, $error);
        # C or D:
        if (($type, $perm, $size, $name) = $buf =~ /^([CD])([0-7]+) (\d+) (.*)$/) {
            _scp_unescape($name);
            $perm = oct $perm;
            if ($type eq 'C') {
                $h->on_file($perm, $size, $name) or last;
                $debug and $debug & 4096 and _debug "transferring file of size $size";
                $pipe->syswrite("\x00");
                $buf = '';
                while ($size) {
                    my $read = $pipe->sysread($buf, ($size > 16384 ? 16384 : $size));
                    unless ($read) {
                        $any->_or_set_error(SSHA_SCP_ERROR, "broken pipe");
                        $debug and $debug & 4096 and _debug "read failed: " . $any->error;
                        last;
                    }
                    $h->on_data($buf) or last;
                    $size -= $read;
                }
                unless ($any->_scp_readline($buf) and $buf eq "\x00") {
                    chomp $buf;
                    $any->_or_set_error(SSHA_SCP_ERROR, "SCP protocol error", $buf);
                    $debug and $debug & 4096 and _debug "failed to read ok code: $buf";
                    last;
                }
                $h->on_end_of_file or last;
            }
            else { # $type eq 'D'
                $h->on_dir($perm, $size, $name) or last;
            }
        }
        elsif (($mtime, $atime) = $buf =~ /^T(\d+)\s+\d+\s+(\d+)\s+\d+\s*$/) {
            $h->on_matime($mtime, $atime) or last;
        }
        elsif ($buf =~ /^E$/) {
            $h->on_end_of_dir() or last;
        }
        elsif (($name, $error) = $buf =~ /^\x01scp:\s(.*):\s*(.*)$/) {
            _scp_unescape($name);
            $h->on_remote_error($name, $error) or last;
        }
        elsif (($error) = $buf =~ /^\x01(?:scp:\s)?(.*)$/) {
            $h->on_remote_error(undef, $error) or last;
        }
        else {
            $any->_or_set_error(SSHA_SCP_ERROR, "SCP protocol error");
            $debug and $debug & 4096 and
                _debug "unknown command received, code: " .ord($buf). " rest: >>>" .substr($buf, 1). "<<<";
            last;
        }
    }

    $pipe->close;

    $h->on_end_of_get;

    if ($any->{error}) {
        if ($any->{error} == SSHA_REMOTE_CMD_ERROR) {
            $any->_set_error(SSHA_SCP_ERROR, $any->{error});
        }
        return;
    }
    return 1;
}

sub scp_get {
    my $any = shift;
    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());
    require Net::SSH::Any::SCP::GetHandler::DiskSaver;
    my $h = Net::SSH::Any::SCP::GetHandler::DiskSaver->new($any, \%opts, \@_);
    $any->scp_get_with_handler(\%opts, $h, @_);
}

sub scp_put_with_handler {
    @_ == 4 or croak 'Usage: $ssh->scp_put_with_handler($opts, $handler, $target)';
    my ($any, $opts, $h, $target) = @_;

    my $double_dash = _first_defined delete($opts->{double_dash}), 1;
    my $remote_scp_command =  _first_defined delete($opts->{remote_scp_cmd}), $any->{remote_cmd}{scp}, 'scp';

    my $pipe = $any->pipe({ %$opts, quote_args => 1 },
                          'strace', '-fo', '/tmp/scp.strace',
                          $remote_scp_command,
                          '-t',
                          ($double_dash ? '--' : ()),
                          $target);
    $any->error and return;

 OUT: while (1) {
        my $buf;
        $any->_scp_readline($pipe, $buf) or last;
        unless ($buf eq "\x00") {
            $any->_or_set_error(SSHA_SCP_ERROR, "SCP protocol error", $buf);
            last;
        }

        my $next = $h->on_next or last;

        $debug and $debug & 4096 and _debug_dump("next file object description from handler", $next);

        my $type = _first_defined $next->{type}, 'C';
        $type =~ s/^file$/C/;
        $type =~ s/^dir(?:ectory)?$/D/;
        $type =~ s/^end_of_dir(?:ectory)?$/E/;

        my ($size, $perm, $error, $line);
        my $name = _first_defined $next->{remote}, $target;
        my $ename = $name;
        _scp_escape($ename);

        if ($type =~ /^[CD]$/) {
            $size = _first_defined $next->{size}, 0;
            $perm = (_first_defined $next->{perm}, 0777) & 0777;
            $line = sprintf("C%04o %d %s", $perm, $size, $ename);
            # print STDERR "line: >$line<";
        }
        elsif ($type eq "E") {
            $line = "E"
        }
        else {
            croak "unknown action type <$type>";
        }
        $line .= "\x0A";
        $debug and $debug & 4096 and _debug_hexdump("sending line", $line);

        unless ($pipe->print($line)) {
            $any->_or_set_error("broken pipe");
            last OUT;
        }

        if ($type eq 'C') {
            $debug and $debug & 4096 and _debug("sending file of $size bytes");
            $any->_scp_readline($pipe, $buf) or last;
            unless ($buf eq "\x00") {
                $any->_or_set_error(SSHA_SCP_ERROR, "SCP protocol error", $buf);
                last;
            }

            while ($size > 0) {
                my $data = $h->on_send_data($size);
                unless (defined $data and length $data) {
                    $debug and $debug & 4096 and _debug("no promised data from put handler");
                    last;
                }
                if (length($data) > $size) {
                    $debug and $debug & 4096 and _debug("too much data, discarding excess");
                    substr($data, $size) = ''
                }

                $debug and $debug & 4096 and _debug("sending " . length($data) . " bytes of data");
                unless ($pipe->print($data)) {
                    $any->_or_set_error(SSHA_SCP_ERROR, "broken pipe");
                    last OUT;
                }
                $size -= length $data;
            }
            $pipe->print($h->on_end_of_file ? "\x00" : "\x01\x0A");
        }
    }

    not $any->{error}
}

sub scp_put {
    my $any = shift;
    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());
    require Net::SSH::Any::SCP::PutHandler::DiskLoader;
    my $h = Net::SSH::Any::SCP::PutHandler::DiskLoader->new($any, \%opts, \@_);
    $any->scp_put_with_handler(\%opts, $h, @_);
}

1;
