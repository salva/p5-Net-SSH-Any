package Net::SSH::Any::SCP::Getter;

use strict;
use warnings;

use Carp;

use Net::SSH::Any::Constants qw(SSHA_SCP_ERROR SSHA_REMOTE_CMD_ERROR);
use Net::SSH::Any::Util qw($debug _debug _debug_hexdump
                           _first_defined _inc_numbered _gen_wanted
                           _scp_escape_name _scp_unescape_name);

sub _or_set_error { shift->{any}->_or_set_error(@_) }

sub _new {
    my ($class, $any, $opts, @srcs) = @_;
    my $g = { any          => $any,
              recursive    => delete($opts->{recursive}),
              glob         => delete($opts->{glob}),
              log          => delete($opts->{log}),
              # on_start   => ...
              # on_end     => ... or enter/leave or whatever
              scp_cmd      => _first_defined(delete($opts->{remote_scp_cmd}), $any->{remote_cmd}{scp}, 'scp'),
              double_dash  => _first_defined(delete($opts->{double_dash}), 1),
              request_time => delete($opts->{request_time}),

              wanted       => _gen_wanted(delete ${$opts}{qw(wanted not_wanted)}),
              srcs         => \@srcs,
              actions      => [],
              error_count  => 0,
              aborted      => undef,
              last_error   => undef,
            };
    bless $g, $class;
    $g;
}

sub _read_line {
    my $g = shift;
    my $pipe = shift;
    $debug and $debug & 4096 and _debug("$g->_read_line($pipe)...");
    for ($_[0]) {
        $_ = '';
        $pipe->sysread($_, 1) or return;
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
    $g->_or_set_error(SSHA_SCP_ERROR, 'broken pipe');
    return;
}

sub _read_response {
    my ($g, $pipe) = @_;
    if ($g->_read_line($pipe, my $buf)) {
	$buf eq "\x00" and return 0;
	$buf =~ /^([\x01\x02])(.*)$/ and return(wantarray ? (ord($1), $2) : ord($1));
	$debug and $debug & 4096 and _debug_hexdump "failed to read response", $buf;
        $g->_or_set_error(SSHA_SCP_ERROR, "SCP protocol error");
    }
    else {
        $g->_or_set_error(SSHA_SCP_ERROR, "broken pipe");
    }
    wantarray ? (2, $g->{any}->error) : 2
}

sub _push_action {
    my ($g, %a) = @_;
    push @{$g->{actions}}, \%a;
    unless (defined $a{path}) {
        # We don't use File::Spec here because we didn't know what
        # the remote file system path separator may be.
        # TODO: allow to change how paths are joined from some setting.
        $a{path} = ( $a{name} =~ m|/|
                     ? $a{name}
                     : join('/', map $_->{name}, @{$g->{actions}}) );
    }
    defined $g->{$_} and $a{$_} = $g->{$_} for qw(mtime atime);
    push @{$g->{log}}, \%a if $g->{log};
    \%a;
}

sub _set_error {
    my ($g, $action, $origin, $error) = @_;
    $action->{error} = $error;
    $action->{error_origin} = $origin;
    $g->{error_count}++;
}

sub set_local_error {
    my ($g, $action, $error) = @_;
    $error = $! unless defined $error;
    $g->{last_error} = $error;
    $g->_set_error($action, 'local', $error);
}

sub last_error {
    my $g = shift;
    my $error = $g->{last_error};
    (defined $error ? $error : 'unknown error')
}

sub abort {
    my $g = shift;
    $g->{aborted} = 1;
}

sub set_remote_error {
    my ($g, $action, $error) = @_;
    $g->_set_error($action, 'remote', $error);
}

sub _check_wanted {
    my ($g, $action) = @_;
    if (my $wanted = $g->{wanted}) {
	unless ($wanted->($action)) {
	    $debug and $debug & 4096 and
		_debugf("%s->set_not_wanted, %s", $g, $action->{path});
	    $action->{not_wanted} = 1;
	    return;
	}
    }
    1;
}

sub on_open {
    my $method = "on_open_$_[1]{type}";
    shift->$method(@_)
}

sub on_open_before_wanted { 1 }

sub _pop_action {
    my ($g, $type) = @_;
    my $action = pop @{$g->{actions}} or
        croak "internal error: _pop_action called but action stack is empty!";
    if (defined $type) {
        $action->{type} eq $type or
            croak "internal error: $type action expected at top of the queue but $action->{type} found";
    }
    $action
}

sub _open {
    my ($g, $type, $perm, $size, $name) = @_;
    my $action = $g->_push_action(type => $type,
                                  perm => $perm,
                                  size => $size,
                                  name => $name);

    if ( $g->on_open_before_wanted($action) and
         $g->_check_wanted($action)         and
         $g->on_open($action) )    { return 1 }

    $g->_pop_action;
    return;
}

sub _close_dir {
    my ($g, $failed, $error) = @_;
    my $action = $g->_pop_action('dir');
    $g->on_close_dir($action);
}

sub on_close {
    my $g = shift;
    my $method = "on_close_$_[0]{type}";
    $g->$method(@_);
}

sub _close {
    my ($g, $type, $failed, $error) = @_;
    my $action = $g->_pop_action($type);
    $g->_set_remote_error($action, $error) if $failed;
    $g->on_close($action, $failed);
}

sub _write {
    my $g = shift;
    $g->on_write($g->{actions}[-1], $_[0]);
}

sub _matime {
    my $g = shift;
    @{$g}{qw(mtime atime)} = @_;
}

sub _remote_error {
    my ($g, $path, $error) = @_;
    my $action =  { type         => 'remote_error',
                    path         => $path };
    $g->set_remote_error($action, $error);
    push @{$g->{log}}, $action if $g->{log};
}

sub _clean_actions {
    my $g = shift;
    while (@{$g->{actions}}) {
        my $type = $g->{actions}[-1]{type};
        my $method = "_close_$type";
        $g->$method(1, "broken pipe");
    }
}

sub on_end_of_get { 1 }

sub run {
    my ($g, $opts) = @_;
    my $any = $g->{any};

    my @cmd   = $any->_quote_args({quote_args => 1},
                                  'strace', '-o', '/tmp/out',
                                  $g->{scp_cmd},
                                  '-f',
                                  ($g->{request_time} ? '-p' : ()),
                                  ($g->{recursive}    ? '-r' : ()),
                                  ($g->{double_dash}  ? '--' : ()));
    my @files = $any->_quote_args({quote_args => 1,
                                   glob_quoting => $g->{glob}},
                                  @{$g->{srcs}});

    my $pipe = $any->pipe({ %$opts, quote_args => 0 },
                          @cmd, @files);
    $any->error and return;

    local $SIG{PIPE} = 'IGNORE';
    my $buf;

    $pipe->syswrite("\x00"); # tell remote side to start transfer
    while (1) {
        $g->_read_line($pipe, $buf, 0) or last;
        $debug and $debug & 4096 and _debug "cmd line: $buf";

        my $ok = 1;

        # C or D:
        if (my ($type, $perm, $size, $name) = $buf =~ /^([CD])([0-7]+) (\d+) (.*)$/) {
            _scp_unescape_name($name);
            $size = int $size;
            $perm = oct $perm;
            if ($type eq 'C') {
		if ($ok = $g->_open(file => $perm, $size, $name)) {
		    $debug and $debug & 4096 and _debug "transferring file of size $size";
		    $pipe->syswrite("\x00");
		    $buf = '';
		    while ($size) {
			my $read = $pipe->sysread($buf, ($size > 16384 ? 16384 : $size));
			unless ($read) {
			    $g->_or_set_error(SSHA_SCP_ERROR, "broken pipe");
			    $g->_close(file => 2, "broken pipe");
			    $debug and $debug & 4096 and _debug "read failed: " . $any->error;
			    last;
			}
			$g->_write($buf) or last;
			$size -= $read;
		    }
		    my ($error_level, $error_msg) = $g->_read_response($pipe);
		    $ok = $g->_close(file => $error_level, $error_msg);
		    last if $error_level == 2;
		}
            }
            else { # $type eq 'D'
		unless ($g->{recursive}) {
		    $g->_or_set_error(SSHA_SCP_ERROR,
                                      "SCP protocol error, unexpected directory entry");
		    last;
		}
                $ok = $g->_open(dir => $perm, $size, $name);
            }

        }
        elsif (my ($mtime, $atime) = $buf =~ /^T(\d+)\s+\d+\s+(\d+)\s+\d+\s*$/) {
            $ok = $g->_matime($mtime, $atime);
        }
        elsif ($buf =~ /^E$/) {
            $ok = $g->_close('dir');
        }
        elsif (my ($error_level, $path, $error_msg) = $buf =~ /^([\x01\x02])scp:(?:\s(.*))?:\s*(.*)$/) {
	    _scp_unescape_name($path) if defined $path;
	    $g->_remote_error($path, $error_msg);
	    next; # do not reply to errors!
	}
	else {
	    $g->_or_set_error(SSHA_SCP_ERROR, "SCP protocol error");
	    $debug and $debug & 4096 and _debug_hexdump "unknown command received", $buf;
	    last;
	}

	$pipe->syswrite( $ok 
			 ? "\x00" 
			 : ( $g->{aborted} ? "\x02" : "\x01") . $g->last_error . "\x0A" )
	    or last;
    }

    $pipe->close;

    $g->_clean_actions;

    if (not $g->on_end_of_get or $g->{error_count}) {
	$g->_or_set_error(SSHA_SCP_ERROR, "SCP transfer not completely successful");
    }

    if ($any->{error}) {
        if ($any->{error} == SSHA_REMOTE_CMD_ERROR) {
            $any->_set_error(SSHA_SCP_ERROR, $any->{error});
        }
        return;
    }
    return 1;
}

1;
