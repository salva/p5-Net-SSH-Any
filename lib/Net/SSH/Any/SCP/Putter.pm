package Net::SSH::Any::SCP::Putter;

use strict;
use warnings;

use Carp;

use Net::SSH::Any::Constants qw(SSHA_SCP_ERROR SSHA_REMOTE_CMD_ERROR);
use Net::SSH::Any::Util qw($debug _debug _debugf _debug_hexdump
                           _first_defined _inc_numbered _gen_wanted
                           _scp_escape_name _scp_unescape_name);

require Net::SSH::Any::SCP::Base;
our @ISA = qw(Net::SSH::Any::SCP::Base);

sub _new {
    my ($class, $any, $opts, $target) = @_;
    my $p = $class->SUPER::_new($any, $opts);
    $p->{target} = $target;
    $p->{recursive} = delete $opts->{recursive};
    $p->{target_is_dir} = delete $opts->{target_is_dir};
    $p->{handles} = [];
    $p;
}

sub read_dir {}
sub _read_dir {
    my ($p, $action) = @_;
    $p->read_dir($action, ($action ? $action->{_handle} : undef));
}

sub open_dir {}
sub open_file {}

sub _open {
    my ($p, $action) = @_;
    my $method = "open_$action->{type}";
    my $handle = $p->$method($action);
    if (defined $handle) {
        $p->{_handle} = $handle;
        return 1;
    }
    else {
        $p->set_local_error($action, "unable to open directory or file for $action->{path}");
        return
    }
}

sub close_dir {}
sub close_file {}

sub _close {
    my ($p, $action) = @_;
    my $method = "close_$action->{type}";
    $p->$method($action, delete $action->{_handle}) and return 1;
    $p->set_local_error($action, "unable to close directory or file $action->{path}");
    return
}

sub _read_file {
    my ($p, $action, $len) = @_;
    $p->read_file($action, $action->{_handle}, $len);
}

sub _send_line_and_get_response {
    my ($p, $action, $line) = @_;
    my ($fatal, $error) = ( $pipe->print($line)
                            ? $p->_read_response($pipe)
                            : (2, "broken pipe"));
    if ($fatal) {
        $p->set_remote_error($action, $error);
        $fatal > 1 and $p->abort;
        return;
    }
    return 1;
}

sub _remote_open {
    my ($p, $action) = @_;
    my ($type, $perm, $size, $name) = @{$action}{qw(type perm size name)};
    my $cmd = ($type eq 'dir'  ? 'D' :
               $type eq 'file' ? 'C' :
               croak "bad action type $action->{type}");
    $perm = (defined $perm ? $perm : 0777);
    _scp_escape_name($name);
    $p->_send_line_and_get_response($action, sprintf("%s%04o %d %s\x0A", $cmd, $perm, $size, $name));
}

sub _clean_actions {
    my $p = shift;
    while (my $action = $p->_pop_action(undef, 1)) {
        $p->_close($action, 2, "broken pipe");
    }
}

sub run {
    my ($p, $opts) = @_;
    my $pipe = $any->pipe({ %$opts, quote_args => 1 },
                          # 'strace', '-fo', '/tmp/scp.strace',
                          $p->{scp_cmd},
                          '-t',
			  ($p->{target_is_dir} ? '-d' : ()),
			  ($p->{recursive}     ? '-r' : ()),
                          ($p->{double_dash}   ? '--' : ()),
                          $target);
    $any->error and return;

    local $SIG{PIPE} = 'IGNORE';

    my ($error_level, $error_msg) = $p->_read_response($pipe);
    if ($error_level) {
	$any->_or_set_error(SSHA_SCP_ERROR, "remote SCP refused transfer", $error_msg);
	return;
    }
 OUT: while (!$p->{aborted}) {
        my $line;
        my $current_dir_action = $p->{actions}[-1];
        if (my $action = $p->_read_dir($current_dir_action)) {
            my $type = $action->{type};
            $action = $p->_push_action(%$action);

            $debug and $debug & 4096 and _debug_dump("next action", $action);

            # local_error actions are just pushed into the log
            if ($type ne 'local_error' and $p->_check_wanted($action)) {
                if ($type eq 'dir') {
                    if ($p->_open_dir($action)) {
                        if ($p->_remote_open($pipe, $action)) {
                            next; # do not pop the action
                        }
                        $p->_close($action);
                    }
                }
                elsif ($type eq 'file') {
                    if ($p->_open_file($action)) {
                        if ($p->_remote_open($pipe, $action)) {
                            my $remaining = $action{size} || 0;
                            my $failed;
                            while ($remaining > 0) {
                                my $data;
                                my $len = ($remaining > 16384 ? 16386 : $remaining);
                                if ($failed) {
                                    $data = "\0" x $len;
                                }
                                else {
                                    $data = $p->_read_file($action, $len);
                                    unless (defined $data and length $data) {
                                        $failed = 1;
                                        $debug and $debug & 4096 and _debug "no data from putter";
                                        redo;
                                    }
                                    if (length($data) > $size) {
                                        $debug and $debug & 4096 and _debug("too much data, discarding excess");
                                        substr($data, $size) = '';
                                        failed = 1;
                                    }
                                }
                                $debug and $debug & 4096 and _debug_hexdump("sending data (bad_size: $bad_size)", $data);
                                $pipe->print($data) or last OUT;
                            }
                        }
                        $p->_close($action) or $failed = 1;
                        $p->_send_line_and_get_response($action, ($failed ? "\x01failed\x0A" : "\x00"));
                    }
                }
                else {
                    croak "internal error: bad action type $type"
                }
            }
            $p->_pop_action;
        }
        else {
            my $action = $p->_pop_action('dir', 1) or last;
            $p->_send_line_and_get_response($action, "E\x0A")
        }
    }

    $pipe->close;

    $p->_clean_actions;

    $p->on_end_of_put or
        $g->_or_set_error(SSHA_SCP_ERROR, "SCP transfer not completely successful");

    not $any->error
}

1;
