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
    $p;
}


sub _readdir {
    my $p = shift;
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

 OUT: while (1) {
        my %action = $p->_readdir;
        my $cmd;
        if (%action) {
            $cmd = ($action{type} eq 'dir'  ? 'D' :
                    $action{type} eq 'file' ? 'C' :
                    croak "internal error: bad action type $action{type}");
        }
        elsif (@{$p->{actions}}) {
            $cmd = 'E';
        }
        else {
            last;
        }

        if ($p->_check_wanted($


	$debug and $debug & 4096 and _debug_dump("next action from handler", $action);

	my $type = _first_defined $action->{type}, 'C';
	$type =~ s/^file$/C/;
	$type =~ s/^dir(?:ectory)?$/D/;
	$type =~ s/^end_of_dir(?:ectory)?$/E/;

	my ($size, $perm, $line);
	my $name = _first_defined $action->{remote}, $target;
	my $ename = $name;
	_scp_escape($ename);

	if ($type =~ /^[CD]$/) {
	    $size = _first_defined $action->{size}, 0;
	    $perm = (_first_defined $action->{perm}, 0777) & 0777;
	    $line = sprintf("%s%04o %d %s", $type, $perm, $size, $ename);
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
	    $any->_or_set_error(SSHA_SCP_ERROR, "broken pipe");
	    last;
	}

	for my $first (1, 0) {
	    my ($error_level, $error_msg) = $any->_scp_read_response($pipe);
	    if ($error_level) {
		$p->on_action_refused($error_level, $error_msg);
		last OUT if $error_level == 2;
		last;
	    }

	    last unless $first and $type eq 'C';

	    $debug and $debug & 4096 and _debug("sending file of $size bytes");
	    my $bad_size = 0;
	    while ($size > 0) {
		my $data;
		if ($bad_size) {
		    $data = "\0" x ($size > 16384 ? 16384 : $size);
		}
		else {
		    $data = $p->on_send_data($size);
		    unless (defined $data and length $data) {
			$bad_size = 1;
			$debug and $debug & 4096 and _debug("no data from put handler");
			redo;
		    }
		    if (length($data) > $size) {
			$debug and $debug & 4096 and _debug("too much data, discarding excess");
			substr($data, $size) = '';
			$bad_size = 1;
		    }
		}
		$debug and $debug & 4096 and _debug_hexdump("sending data (bad_size: $bad_size)", $data);
		unless ($pipe->print($data)) {
		    $any->_or_set_error(SSHA_SCP_ERROR, "broken pipe");
		    last OUT;
		}
		$size -= length $data;
	    }
	    my $ok = $p->on_end_of_file($bad_size);
	    $pipe->print($ok ? "\x00" : "\x01\x0A");
	}
    } # OUT

    $pipe->close;

    $p->on_end_of_put;
    not $any->error
}

1;
