package Net::SSH::Any::SCP;

use strict;
use warnings;

use Net::SSH::Any;
package Net::SSH::Any;

our $debug;

sub _scp_unescape {
    s/\\\\|\\\^([A-Z])/$1 ? chr(ord($1) - 64) : '\\'/ge for @_;
}

sub _scp_get_with_handler {
    my $any = shift;
    my $opts = shift;
    my $handler = shift;

    my $glob = delete $opts->{glob};
    my $recursive = delete $opts->{recursive};
    my $double_dash = _first_defined(delete $opts->{double_dash}, 1);

    my $remote_scp_command =  _first_defined delete($opts->{remote_scp_cmd}), $any->{remote_cmd}{scp}, 'scp';

    my @cmd   = $any->_quote_args({quote_args => 1},
                                  $remote_scp_command,
                                  '-f',
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

        $buf = '';
        do {
            my $bytes = $pipe->sysread($buf, 1, length $buf);
            unless ($bytes) {
                $debug and $debug & 4096 and _debug "$bytes read from pipe, error: " . $any->error;
                return;
            }
        } until $buf =~ /\x0A$/;

        $debug and $debug & 4096 and _debug "cmd line: $buf";

        # \x00:
        if (my ($error) = $buf =~ /^\x00(.*)/) {
            $debug and $debug & 4096 and _debug "remote error: " . $error;
        }
        # C:
        elsif (my ($type, $perm, $size, $name) = $buf =~ /^([CD])([0-7]+) (\d+) (.*)$/) {
            _scp_unescape($name);
            $perm = oct $perm;
            if ($type eq 'C') {
                $handler->on_file($perm, $size, $name) or return;
                $debug and $debug & 4096 and _debug "transferring file of size $size";
                $pipe->syswrite("\x00");
                $buf = '';
                while ($size) {
                    my $read = $pipe->sysread($buf, ($size > 16384 ? 16384 : $size));
                    unless ($read) {
                        $debug and $debug & 4096 and _debug "read failed: " . $any->error;
                        return;
                    }
                    $handler->on_data($buf) or return;
                    $size -= $read;
                }
                $buf = '';
                unless ($pipe->sysread($buf, 1) and $buf eq "\x00") {
                    $debug and $debug & 4096 and _debug "sysread failed to read ok code: $buf";
                    return;
                }
                $handler->on_end_of_file or return;
            }
            else { # $type eq 'D'
                $handler->on_dir($perm, $size, $name) or return;
            }
        }
        elsif ($buf =~ /^E(.*)/) {
            $handler->on_end_of_dir($1) or return;
        }
        elsif (my ($name, $error) = $buf =~ /^\x01scp:\s(.*):\s*(.*)$/) {
            _scp_unescape($name);
            $handler->on_remote_error($name, $error) or return;
        }
        elsif (my ($error) = $buf =~ /^\x01(?:scp:\s)?(.*)$/) {
            $handler->on_remote_error(undef, $error) or return;
        }
        else {
            $debug and $debug & 4096 and
                _debug "unknown command received, code: " .ord($buf). " rest: >>>" .substr($buf, 1). "<<<";
            return;
        }
    }
}

sub scp_get {
    my $any = shift;
    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());
    my $handler = Net::SSH::Any::SCP::GetHandler::Disk->_new($any, \%opts, \@_);
    $any->_scp_get_with_handler(\%opts, $handler, @_)
}

sub scp_put {

}

package Net::SSH::Any::SCP::GetHandler;

sub _new {
    my ($class, $any, $opts, $files) = @_;
    my $h = { any => $any,
              action_log => delete $opts->{action_log},
            };

    bless $h, $class;
}

for my $method (qw(on_file on_data on_end_of_file on_dir on_end_of_dir)) {
    no strict;
    *{$method} = sub {
        if ($debug and $debug and 4096) {
            my $args = (@_ == 4              ? "perm: $_[1], size: $_[2], name: $_[3]" :
                        $method eq 'on_data' ? length($_[1]) . " bytes"                :
                        '' );
            Net::SSH::Any::_debug "called $_[0]->$method($args)";
        }
    };
}

sub _scp_error {
    my $h = shift;
    $h->{any}->_set_error(SSHA_SCP_ERROR => @_);
    return
}

sub _push_action {
    my ($h, %action) = @_;
    my $action = \%action;
    local ($@, $SIG{__WARN__}, $SIG{__DIE__});
    eval { push @{$h->{action_log}}, $action };
    $action
}

sub on_remote_error {
    my ($h, $path, $error) = @_;
    $debug and $debug & 4096 and Net::SSH::Any::_debug("$h->on_remote_error(@_)");
    $h->_push_action( action_type => 'remote_error',
                      path => $path,
                      error => $error} );
}

package Net::SSH::Any::SCP::GetHandler::Disk;
our @ISA = qw(Net::SSH::Any::SCP::GetHandler);

sub _new {
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
    $h->{parent_dir} = [];
    $h->{dir_perms} = [];

    $h;
}

sub on_file {
    my ($h, $perm, $size, $name) = @_;
    $debug and $debug and 4096 and Net::SSH::Any::_debug "on_file(perm: $perm, size: $size, name: $name)";
    $h->{current_perm} = $perm;
    $h->{current_size} = $size;
    $h->{current_name} = $name;
    my $fn = (defined $h->{target_dir}
              ? File::Spec->join($h->{target_dir}, $name)
              : $h->{target});
    $debug and $debug & 4096 and Net::SSH::Any::_debug "opening file $fn";
    open my $fh, ">", $fn;
    unless ($fh) {
        $h->_scp_error("Unable to create file '$fn'", $!);
        return
    }
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
        $h->_scp_error("Unable to write to file '$h->{current_fn}'", $!);
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
    push @{$h->{dir_perm}}, $perm;
    $h->{target_dir} = $dn;

    unless (-d $dn or mkdir $dn, 0700 | ($perm & 0777)) {
        $h->_scp_error("Unable to create directory '$dn'", $!);
        return;
    }
    unless (-x $dn) {
        $h->_scp_error("Access forbidden to directory '$dn'", $!);
        return;
    }

    1;
}

sub on_end_of_dir {
    my $h = shift;
    $debug and $debug and 4096 and Net::SSH::Any::_debug "on_end_of_dir";
    my $perm = pop @{$h->{dir_perms}};
    chmod $perm, $h->{target_dir} if defined $perm;
    $h->{target_dir} = pop @{$h->{parent_dir}};
    1;
}



1;
