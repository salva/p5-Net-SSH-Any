package Net::SSH::Any::SCP;

use Net::SSH::Any;
package Net::SSH::Any;

use strict;
use warnings;

use Fcntl ();

our $debug;

sub _scp_unescape {
    s/\\\\|\\\^([A-Z])/$1 ? chr(ord($1) - 64) : '\\'/ge for @_;
}

sub scp_get_with_handler {
    my $any = shift;
    my $opts = shift;
    my $h = shift;

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
                length $buf and $any->_or_set_error(SSHA_SCP_ERROR, 'broken pipe');
                last;
            }
        } until $buf =~ /\x0A$/;

        $debug and $debug & 4096 and _debug "cmd line: $buf";

        my ($type, $perm, $size, $name, $error);

        # C:
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
                $buf = '';
                unless ($pipe->sysread($buf, 1) and $buf eq "\x00") {
                    $any->_or_set_error(SSHA_SCP_ERROR, "SCP protocol error");
                    $debug and $debug & 4096 and _debug "sysread failed to read ok code: $buf";
                    last;
                }
                $h->on_end_of_file or last;
            }
            else { # $type eq 'D'
                $h->on_dir($perm, $size, $name) or last;
            }
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
    my $h = Net::SSH::Any::SCP::GetHandler::DiskSaver->_new($any, \%opts, \@_);
    $any->scp_get_with_handler(\%opts, $h, @_)
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

sub _scp_local_error {
    my $h = shift;
    $h->{any}->_set_error(@_, $!);

    local ($@, $SIG{__DIE__}, $SIG{__WARN__});
    eval {
        my $action = $h->{action_log}[-1];
        $action->{error} = $_[0];
        $action->{errno} = $!;
    };
    return;
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
    $h->_push_action( type => 'remote_error',
                      remote => $path,
                      error => $error );
    1
}

sub on_end_of_get {
    my $h = shift;
    $debug and $debug & 4096 and Net::SSH::Any::_debug("$h->on_end_of_get(@_)");
    1
}

package Net::SSH::Any::SCP::GetHandler::DiskSaver;
our @ISA = qw(Net::SSH::Any::SCP::GetHandler);

BEGIN { *_first_defined = \&Net::SSH::Any::_first_defined }

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

    $h->{numbered} = delete $opts->{numbered};
    unless ($h->{numbered}) {
        $h->{overwrite} = _first_defined delete($opts->{overwrite}), 1;
    }
    $h->{copy_perm} = _first_defined delete($opts->{copy_perm}), 1;

    $h->{parent_dir} = [];
    $h->{dir_perms} = [];
    $h->{dir_parts} = [];

    $h;
}

sub _inc_numbered {
    $_[0] =~ s{^(.*)\((\d+)\)((?:\.[^\.]*)?)$}{"$1(" . ($2+1) . ")$3"}e or
    $_[0] =~ s{((?:\.[^\.]*)?)$}{(1)$1};
    $debug and $debug & 128 and _debug("numbering to: $_[0]");
}

sub on_file {
    my ($h, $perm, $size, $name) = @_;
    $debug and $debug and 4096 and Net::SSH::Any::_debug "on_file(perm: $perm, size: $size, name: $name)";

    my $fn = (defined $h->{target_dir}
              ? File::Spec->join($h->{target_dir}, $name)
              : $h->{target});
    $debug and $debug & 4096 and Net::SSH::Any::_debug "opening file $fn";

    my $action = $h->_push_action(type   => 'file',
                                  remote => join('/', @{$h->{dir_parts}}, $name),
                                  local  => $fn,
                                  perm   => $perm,
                                  size   => $size );

    unlink $fn if $h->{overwrite};

    my $flags = Fcntl::O_CREAT|Fcntl::O_WRONLY;
    $flags |= Fcntl::O_EXCL if $h->{numbered} or not $h->{overwrite};
    $perm = 0777 unless $h->{copy_perm};

    my $fh;
    while (1) {
        sysopen $fh, $fn, $flags, $perm and last;
        unless ($h->{numbered} and -e $fn) {
            $h->_scp_local_error("Unable to create file '$fn'");
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
    $debug and $debug and 4096 and Net::SSH::Any::_debug length($_[0]) . " bytes received:\n>>>$_[0]<<<\n\n";
    print {$h->{current_fh}} $_[0];
    1;
}

sub on_end_of_file {
    my $h = shift;
    $debug and $debug and 4096 and Net::SSH::Any::_debug "on_end_of_file";
    unless (close $h->{current_fh}) {
        $h->_scp_local_error("Unable to write to file '$h->{current_fn}'");
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
    push @{$h->{dir_parts}}, $name;
    push @{$h->{dir_perm}}, $perm;
    $h->{target_dir} = $dn;

    $h->_push_action(type   => 'dir',
                     remote => join('/', @{$h->{dir_parts}}),
                     local  => $dn,
                     perm   => $perm);

    $perm = 0777 unless $h->{copy_perm};

    unless (-d $dn or mkdir $dn, 0700 | ($perm & 0777)) {
        $h->_scp_local_error("Unable to create directory '$dn'");
        return;
    }
    unless (-x $dn) {
        $h->_scp_local_error("Access forbidden to directory '$dn'");
        return;
    }
    1;
}

sub on_end_of_dir {
    my $h = shift;
    $debug and $debug and 4096 and Net::SSH::Any::_debug "on_end_of_dir";
    pop @{$h->{dir_parts}};
    my $perm = pop @{$h->{dir_perm}};
    $perm = 0777 unless $h->{copy_perm};
    chmod $perm, $h->{target_dir} if defined $perm;
    $h->{target_dir} = pop @{$h->{parent_dir}};
    1;
}

1;
