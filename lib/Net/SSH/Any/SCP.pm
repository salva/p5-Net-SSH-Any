package Net::SSH::Any::SCP;

package Net::SSH::Any;

our $debug;

use strict;
use warnings;

sub _scp_get_with_handler {
    my $any = shift;
    my $opts = shift;
    my $handler = shift;

    my $pipe = $any->pipe($opts, scp => '-f', '--', @_);
    $any->error and return;

    my $on_error;
    my $buf;
    while (1) {
        $pipe->syswrite("\x00");

        $buf = '';
        do {
            # my $bytes = $pipe->sysread($buf, ($on_error ? 1 : 10000), length $buf);
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
        elsif (my ($perm, $size, $name) = $buf =~ /^C([0-7]+) (\d+) (.*)$/) {
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
            $handler->on_eof or return;
        }
        elsif ($buf =~ /^D/) {
            $handler->on_D or return;
            $handler->on_eof;
        }
        elsif ($buf =~ /^E/) {
            $handler->on_E or return;
            $handler->on_eof;
        }
        else {
            $debug and $debug & 4096 and _debug "unknown command received: " . $buf;
            return;
        }
    }
}

sub scp_get {
    my $any = shift;
    my $opts = shift;
    my $target = pop @_;
    my $handler = Net::SSH::Any::SCP::GetHandler::Disk->_new($any, $target);
    $any->_scp_get_with_handler($opts, $handler, @_)
}

sub scp_put {

}

package Net::SSH::Any::SCP::GetHandler;

sub _new {
    my ($class, $any) = @_;
    my $h = { any => $any,
              error => undef };
    bless $h, $class;
}

sub on_error {
    my ($h, $error) = @_;
    print STDERR "scp error: $error\n";
}

package Net::SSH::Any::SCP::GetHandler::Disk;
our @ISA = qw(Net::SSH::Any::SCP::GetHandler);

sub _new {
    my ($class, $any, $target) = @_;
    my $h = $class->SUPER::_new($any);
    $h->{target} = $target;
    $h;
}

sub on_C {
    my ($h, $perm, $size, $name) = @_;
    $h->{current_perm} = $perm;
    $h->{current_size} = $size;
    $h->{current_name} = $name;
    1;
}

sub on_data {
    my $h = shift;
    $debug and $debug and 4096 and Net::SSH::Any::_debug length($_[0]) . " bytes received:\n>>>$_[0]<<<\n\n";
    1;
}

sub on_eof {
    my $h = shift;
    $debug and $debug and 4096 and Net::SSH::Any::_debug "EOF received";
    1;
}

1;
