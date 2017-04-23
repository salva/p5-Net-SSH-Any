package Net::SSH::Any::DPipe;

use strict;
use warnings;

use Carp;
our @CARP_NOT = qw(Net::SSH::Any);

sub expecter {
    my $dpipe = shift;
    $dpipe->_any->_load_module('Net::SSH::Any::Expect') or return;
    Net::SSH::Any::Expect->_new($dpipe->_any, $dpipe, @_);
}

1;

__END__

=head1 NAME

Net::SSH::Any::DPipe - bidirectional communication with remote process

=head1 SYNOPSIS

  my $dpipe = $ssh->dpipe(\%opts, @cmd);

  # IO::Handle interface...
  my $wlen = $dpipe->syswrite($wbuf);
  my $rlen = $dpipe->sysread($rbuf, 1024);
  my $line = $dpipe->getline;

=head1 DESCRIPTION

Objects of any of the classes derived from Net::SSH::Any::DPipe
support a subset of L<IO::Handler> API.

Specifically, the following methods are supported:

    close eof fileno getc read print printf say sysread syswrite
    blocking opened getline getlines write error clearerr sync flush
    printflush blocking

=head1 BUGS

This module is still experimental. DPipe support may vary across backends.

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2011-2017 by Salvador FandiE<ntilde>o,
E<lt>sfandino@yahoo.comE<gt>

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.12.4 or,
at your option, any later version of Perl 5 you may have available.

=cut
