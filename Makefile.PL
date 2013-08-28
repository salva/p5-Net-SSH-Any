
use strict;
use warnings;
use 5.008;

use ExtUtils::MakeMaker;

my %prereq_pm = ($ENV{AUTHOR_TESTING} ? ('Test::SSH' => '0.03') : ());

WriteMakefile( NAME          => 'Net::SSH::Any',
               VERSION_FROM  => 'lib/Net/SSH/Any.pm',
               PREREQ_PM     => \%prereq_pm,
               ABSTRACT_FROM => 'lib/Net/SSH/Any.pm',
               AUTHOR        => 'Salvador Fandiño <sfandino@yahoo.com>' );

