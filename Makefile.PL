
use strict;
use warnings;
use 5.008;

use ExtUtils::MakeMaker;
WriteMakefile( NAME          => 'Net::SSH::Any',
               VERSION_FROM  => 'lib/Net/SSH/Any.pm',
               PREREQ_PM     => {},
               ABSTRACT_FROM => 'lib/Net/SSH/Any.pm',
               AUTHOR        => 'Salvador Fandiño <sfandino@yahoo.com>' );
