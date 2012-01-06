#!perl -T

use Test::More tests => 1;

BEGIN {
    use_ok( 'Crypt::HTTP::Signature' ) || print "Bail out!\n";
}

diag( "Testing Crypt::HTTP::Signature $Crypt::HTTP::Signature::VERSION, Perl $], $^X" );
