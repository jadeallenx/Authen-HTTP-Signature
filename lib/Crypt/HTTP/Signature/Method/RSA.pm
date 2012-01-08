package Crypt::HTTP::Signature::Method::RSA;

use strict;
use warnings;

use Moo::Role;
use Crypt::OpenSSL::RSA;
use MIME::Base64 qw(encode_base64);

=head1 NAME

Crypt::HTTP::Signature::Method::RSA - Compute digest using asymmetric keys

=head1 VERSION

Version: 0.01

=cut

our $VERSION = '0.01';

=head1 PURPOSE

This role uses asymmetric RSA keys to compute an HTTP::Signature digest. It implements the
RSA-SHA{1, 256, 512} algorithms.

=head1 ATTRIBUTES

=over

=item * public_key_callback

Expects a C<CODE> reference to be used to generate a buffer containing an RSA public key. The key_id attribute's
value will be supplied to the callback as its first parameter. This value should be a string like

  ----BEGIN RSA PUBLIC KEY----
  ...
  ----END RSA PUBLIC KEY----

=back

=cut

has 'public_key_callback' => (
    is => 'rw',
    isa => sub { ref($_[0] eq 'CODE' },
    predicate => 'has_public_key_callback',
    lazy => 1,
);

=over

=item * private_key_callback

Expects a C<CODE> reference to be used to generate a buffer containing an RSA private key. The key_id 
attribute's value will be supplied to the callback as its first parameter. This value should be a string
like:

  ----BEGIN RSA PRIVATE KEY----
  ...
  ----END RSA PRIVATE KEY----

=back

=cut

has 'private_key_callback' => (
    is => 'rw',
    isa => sub { ref($_[0]) eq 'CODE' },
    predicate => 'has_private_key_callback',
    lazy => 1,
);



