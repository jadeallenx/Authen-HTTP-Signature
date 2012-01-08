package Crypt::HTTP::Signature::Method::HMAC;

use 5.010;
use warnings;
use strict;

use Moo::Role;
use Digest::SHA qw(hmac_sha1_base64 hmac_sha256_base64 hmac_sha512_base64);
use Carp qw(confess);

=head1 NAME

Crypt::HTTP::Signature::Method::HMAC - Compute digest using a symmetric key

=head1 VERSION

Version: 0.01

=cut

our $VERSION = '0.01';

=head1 PURPOSE

This role uses a symmetric key to compute an HTTP::Signature digest. It implements the
HMAC-SHA{1, 256, 512} algorithms.

=head1 ATTRIBUTES

These are Perlish mutators; pass a value to set it, pass no value to get the current value.

=over

=item * key_callback

Expects a C<CODE> reference to be used to generate the key material for the digest. The C<key_id>
will be passed as the first parameter to the callback.

=back

=cut

has 'key_callback' => (
    is => 'rw',
    isa => sub { ref($_[0]) eq "CODE" },
    predicate => 'has_key_callback',
);


=head1 METHODS

=cut

sub _pad_base64 {
    my $self = shift;
    my $b64_str = shift;

    my $n = length($b64_str) % 4;

    if ( $n ) {
        $b64_str .= '=' x $n;
    }

    return $b64_str;
}

sub _get_digest {
    my $self = shift;
    my $algo = shift;
    my $data = shift;
    my $key = shift;

    my $digest;
    for ( $algo ) {
        when ( /sha1/ ) {
            $digest = hmac_sha1_base64($data, $key);
        }
        when ( /sha256/ ) {
            $digest = hmac_sha256_base64($data, $key);
        }
        when ( /sha512/ ) {
            $digest = hmac_sha512_base64($data, $key);
        }
    }

    confess "I couldn't get a $algo digest\n" unless defined $digest && length $digest;

    return $digest;
}

=over

=item sign()

This method computes and returns a base 64 encoded digest of the C<signing_string>. It is also
stored as C<signature>.

=back

=cut

sub sign {
    my $self = shift;
    
    confess "How can I sign anything without a signing string?\n" unless $self->has_signing_string;
    confess "How can I sign anything without a key?\n" unless $self->has_key_callback;

    my $key = $self->key_callback->($self->key_id);

    my $digest = $self->_get_digest($self->algorithm, $self->signing_string, $key);
    
    return $self->signature( $self->_pad_base64( $digest ) );
}

=over

=item validate()

This method compares a candidate signature to a computed signature. If they are the same, it
returns a true value. Otherwise, it returns a false value.

=back

=cut

sub validate {
    my $self = shift;
    
    my $candidate = self->signature;

    confess "How can I validate anything without a signing string?" unless $self->has_signing_string;
    confess "How can I validate anything without a key?" unless $self->has_key_callback;

    my $key = $self->key_callback->($self->key_id);

    my $digest = $self->_get_digest($self->algorithm, $self->signing_string, $key);
    
    return $self->_pad_base64( $digest ) eq $candidate;
}

1;
