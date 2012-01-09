package Crypt::HTTP::Signature::Parse;

use strict;
use warnings;

use Moo::Role;

=head1 NAME

Crypt::HTTP::Signature::Parse - Parse HTTP signature headers

=head1 VERSION

Version: 0.01

our $VERSION = '0.01';

=head1 PURPOSE

This role parses HTTP signature headers (if one exists) from a request.

=head1 ATTRIBUTES

=over

=item header_callback

Expects a C<CODE> reference.  

This callback represents the method to get header values from the request object passed to C<parse()>. 
If the request is a scalar string or L<HTTP::Request> object (or something that implements the 
same API as L<HTTP::Request> for headers), no callback is necessary - the parser will coerce the string 
into an L<HTTP::Request> object automatically and use the default callback which expects an 
L<HTTP::Request> as the request.

The request will be the first parameter, and name of the header to fetch a value will be provided 
as the second parameter to the callback. The callback should return the value(s) of that header.

=back

=cut

has 'header_callback' => (
    is => 'rw',
    isa => sub { ref($_[0]) eq "CODE" },
    predicate => 'has_header_callback',
    default => sub { 
        my $self = shift;
        my $request = shift;
        my $header_name = shift;

        return $request->header($header_name);
    }
    lazy => 1,
);

=head1 METHOD

=over

=item parse()

This implements the parsing of the signature header components.  It returns a new L<Crypt::HTTP::Signature>
object on success, undef otherwise.

=back

=cut

sub parse {
    my $self = shift;
    my $request = shift;

    my $sig_str = $self->header_callback->($request, 'Authorization');

    confess 'No Authorization header value was returned!' unless $sig_str;

# Authorization: Signature keyId="Test",algorithm="rsa-sha256" MDyO5tSvin5FBVdq3gMBTwtVgE8U/JpzSwFvY7gu7Q2tiZ5TvfHzf/RzmRoYwO8PoV1UGaw6IMwWzxDQkcoYOwvG/w4ljQBBoNusO/mYSvKrbqxUmZi8rNtrMcb82MS33bai5IeLnOGl31W1UbL4qE/wL8U9wCPGRJlCFLsTgD8=

    my ( $sig_text, $params, $b64_str ) = split / /, $sig_str;

    confess "$sig_text does not match 'Signature'" unless $sig_text =~ /^Signature$/;

    my ( $key_id, $algo, $headers ) = split /,/ $params;

    $key_id =~ s/keyId="(.+)"/$1/;
    $algo =~ s/algorithm="(.+)"/$1/;
    $headers =~ s/headers="(.+)"/$1/;

    my @hdrs = split / /, $headers;

    push @hdrs, "Date" unless @hdrs;

    # detect duplicate headers

    my $h;
    foreach my $hdr ( @hdrs ) {
        if ( exists $h->{$hdr} ) {
            confess "Duplicate header $hdr found in request. Aborting.";
        }
        $h->{$hdr}++;
    }




}

1;
