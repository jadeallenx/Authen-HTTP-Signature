package Crypt::HTTP::Signature;

use 5.010;
use strict;
use warnings;

use Moo;
use Scalar::Util qw(blessed);
use List::Util qw(first);
use Carp qw(confess);

use Digest::MD5 qw(md5_base64);

with 'Crypt::HTTP::Signature::Parse';

=head1 NAME

Crypt::HTTP::Signature - Sign and validate HTTP headers

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';

=head1 SYNOPSIS

Create signatures:

    use 5.010;
    use Crypt::HTTP::Signature;
    use File::Slurp qw(read_file);
    use HTTP::Request::Common;

    my $c = Crypt::HTTP::Signature->new(
        private_key_callback => sub { read_file("/my/priv_key.pem") or die $!; },
        key_id => 'Test',
    );

    my $req = POST('http://example.com/foo?param=value&pet=dog', 
            Content_Type => 'application/json',
            Content_MD5 => 'Sd/dVLAcvNLSq16eXua5uQ==',
            Content_Length => 18,
            Date => 'Thu, 05 Jan 2012 21:31:40 GMT',
            Content => '{"hello": "world"}'
    );

    my $signed_req = $c->sign_request($req); # signs the default 'Date' header with private_key

Validate signatures:

    use 5.010;
    use Crypt::HTTP::Signature;
    use HTTP::Request::Common;
    use File::Slurp qw(read_file);

    my $req = POST('http://example.com/foo?param=value&pet=dog', 
            Content_Type => 'application/json',
            Content_MD5 => 'Sd/dVLAcvNLSq16eXua5uQ==',
            Content_Length => 18,
            Date => 'Thu, 05 Jan 2012 21:31:40 GMT',
            Authorization => q{Signature keyId="Test",algorithm="rsa-sha256" MDyO5tSvin5FBVdq3gMBTwtVgE8U/JpzSwFvY7gu7Q2tiZ5TvfHzf/RzmRoYwO8PoV1UGaw6IMwWzxDQkcoYOwvG/w4ljQBBoNusO/mYSvKrbqxUmZi8rNtrMcb82MS33bai5IeLnOGl31W1UbL4qE/wL8U9wCPGRJlCFLsTgD8=},
            Content => '{"hello": "world"}'
    );

    $c = Crypt::HTTP::Signature->new( 
        request => $req,
        public_key_callback => sub{ read_file("/my/public/key.pem") },
    );

    if ( $c->validate() ) {
        say "Request is valid!"
    }
    else {
        say "Request isn't valid";
    };

=head1 PURPOSE

This is an implementation of Joyent's HTTP signature authentication scheme. The idea is to authenticate
connections (over HTTPS ideally) using either an RSA keypair or a symmetric key by signing a set of header 
values.

=head1 ATTRIBUTES

These are Perlish mutators; give an argument to set a value or no argument to get the current value.

=over

=item algorithm

One of:

=over

=item * C<rsa-sha1>

=item * C<rsa-sha256> (B<default>)

=item * C<rsa-sha512>

=item * C<hmac-sha1>

=item * C<hmac-sha256>

=item * C<hmac-sha512>

=back

=back

=cut

has 'algorithm' => (
    is => 'rw',
    isa => sub { 
        my $n = shift; 
        confess "$n doesn't match any supported algorithm.\n" unless 
            scalar grep { $_ eq $n } qw(
                rsa-sha1 
                rsa-sha256 
                rsa-sha512 
                hmac-sha1 
                hmac-sha256 
                hmac-sha512
            ); 
    },
    default => sub { 'rsa-sha256' },
);

=over

=item headers

The list of headers to be signed (or already signed.) Defaults to the 'Date' header. The order of the headers 
in this list will be used to build the order of the text in the signing string.

This attribute can have some psuedo-values. These are:

=over

=item * C<request-line>

Use the text of the path and query from the request (e.g., C</foo?param=value&pet=dog>) as part of 
the signing string.

=item * C<all>

Use all headers in a given request including C<request-line> itself in the signing string.

=back

=back

=cut

has 'headers' => (
    is => 'rw',
    isa => sub { confess "The 'headers' attribute expects an arrayref.\n" unless ref($_[0]) eq ref([]) },
    default => sub { [ 'Date' ] },
);

=over

=item signing_string

The string used to compute the signature digest. It contents are derived from the 
values of the C<headers> array.

=back

=cut

has 'signing_string' => (
    is => 'rw',
    predicate => 'has_signing_string',
);

=over

=item signature

Contains the digital signature authorization data.

=back

=cut

has 'signature' => (
    is => 'rw',
    predicate => 'has_signature',
);

=over

=item extensions

There are currently no extentions implemented by this library, but the library will append extension
information to the generated header data if this attribute has one or more values.

=back

=cut

has 'extensions' => (
    is => 'rw',
    predicate => 'has_extensions',
);


=over

=item key_id

A means to identify the key being used to both sender and receiver. This can be any token which makes
sense to the sender and receiver. The exact specification of a token and any necessary key management 
are outside the scope of this library.

=back

=cut

has 'key_id' => (
    is => 'rw',
    predicate => 'has_key_id',
);

=over

=item request

Holds the request to be parsed.

=back

=cut

has 'request' => (
    is => 'rw',
    isa => sub { confess ref($_[0]) . " isn't a HTTP::Request" unless blessed($_[0]) =~ /HTTP::Request/ },
    predicate => 'has_request',
);

around request => sub {
    my $orig = shift;
    my $r = shift;

    unless( blessed($r) eq "HTTP::Request" ) {
        if ( ! ref($r) ) {
            $orig->request( HTTP::Request->parse($r) );
        }
        else {
            confess "I don't know how to coerce " . ref($r);
        }
    }
};

=over

=item authorizaton_string

The text to identify the HTTP signature authorization scheme. Currently defined as the string
literal 'Signature'.  Read-only.

=back

=cut

has 'authorization_string' => (
    is => 'ro',
    default => sub { 'Signature' },
);

=over

=item header_callback

Expects a C<CODE> reference.  

This callback represents the method to get header values from the object in the C<request> attribute. 

The request will be the first parameter, and name of the header to fetch a value will be provided 
as the second parameter to the callback.

B<NOTE>: The callback should be prepared to handle a "psuedo-header" of C<request-line> which
is the path and query portions of the request's URI. (For more information see the 
L<HTTP signature specification|https://github.com/joyent/node-http-signature/blob/master/http_signing.md>.)

=back

=cut

has 'header_callback' => (
    is => 'rw',
    isa => sub { die "'header_callback' expects a CODE ref\n" unless ref($_[0]) eq "CODE" },
    predicate => 'has_header_callback',
    default => sub { 
        my $self = shift;
        my $request = shift;
        my $header_name = shift;

        $header_name eq 'request-line' ? $request->uri->path_query : $request->header($header_name);
    },
    lazy => 1,
);

=over 

=item skew

Defaults to 300 seconds in either direction from your clock. If the Date header data is outside of this range, 
the request is considered invalid.

Set this value to 0 to disable skew checks for testing purposes.

=back

=cut

has 'skew' => (
    is => 'rw',
    isa => sub { die "$_[0] isn't an integer" unless $_[0] =~ /0-9+/ },
    default => { 300 },
);

=head1 METHODS

The specific signature, validation, and signature header parsing methods are provided by various
roles: L<Crypt::HTTP::Signature::Method::HMAC>, L<Crypt::HTTP::Signature::Method::RSA>, 
L<Crypt::HTTP::Signature::Parse>.  Please see those roles' documentation for more information
about them.

=over 

=item update_signing_string()

This method updates a signing string using the contents of the C<headers> attribute.

=back

=cut

# if we find the 'all' header value, explode to include all headers.
sub _explode_headers {
    my $self = shift;

    if ( first { $_ eq 'all' } @{ $self->headers } ) {
        my @all = $self->request->header->header_field_names;
        unshift @all, 'request-line';
        $self->headers( \@all );
    }
}

sub update_signing_string {
    my $self = shift;

    $self->_explode_headers();

    confess "I can't update the signing string because I don't have a request" unless $self->has_request;
    confess "I can't update the signing string because I don't have a header_callback" unless $self->has_header_callback;

    my $ss = join "\n", map { $self->header_callback->($self->request, $_) or confess "Couldn't get header value for $_\n" } @{ $self->headers };

    $self->signing_string( $ss );
}

=over

=item format_signature()

This method returns a formatted string ready to insert into an L<HTTP::Request> 
object as the 'Authorization' header.

=back

=cut

sub format_signature {
    my $self = shift;
    
    $self->_explode_headers();

    my $rv = sprintf(q{%s keyId="%s",algorithm="%s"}, 
                $self->authorization_string,
                $self->key_id,
                $self->algorithm
             );

    if ( scalar @{ $self->headers } == 1 and $self->headers->[0] =~ /Date/i ) {
        # if there's only the default header, omit the headers param
    }
    else {
        $rv .= q{,headers="} . join " ", lc @{$self->headers} . q{"};
    }

    if ( $self->has_extentions ) {
        $rv .= q{,ext="} . $self->extentsions . q{"};
    }

    $rv .= q{ } . $self->signature;

    return $rv;

}

=over

=item check_skew()

The method checks if a signature is outside of the defined amount of clock skew. It understands all of the
formats accepted by L<HTTP::Date>.

=back

=cut

sub check_skew {
    my $self = shift;

    if ( $self->skew ) {
        my $request = shift || $self->request;
        confess "No request found" unless $request;

        my $header_time = str2time($self->header_callback->($request, 'date'));
        confess "No Date header was returned (or could be parsed)" unless $header_time;

        my $diff = abs(time - $header_time);
        if ( $diff >= $self->skew ) {
           confess "Request is outside of clock skew tolerance: $diff seconds computed, " . $self->skew . " seconds allowed.\n";
        }
    }

    return 1;

}

=over

=item sign_request()

Uses the C<sign()> method and adds the C<Authorization> header to a request with a properly
formatted signature line.

Takes an optional L<HTTP::Request> object. The default input is the C<request> attribute.

Returns a signed request with an updated 'Date' header.

=back

=cut

sub sign_request {
    my $self = shift;
    my $request = shift || $self->request;

    confess "I don't have a request to sign" unless $request;

    $self->sign($request);

    $request->header( 'Authorization' => $self->format_signature );

    $self->request($request);
}

=over 

=item update_date_header()

Updates the C<Date> header in a request with the current system GMT date and time.

=back

=cut

sub update_date_header {
    my $self = shift;
    my $request = shift || $self->request;

    $request->header->date(time);

    $self->request($request);
}

=over

=item hash_request_content()

Adds a C<Content-MD5> header to the request. Optionally takes a L<HTTP::Request> object; 
it uses C<request> as its default input.

=back

=cut

sub hash_request_content {
    my $self = shift;
    my $request || $self->request;

    return undef unless $request;

    my $digest = md5_base64($request->content);

    # Padding for Base64 interop
    $digest .= '==';

    $request->header( 'Content-MD5' => $digest );

    $self->request( $request );
}

=head1 AUTHOR

Mark Allen, C<< <mrallen1 at yahoo.com> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-crypt-http-signature at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Crypt-HTTP-Signature>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Crypt::HTTP::Signature

You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Crypt-HTTP-Signature>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Crypt-HTTP-Signature>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Crypt-HTTP-Signature>

=item * MetaCPAN

L<https://metacpan.org/dist/Crypt-HTTP-Signature/>

=item * GitHub

L<https://github.com/mrallen1/Crypt-HTTP-Signature/>

=back

=head1 SEE ALSO

L<Crypt::HTTP::Signature::Parse>, 
L<Crypt::HTTP::Signature::Method::HMAC>, 
L<Crypt::HTTP::Signature::Method::RSA>

L<Joyent's HTTP Signature specification|https://github.com/joyent/node-http-signature/blob/master/http_signing.md>

=head1 LICENSE AND COPYRIGHT

Copyright 2012 Mark Allen.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.

=cut

1; # End of Crypt::HTTP::Signature
