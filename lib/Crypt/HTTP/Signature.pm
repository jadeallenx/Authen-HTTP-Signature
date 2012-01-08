package Crypt::HTTP::Signature;

use 5.010;
use strict;
use warnings;

use Moo;

=head1 NAME

Crypt::HTTP::Signature - Sign and validate HTTP headers

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';

=head1 SYNOPSIS

Create signatures:

    use Crypt::HTTP::Signature;
    use File::Slurp qw(read_file);
    use HTTP::Request::Common;

    my $c = Crypt::HTTP::Signature->new(
        public_key_callback => sub { read_file("/my/pub_key.pem") or die $!; },
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

    my $signature = $c->sign($req); # uses the default 'Date' header

    $req->header( Authorization => $signature );

Validate signatures:

    use 5.010;
    use Crypt::HTTP::Signature;
    use HTTP::Request::Common;
    use File::Slurp;

    my $c = Crypt::HTTP::Signature->new(
        public_key_callback => sub { File::Slurp::read_file("/my/pub_key.pem"); },
        private_key_callback => sub { File::Slurp::read_file("/my/priv_key.pem"); },
    );

    my $req = POST('http://example.com/foo?param=value&pet=dog', 
            Content_Type => 'application/json',
            Content_MD5 => 'Sd/dVLAcvNLSq16eXua5uQ==',
            Content_Length => 18,
            Date => 'Thu, 05 Jan 2012 21:31:40 GMT',
            Authorization => q{Signature keyId="Test",algorithm="rsa-sha256" MDyO5tSvin5FBVdq3gMBTwtVgE8U/JpzSwFvY7gu7Q2tiZ5TvfHzf/RzmRoYwO8PoV1UGaw6IMwWzxDQkcoYOwvG/w4ljQBBoNusO/mYSvKrbqxUmZi8rNtrMcb82MS33bai5IeLnOGl31W1UbL4qE/wL8U9wCPGRJlCFLsTgD8=},
            Content => '{"hello": "world"}'
    );

    my $header = $req->header('Authorization');
    my $signature = $c->parse($header);

    if ( $c->validate($signature) ) {
        say "Request is valid!"
    }
    else {
        say "Request isn't valid";
    };

=head1 PURPOSE

This is an implementation of Joyent's HTTP signature authentication scheme. The idea is to authenticate
connections (hopefully over HTTPS) using either an RSA keypair or a symmetric

=head1 ATTRIBUTES

These are Perlish mutators; give an argument to set a value or no argument to get the current value.


=over

=item * algorithm

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
        my @algos = grep { $_ eq $n } qw(rsa-sha1 rsa-sha256 rsa-sha512 
            hmac-sha1 hmac-sha256 hmac-sha512); 
        return scalar @algos;
    },
    default => sub { 'rsa-sha256' },
);

=over 

=item * skew

Defaults to 300 seconds in either direction from your clock. If the Date header data is outside of this range, 
the request is considered invalid.

=back

=cut

has 'skew' => (
    is => 'rw',
    isa => sub { $_[0] =~ /0-9+/ },
    default => { 300 },
);


=over

=item * headers

The list of headers to be signed (or already signed.) Defaults to the 'Date' header. The order of the headers 
in this list will be used to build the order of the text in the signing string.

This attribute can have some psuedo-values. These are:

=over

=item * C<:request_line>

Use the text of the request (e.g., C</foo?param=value&pet=dog>) as part of the signing string.

=item * C<:all>

Use all headers in a given request including the request itself in the signing string.

=back

=back

=cut

has 'headers' => (
    is => 'rw',
    isa => sub { ref($_[0]) eq ref([]) },
    default => sub { [] },
);

=over

=item * signing_string

The string used to compute the signature digest. It contents are derived from the 
values of the C<headers> array.

=back

=cut

has 'signing_string' => (
    is => 'rw',
    predicate => 'has_signing_string',
);

=over

=item * signature

Contains the digital signature authorization data.

=back

=cut

has 'signature' => (
    is => 'rw',
);

=over

=item * extensions

There are currently no extentions implemented by this library, but the library will append extension
information to the generated header data if this attribute has one or more values.

=back

=cut

has 'extensions' => (
    is => 'rw',
    predicate => 'has_extensions',
);


=over

=item * key_id

A means to identify the key being used to both sender and receiver. This can be any token which makes
sense to the sender and receiver. The exact specification of a token and any necessary key management 
are outside the scope of this library.

=back

=cut

has 'key_id' => (
    is => 'rw',
    predicate => 'has_key_id',
);


=head1 METHODS






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

L<Joyent's HTTP Signature specification|https://github.com/joyent/node-http-signature/blob/master/http_signing.md>

=head1 LICENSE AND COPYRIGHT

Copyright 2012 Mark Allen.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.

=cut

1; # End of Crypt::HTTP::Signature
