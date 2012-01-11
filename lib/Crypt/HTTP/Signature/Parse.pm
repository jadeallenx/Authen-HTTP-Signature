package Crypt::HTTP::Signature::Parse;

use strict;
use warnings;

use Moo::Role;
use HTTP::Date qw(str2time);
use Carp qw(confess);

=head1 NAME

Crypt::HTTP::Signature::Parse - Parse HTTP signature headers

=cut

our $VERSION = '0.01';

=head1 PURPOSE

This role parses a HTTP signature 'Authorization' header (if one exists) from a L<HTTP::Request> 
object and populates attributes in a L<Crypt::HTTP::Signature> object.

=head1 METHOD

=over

=item parse()

This method parses signature header components.

=back

=cut

sub parse {
    my $self = shift;
    my $request = shift; 

    if ( $request && not $self->has_request) {
        $self->request($request);
    }
    elsif ( not $request && $self->has_request ) {
        $request = $self->request;
    }
    else {
        confess "There was no request to parse!" unless $request;
    }

    my $sig_str = $self->header_callback->($request, 'authorization');
    confess 'No Authorization header value was returned!' unless $sig_str;

    $self->check_skew();

    # Should look something like:
    # Authorization: Signature keyId="Test",algorithm="rsa-sha256" MDyO5tSvin5FBVdq3gMBTwtVgE8U/JpzSwFvY7gu7Q2tiZ5TvfHzf/RzmRoYwO8PoV1UGaw6IMwWzxDQkcoYOwvG/w4ljQBBoNusO/mYSvKrbqxUmZi8rNtrMcb82MS33bai5IeLnOGl31W1UbL4qE/wL8U9wCPGRJlCFLsTgD8=

    my ( $sig_text, $params, $b64_str ) = split / /, $sig_str;

    confess "$sig_text does not match required string 'Signature'" unless $sig_text =~ /^Signature$/;

    my ( $key_id, $algo, $hdrs, $ext ) = split /,/, $params;

    $key_id =~ s/^keyId="(.+)"$/$1/;
    $algo =~ s/^algorithm="(.+)"$/$1/;
    $hdrs =~ s/^headers="(.+)"$/$1/;
    $ext =~ s/^ext="(.+)"$/$1/;

    my @headers = split / /, $hdrs;

    push @headers, "date" unless @headers;

    # die on duplicate headers
    my %h;
    foreach my $hdr ( @headers ) {
        if ( exists $h{$hdr} ) {
            confess "Duplicate header '$hdr' found in signature header parameter. Aborting.";
        }
        $h{$hdr}++;
    }

    $self->key_id($key_id);
    $self->algorithm($algo);
    $self->headers(\@headers);
    $self->extentions($ext);
    $self->signature($b64_str);

    return $self;
}

=head1 SEE ALSO

L<Crypt::HTTP::Signature>

=cut

1;
