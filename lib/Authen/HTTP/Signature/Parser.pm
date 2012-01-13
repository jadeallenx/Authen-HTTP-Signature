package Authen::HTTP::Signature::Parser;

use strict;
use warnings;

use Moo;
use Authen::HTTP::Signature;
use HTTP::Date qw(str2time);
use Scalar::Util qw(blessed);
use Carp qw(confess);

=head1 NAME

Authen::HTTP::Signature::Parser - Parse HTTP signature headers

=cut

our $VERSION = '0.01';

=head1 PURPOSE

This class parses a HTTP signature 'Authorization' header (if one exists) from a L<HTTP::Request> 
object and populates attributes in a L<Authen::HTTP::Signature> object.

=head1 ATTRIBUTES

=over

=item request

The request to be parsed. 

=back

=cut

has 'request' => (
    is => 'rw',
    isa => sub { confess "'request' must be blessed" unless blessed($_[0]) },
);

around BUILDARGS => sub {
    my $orig = shift;
    my $class = shift;

    if ( @_ == 1 ) {
        unshift @_, "request";
    }

    return $class->$orig(@_);
}

=over

=item get_header

A call back to get a header from C<request>.

=back

=cut

has 'get_header' => (
    is => 'rw',
    isa => sub { die "'get_header' expects a CODE ref\n" unless ref($_[0]) eq "CODE" },
    predicate => 'has_get_header',
    default => sub { 
        my $self = shift;
        my $request = shift;
        my $name = shift;

        $name eq 'request-line' ? 
            sprintf("%s %s %s", 
                $request->method,
                $request->uri->path_query,
                $request->protocol)
            : $request->header($name);
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
    default => sub { 300 },
);

=head1 METHOD

=over

=item parse()

This method parses signature header components.

=back

=cut

sub parse {
    my $self = shift;
    my $request = shift || $self->request;

    confess "There was no request to parse!" unless $request;

    my $sig_str = $self->get_header->($request, 'authorization');
    confess 'No authorization header value was returned!' unless $sig_str;

    $self->_check_skew($request);

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

    my $ss = join "\n", map { 
        $self->get_header->($request, $_) 
            or confess "Couldn't get header value for $_\n" } @headers;

    return Authen::HTTP::Signature->new(
        key_id         => $key_id,
        headers        => \@headers,
        signing_string => $ss,
        algorithm      => $algo,
        extentions     => $ext,
        signature      => $b64_str,
        request        => $request,
    );
}

sub _check_skew {
    my $self = shift;

    if ( $self->skew ) {
        my $request = shift;
        confess "No request found" unless $request;

        my $header_time = str2time($self->get_header->($request, 'date'));
        confess "No Date header was returned (or could be parsed)" unless $header_time;

        my $diff = abs(time - $header_time);
        if ( $diff >= $self->skew ) {
           confess "Request is outside of clock skew tolerance: $diff seconds computed, " . $self->skew . " seconds allowed.\n";
        }
    }

    return 1;

}


=head1 SEE ALSO

L<Authen::HTTP::Signature>

=cut

1;
