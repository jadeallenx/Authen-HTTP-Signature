package Crypt::HTTP::Signature::Parser;

use strict;
use warnings;

use Moo;
use Crypt::HTTP::Signature;
use HTTP::Date qw(str2time);
use Scalar::Util qw(blessed);
use HTTP::Request;
use Carp qw(confess);

=head1 NAME

Crypt::HTTP::Signature::Parser - Parse HTTP signature headers

=head1 VERSION

Version: 0.01

=cut

our $VERSION = '0.01';

=head1 PURPOSE

This class parses HTTP signature headers (if one exists) from a request and returns a new 
L<Crypt::HTTP::Signature> object.

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
    }
    lazy => 1,
);

=over

=item request

Holds the request to be parsed.

=back

=cut

has 'request' => (
    is => 'rw',
);

=over 

=item skew

Defaults to 300 seconds in either direction from your clock. If the Date header data is outside of this range, 
the request is considered invalid.

Set this value to 0 to disable skew checks. (Useful for testing, but far less secure!)

=back

=cut

has 'skew' => (
    is => 'rw',
    isa => sub { die "$_[0] isn't an integer" unless $_[0] =~ /0-9+/ },
    default => { 300 },
);

=head1 METHODS

=over

=item new()

Instantiates a new parser object. Can be called in several ways:

=over

=item * Pass a request

Directly pass in a string or an L<HTTP::Request> object. (That is, use the default header callback.)

  my $c = Crypt::HTTP::Signature::Parser->new($request);

=item * Pass a request and a callback

Pass in a request and a header callback (as described above)

  my $c = Crypt::HTTP::Signature::Parser->new($request, \&my_callback);

=item * Using a hashref

This is the traditional construction call.

  my $c = Crypt::HTTP::Signature::Parser->new(
        request => $request,
        header_callback => \&my_callback,
        skew => 600, # different from the default
  );

=item * No parameters

  my $p = Crypt::HTTP::Signature::Parser->new();
  $p->header_callback( \&my_callback );
  my $c;
  try {
      $c = $p->parse($request);
  }
  catch {
      die "Parse failed: $_";
  };
 
  $c->private_key_callback( sub { 0xbada5511 } );
  $c->validate() or die;

=back

=back

=cut

around BUILDARGS => sub {
    my $orig = shift;
    my $class = shift;

    # Yay argument munging!
    if ( @_ == 1 ) {
        if ( blessed($_[0]) ) {
            unshift @_, "request"
        }
        if ( ref($_[0]) eq "HASH" ) {
            # this is a no-op; let Moo handle it
        }
        if ( ref($_[0]) eq "CODE" ) {
            unshift @_, "header_callback"
        }
        else {
            # Try to coerce a string into an HTTP Request object.
            push @_, HTTP::Request->parse($_[0]);
            $_[0] = "request";
    }
    elsif ( @_ == 2 )
        if ( ref($_[1]) eq "CODE" && blessed ($_[0]) ) {
            unshift @_, "request";
            splice @_, 2, 0, "header_callback";
        }
        elsif ( ref($_[1] eq "CODE" && ! ref($_[0]) {
            splice @_, 0, 1, "request", HTTP::Request->parse($_[0]);
            splice @_, 2, 0, "header_callback";
        }
    }

    $class->orig(@_);
};

=over

=item parse()

This method parses signature header components.  It returns a new L<Crypt::HTTP::Signature>
object on success. This method will C<confess> failures, so wrap it in L<Try::Tiny> if you need a more
graceful failure.

=back

=cut

sub parse {
    my $self = shift;
    my $request = shift || $self->request;

    confess "There was no request to parse!" unless $request;

    my $sig_str = $self->header_callback->($request, 'Authorization');
    confess 'No Authorization header value was returned!' unless $sig_str;

    # Check clock skew
    if ( $self->skew ) {
        my $header_time = str2time($self->header_callback->($request, 'Date'));
        confess "No Date header was returned (or could be parsed)" unless $header_time;
        my $diff = abs(time - $header_time);
        if ( $diff >= $self->skew ) {
           confess "Request is outside of clock skew tolerance: $diff seconds computed, " . $self->skew . " seconds allowed.\n";
        }
    }

    # Should look something like:
    # Authorization: Signature keyId="Test",algorithm="rsa-sha256" MDyO5tSvin5FBVdq3gMBTwtVgE8U/JpzSwFvY7gu7Q2tiZ5TvfHzf/RzmRoYwO8PoV1UGaw6IMwWzxDQkcoYOwvG/w4ljQBBoNusO/mYSvKrbqxUmZi8rNtrMcb82MS33bai5IeLnOGl31W1UbL4qE/wL8U9wCPGRJlCFLsTgD8=

    my ( $sig_text, $params, $b64_str ) = split / /, $sig_str;

    confess "$sig_text does not match required string 'Signature'" unless $sig_text =~ /^Signature$/;

    my ( $key_id, $algo, $hdrs, $ext ) = split /,/ $params;

    $key_id =~ s/^keyId="(.+)"$/$1/;
    $algo =~ s/^algorithm="(.+)"$/$1/;
    $hdrs =~ s/^headers="(.+)"$/$1/;
    $ext =~ s/^ext="(.+)"$/$1/;

    my @headers = split / /, $hdrs;

    push @headers, "Date" unless @headers;

    # die on duplicate headers
    my %h;
    foreach my $hdr ( @headers ) {
        if ( exists $h{$hdr} ) {
            confess "Duplicate header '$hdr' found in signature header parameter. Aborting.";
        }
        $h{$hdr}++;
    }

    # build signing string
    my $ss = join "\n", map { $self->header_callback->($request, $_) } @headers;

    return Crypt::HTTP::Signature->new(
        key_id => $key_id,
        algorithm => $algo,
        headers => \@headers,
        extentions => $ext,
        signature => $b64_str,
        signing_string => $ss,
        request => $request,
    );
}

=head1 SEE ALSO

L<Crypt::HTTP::Signature>

=cut

1;
