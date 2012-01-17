use 5.010;

use Test::More tests => 4;
use Test::Fatal;

my $reqstr = <<_EOT;
POST /foo?param=value&pet=dog HTTP/1.1
Host: example.com
Date: Thu, 05 Jan 2012 21:31:40 GMT
Content-Type: application/json
Content-MD5: Sd/dVLAcvNLSq16eXua5uQ==
Content-Length: 18

{"hello": "world"}
_EOT

my $default = q{Signature keyId="Test",algorithm="rsa-sha256" MDyO5tSvin5FBVdq3gMBTwtVgE8U/JpzSwFvY7gu7Q2tiZ5TvfHzf/RzmRoYwO8PoV1UGaw6IMwWzxDQkcoYOwvG/w4ljQBBoNusO/mYSvKrbqxUmZi8rNtrMcb82MS33bai5IeLnOGl31W1UbL4qE/wL8U9wCPGRJlCFLsTgD8=};
my $all = q{Signature keyId="Test",algorithm="rsa-sha256",headers="request-line host date content-type content-md5 content-length" gVrKP7wVh1+FmWbNlhj0pNXIe9XmeOA6EcnoOKAvUILnwaMFzaKaam9UmeDPwjC9TdT+jSRqjtyZE49kZcSpYAHxGlPQ4ziXFRfPprlN/3Xwg3sUOGqbBiS3WFuY3QOOWv4tzc5p70g74U/QvHNNiYMcjoz89vRJhefbFSNwCDs=};

my $public_str = <<_EOT;
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCFENGw33yGihy92pDjZQhl0C3
6rPJj+CvfSC8+q28hxA161QFNUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6
Z4UMR7EOcpfdUE9Hf3m/hs+FUR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJw
oYi+1hqp1fIekaxsyQIDAQAB
-----END PUBLIC KEY-----
_EOT

use Authen::HTTP::Signature::Parser;
use HTTP::Request;

my $req = HTTP::Request->parse($reqstr);
$req->header(Authorization => $default);

my $exception = exception { Authen::HTTP::Signature::Parser->new($req)->parse() };
like($exception, qr/skew/, "clock skew error");

my $pr = Authen::HTTP::Signature::Parser->new(
    skew => 0,
);

my $p = $pr->parse($req);

isa_ok($p, 'Authen::HTTP::Signature', 'parsed request');

$p->key($public_str);
is($p->verify(), 1, 'default verify successful');

$req->header( Authorization => $all );

$p = $pr->parse($req);
$p->key($public_str);
is($p->verify(), 1, 'all verify successful');

