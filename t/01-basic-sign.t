use 5.010;

use Test::More tests => 3;

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

my $private_str = <<_EOT;
-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDCFENGw33yGihy92pDjZQhl0C36rPJj+CvfSC8+q28hxA161QF
NUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6Z4UMR7EOcpfdUE9Hf3m/hs+F
UR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJwoYi+1hqp1fIekaxsyQIDAQAB
AoGBAJR8ZkCUvx5kzv+utdl7T5MnordT1TvoXXJGXK7ZZ+UuvMNUCdN2QPc4sBiA
QWvLw1cSKt5DsKZ8UETpYPy8pPYnnDEz2dDYiaew9+xEpubyeW2oH4Zx71wqBtOK
kqwrXa/pzdpiucRRjk6vE6YY7EBBs/g7uanVpGibOVAEsqH1AkEA7DkjVH28WDUg
f1nqvfn2Kj6CT7nIcE3jGJsZZ7zlZmBmHFDONMLUrXR/Zm3pR5m0tCmBqa5RK95u
412jt1dPIwJBANJT3v8pnkth48bQo/fKel6uEYyboRtA5/uHuHkZ6FQF7OUkGogc
mSJluOdc5t6hI1VsLn0QZEjQZMEOWr+wKSMCQQCC4kXJEsHAve77oP6HtG/IiEn7
kpyUXRNvFsDE0czpJJBvL/aRFUJxuRK91jhjC68sA7NsKMGg5OXb5I5Jj36xAkEA
gIT7aFOYBFwGgQAQkWNKLvySgKbAZRTeLBacpHMuQdl1DfdntvAyqpAZ0lY0RKmW
G6aFKaqQfOXKCyWoUiVknQJAXrlgySFci/2ueKlIE1QqIiLSZ8V8OlpFLRnb1pzI
7U1yQXnTAEFYM560yJlzUpOb1V4cScGd365tiSMvxLOvTA==
-----END RSA PRIVATE KEY-----
_EOT

use Authen::HTTP::Signature;
use HTTP::Request;

my $req = HTTP::Request->parse($reqstr);

my $default_auth = Authen::HTTP::Signature->new(
    key => $private_str,
    request => $req,
    key_id => 'Test',
);

isa_ok($default_auth, 'Authen::HTTP::Signature', 'constructed object');
my $signed_req = $default_auth->sign();
is($signed_req->header('Authorization'), $default, 'default auth header matches');

my $all_auth = Authen::HTTP::Signature->new(
    key => $private_str,
    request => $req,
    key_id => 'Test',
    headers => [qw(request-line host date content-type content-md5 content-length)],
);

my $sign2 = $all_auth->sign();
is($sign2->header('Authorization'), $all, 'all header matches');
