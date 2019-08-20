<?php
use PHPUnit\Framework\TestCase;

final class JWTTest extends TestCase
{
    private $jwt;

    public function __construct()
    {
        parent::__construct();
        $this->jwt = new Goenitz\JWT\JWT;
    }

    public function testEncodeDecode()
    {
        $token = $this->jwt->encode('abc', 'key');
        $this->assertEquals('abc', $this->jwt->decode($token, 'key'));
    }

    public function testDecodeFromPython()
    {
        $msg = 'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.Iio6aHR0cDovL2FwcGxpY2F0aW9uL2NsaWNreT9ibGFoPTEuMjMmZi5vbz00NTYgQUMwMDAgMTIzIg.E_U8X2YpMT5K1cEiT_3-IvBYfrdIFIeVYeOqre_Z5Cg';
        $this->assertEquals(
            $this->jwt->decode($msg, 'my_key'),
            '*:http://application/clicky?blah=1.23&f.oo=456 AC000 123'
        );
    }

    public function testUrlSafeCharacters()
    {
        $encoded = $this->jwt->encode('f?', 'a');
        $this->assertEquals('f?', $this->jwt->decode($encoded, 'a'));
    }

    public function testMalformedUtf8StringsFail()
    {
        $this->expectException('Goenitz\JWT\JWTException');
        $this->jwt->encode(pack('c', 128), 'a');
    }

    public function testMalformedJsonThrowsException()
    {
        $this->expectException('Goenitz\JWT\JWTException');
        $this->jwt->jsonDecode('this is not valid JSON string');
    }

    public function testNullKeyFails()
    {
        $payload = ["message" => "abc"];
        $encoded = $this->jwt->encode($payload, 'my_key');
        $this->expectException('Goenitz\JWT\JWTException');
        $decoded = $this->jwt->decode($encoded, null);
    }
}
