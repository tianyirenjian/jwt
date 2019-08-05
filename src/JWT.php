<?php
namespace Goenitz\JWT;

class JWT {
    private $jti = false;

    private $algs = [
        'HS256' => ['hash_hmac', 'SHA256'],
        'HS384' => ['hash_hmac', 'SHA384'],
        'HS512' => ['hash_hmac', 'SHA512'],
        'RS256' => ['openssl', 'SHA256'],
        'RS384' => ['openssl', 'SHA384'],
        'RS512' => ['openssl', 'SHA512'],
    ];

    /**
     * @param $jti = false
     */
    public function __construct($jti = false)
    {
        $this->jti = false;
    }

    public function encode($payload, $key, $alg = 'HS256')
    {
        $header = $this->base64Encode(json_encode([
            'type' => 'JWT',
            'alg' => $alg,
        ]));
        $payload = $this->base64Encode(json_encode($payload));
        $signature = $this->sign("$header.$payload", $key, $alg);
        return "$header.$payload." . $this->base64Encode($signature);
    }

    private function sign($data, $key, $alg = 'HS256')
    {
        if (!array_key_exists($alg, $this->algs)) {
            // TODO throw exception
        }
        list($function, $algorithm) = $this->algs[$alg];
        if ($function == 'hash_hmac') {
            return hash_hmac($algorithm, $data, $key, true);
        }
        if ($function == 'openssl') {
            $signature = '';
            $success = openssl_sign($data, $signature, $key, $algorithm);
            if (!$success) {
                // TODO throw exception
            } else {
                return $signature;
            }
        }
        // TODO throw exception
    }

    private function base64Encode($data)
    {
        $data = base64_encode($data);
        return strtr($data, [
            '=' => '',
            '+' => '-',
            '/' => '_',
        ]);
    }
}
