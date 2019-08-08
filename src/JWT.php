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
        $this->determineSupportAlgorithm($alg);
        list($function, $algorithm) = $this->algs[$alg];
        if ($function == 'hash_hmac') {
            return hash_hmac($algorithm, $data, $key, true);
        }
        if ($function == 'openssl') {
            $signature = '';
            $success = openssl_sign($data, $signature, $key, $algorithm);
            if (!$success) {
                throw new JWTException('Openssl unable to sign data');
            } else {
                return $signature;
            }
        }
    }

    public function verify($jwt, $key, $alg = 'HS256')
    {
        $this->determineSupportAlgorithm($alg);

        list($header, $payload, $signature) = explode('.', $jwt);
        $deHeader = json_decode($this->base64Decode($header), true);
        if (isset($deHeader['alg']) && $deHeader['alg'] != $alg) {
            return false;
        }
        
        list($function, $algorithm) = $this->algs[$alg];
        if ($function == 'hash_hmac') {
            return $signature == $this->base64Encode(hash_hmac($algorithm, "$header.$payload", $key, true));
        }
        if ($function == 'openssl') {
            $success = openssl_verify("$header.$payload", $this->base64Decode($signature), $key, $algorithm);
            // code below from https://github.com/firebase/php-jwt/blob/master/src/JWT.php
            if ($success === 1) {
                return true;
            } elseif ($success === 0) {
                return false;
            }
            // returns 1 on success, 0 on failure, -1 on error.
            throw new JWTException(
                'OpenSSL error: ' . openssl_error_string()
            );
        }
        return false;
    }

    private function determineSupportAlgorithm($alg)
    {
        if (!array_key_exists($alg, $this->algs)) {
            throw new JWTException('Algorithm not supported.');
        }
    }

    private function base64Encode($data)
    {
        return strtr(base64_encode($data), [
            '=' => '',
            '+' => '-',
            '/' => '_',
        ]);
    }

    private function base64Decode($data)
    {
        $data = strtr($data, '-_', '+/');
        $reminder = strlen($data) % 4;
        if ($reminder) {
            $data .= str_repeat('=', 4 - $reminder);
        }
        return base64_decode($data);
    }
}
