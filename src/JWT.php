<?php
namespace Goenitz\JWT;

class JWT {
    private $algs = [
        'HS256' => ['hash_hmac', 'SHA256'],
        'HS384' => ['hash_hmac', 'SHA384'],
        'HS512' => ['hash_hmac', 'SHA512'],
        'RS256' => ['openssl', 'SHA256'],
        'RS384' => ['openssl', 'SHA384'],
        'RS512' => ['openssl', 'SHA512'],
    ];

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

        $explodes = explode('.', $jwt);
        if (count($explodes) != 3) {
            throw new JWTException('Invalid token');
        }

        list($header64, $payload64, $signature64) = $explodes;
        $header = json_decode($this->base64Decode($header64), true);
        if (!isset($header['alg'])) {
            throw new JWTException('Empty algorithm');
        }
        if (!isset($this->algs[$header['alg']])) {
            throw new JWTException('Algorithm not supported');
        }
        if ($header['alg'] != $alg) {
            return false;
        }
        
        list($function, $algorithm) = $this->algs[$alg];
        if ($function == 'hash_hmac') {
            return $signature64 == $this->base64Encode(hash_hmac($algorithm, "$header64.$payload64", $key, true));
        }
        if ($function == 'openssl') {
            $success = openssl_verify("$header64.$payload64", $this->base64Decode($signature64), $key, $algorithm);
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

    public function decode($jwt, $key, $alg = 'HS256')
    {
        if ($this->verify($jwt, $key, $alg)) {
            list(, $payload64, ) = explode('.', $jwt);
            return json_decode($this->base64Decode($payload64));
        }
        throw new JWTException('Invalid token');
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
