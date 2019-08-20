<?php
/*
 * A lot of code form https://github.com/firebase/php-jwt/blob/master/src/JWT.php, thank you.
* */
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
        $header = $this->base64Encode($this->jsonEncode([
            'type' => 'JWT',
            'alg' => $alg,
        ]));
        $payload = $this->base64Encode($this->jsonEncode($payload));
        $signature = $this->sign("$header.$payload", $key, $alg);
        return "$header.$payload." . $this->base64Encode($signature);
    }

    public function jsonDecode($input, $assoc = false)
    {
        if (version_compare(PHP_VERSION, '5.4.0', '>=') && !(defined('JSON_C_VERSION') && PHP_INT_SIZE > 4)) {
            $obj = json_decode($input, $assoc, 512, JSON_BIGINT_AS_STRING);
        } else {
            $max_int_length = strlen((string) PHP_INT_MAX) - 1;
            $json_without_bigints = preg_replace('/:\s*(-?\d{'.$max_int_length.',})/', ': "$1"', $input);
            $obj = json_decode($json_without_bigints, $assoc);
        }
        if (function_exists('json_last_error') && $errno = json_last_error()) {
            $this->handleJsonError($errno);
        } elseif ($obj === null && $input !== 'null') {
            throw new JWTException('Null result with non-null input');
        }
        return $obj;
    }

    public function jsonEncode($input)
    {
        $json = json_encode($input);
        if (function_exists('json_last_error') && $errno = json_last_error()) {
            $this->handleJsonError($errno);
        } elseif ($json === 'null' && $input !== null) {
            throw new JWTException('Null result with non-null input');
        }
        return $json;
    }

    private function handleJsonError($errno)
    {
        $messages = array(
            JSON_ERROR_DEPTH => 'Maximum stack depth exceeded',
            JSON_ERROR_STATE_MISMATCH => 'Invalid or malformed JSON',
            JSON_ERROR_CTRL_CHAR => 'Unexpected control character found',
            JSON_ERROR_SYNTAX => 'Syntax error, malformed JSON',
            JSON_ERROR_UTF8 => 'Malformed UTF-8 characters' //PHP >= 5.3.3
        );
        throw new JWTException(
            isset($messages[$errno])
            ? $messages[$errno]
            : 'Unknown JSON error: ' . $errno
        );
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

    public function verify($jwt, $key, $alg = null)
    {
        $explodes = explode('.', $jwt);
        if (count($explodes) != 3) {
            throw new JWTException('Invalid token');
        }

        list($header64, $payload64, $signature64) = $explodes;
        $header = $this->jsonDecode($this->base64Decode($header64), true);
        if (!isset($header['alg'])) {
            throw new JWTException('Empty algorithm');
        }
        if (is_null($alg)) {
            $alg = $header['alg'];
        }

        $this->determineSupportAlgorithm($alg);

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

    public function decode($jwt, $key, $alg = null)
    {
        if ($this->verify($jwt, $key, $alg)) {
            list(, $payload64, ) = explode('.', $jwt);
            return $this->jsonDecode($this->base64Decode($payload64));
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
