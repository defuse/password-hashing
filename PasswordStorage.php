<?php

// These constants may be changed without breaking existing hashes.
define("PBKDF2_HASH_ALGORITHM", "sha1");
define("PBKDF2_ITERATIONS", 64000);
define("PBKDF2_SALT_BYTES", 24);
define("PBKDF2_OUTPUT_BYTES", 18);

// These constants define the encoding and may not be changed.
define("HASH_SECTIONS", 5);
define("HASH_ALGORITHM_INDEX", 0);
define("HASH_ITERATION_INDEX", 1);
define("HASH_SIZE_INDEX", 2);
define("HASH_SALT_INDEX", 3);
define("HASH_PBKDF2_INDEX", 4);

class InvalidHashException extends Exception {}
class CannotPerformOperationException extends Exception {}

class PasswordStorage {

    public static function create_hash($password)
    {
        // format: algorithm:iterations:outputSize:salt:pbkdf2output
        $salt_raw = mcrypt_create_iv(PBKDF2_SALT_BYTES, MCRYPT_DEV_URANDOM);
        if ($salt_raw === false) {
            throw new CannotPerformOperationException(
                "Random number generator failed. Not safe to proceed."
            );
        }

        $PBKDF2_Output = self::pbkdf2(
            PBKDF2_HASH_ALGORITHM,
            $password,
            $salt_raw,
            PBKDF2_ITERATIONS,
            PBKDF2_OUTPUT_BYTES,
            true
        );

        return PBKDF2_HASH_ALGORITHM . 
            ":" .
            PBKDF2_ITERATIONS . 
            ":" .
            PBKDF2_OUTPUT_BYTES . 
            ":" .
            base64_encode($salt_raw) . 
            ":" .
            base64_encode($PBKDF2_Output);
    }
    
    public static function verify_password($password, $hash)
    {
        $params = explode(":", $hash);
        if(count($params) != HASH_SECTIONS) {
            throw new InvalidHashException(
                "Fields are missing from the password hash."
            );
        }

        $pbkdf2 = base64_decode($params[HASH_PBKDF2_INDEX], true);
        if ($pbkdf2 === false) {
            throw new InvalidHashException(
                "Base64 decoding of pbkdf2 output failed."
            );
        }

        $salt_raw = base64_decode($params[HASH_SALT_INDEX], true);
        if ($salt_raw === false) {
            throw new InvalidHashException(
                "Base64 decoding of salt failed."
            );
        }

        $storedOutputSize = (int)$params[HASH_SIZE_INDEX];
        if (strlen($pbkdf2) !== $storedOutputSize) {
            throw new InvalidHashException(
                "PBKDF2 output length doesn't match stored output length."
            );
        }

        $iterations = (int)$params[HASH_ITERATION_INDEX];
        if ($iterations < 1) {
            throw new InvalidHashException(
                "Invalid number of iterations. Must be >= 1."
            );
        }
 
        return self::slow_equals(
            $pbkdf2,
            self::pbkdf2(
                $params[HASH_ALGORITHM_INDEX],
                $password,
                $salt_raw,
                $iterations,
                strlen($pbkdf2),
                true
            )
        );
    }
    
    // Compares two strings $a and $b in length-constant time.
    public static function slow_equals($a, $b)
    {
        $diff = strlen($a) ^ strlen($b);
        for($i = 0; $i < strlen($a) && $i < strlen($b); $i++)
        {
            $diff |= ord($a[$i]) ^ ord($b[$i]);
        }
        return $diff === 0;
    }
    
    /*
     * PBKDF2 key derivation function as defined by RSA's PKCS #5: https://www.ietf.org/rfc/rfc2898.txt
     * $algorithm - The hash algorithm to use. Recommended: SHA256
     * $password - The password.
     * $salt - A salt that is unique to the password.
     * $count - Iteration count. Higher is better, but slower. Recommended: At least 1000.
     * $key_length - The length of the derived key in bytes.
     * $raw_output - If true, the key is returned in raw binary format. Hex encoded otherwise.
     * Returns: A $key_length-byte key derived from the password and salt.
     *
     * Test vectors can be found here: https://www.ietf.org/rfc/rfc6070.txt
     *
     * This implementation of PBKDF2 was originally created by https://defuse.ca
     * With improvements by http://www.variations-of-shadow.com
     */
    public static function pbkdf2($algorithm, $password, $salt, $count, $key_length, $raw_output = false)
    {
        $algorithm = strtolower($algorithm);
        if(!in_array($algorithm, hash_algos(), true)) {
            throw new CannotPerformOperationException(
                "Invalid or unsupported hash algorithm."
            );
        }

        // Whitelist, or we could end up with people using CRC32.
        $ok_algorithms = array(
            "sha1", "sha224", "sha256", "sha384", "sha512",
            "ripemd160", "ripemd256", "ripemd320", "whirlpool"
        );
        if (!in_array($algorithm, $ok_algorithms, true)) {
            throw new CannotPerformOperationException(
                "Algorithm is not a secure cryptographic hash function."
            );
        }

        if($count <= 0 || $key_length <= 0) {
            throw new CannotPerformOperationException(
                "Invalid PBKDF2 parameters."
            );
        }
    
        if (function_exists("hash_pbkdf2")) {
            // The output length is in NIBBLES (4-bits) if $raw_output is false!
            if (!$raw_output) {
                $key_length = $key_length * 2;
            }
            return hash_pbkdf2($algorithm, $password, $salt, $count, $key_length, $raw_output);
        }
    
        $hash_length = strlen(hash($algorithm, "", true));
        $block_count = ceil($key_length / $hash_length);
    
        $output = "";
        for($i = 1; $i <= $block_count; $i++) {
            // $i encoded as 4 bytes, big endian.
            $last = $salt . pack("N", $i);
            // first iteration
            $last = $xorsum = hash_hmac($algorithm, $last, $password, true);
            // perform the other $count - 1 iterations
            for ($j = 1; $j < $count; $j++) {
                $xorsum ^= ($last = hash_hmac($algorithm, $last, $password, true));
            }
            $output .= $xorsum;
        }
    
        if($raw_output) {
            return substr($output, 0, $key_length);
        } else {
            return bin2hex(substr($output, 0, $key_length));
        }
    }

}

