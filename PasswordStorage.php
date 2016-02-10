<?php

class InvalidHashException extends Exception {}
class CannotPerformOperationException extends Exception {}

class PasswordStorage
{
    // These constants may be changed without breaking existing hashes.
    const PBKDF2_HASH_ALGORITHM = "sha1";
    const PBKDF2_ITERATIONS = 64000;
    const PBKDF2_SALT_BYTES = 24;
    const PBKDF2_OUTPUT_BYTES = 18;

    // These constants define the encoding and may not be changed.
    const HASH_SECTIONS = 5;
    const HASH_ALGORITHM_INDEX = 0;
    const HASH_ITERATION_INDEX = 1;
    const HASH_SIZE_INDEX = 2;
    const HASH_SALT_INDEX = 3;
    const HASH_PBKDF2_INDEX = 4;

    /**
     * Hash a password with PBKDF2
     * 
     * @param string $password
     * @return string
     */
    public static function create_hash($password)
    {
        // format: algorithm:iterations:outputSize:salt:pbkdf2output
        if (!\is_string($password)) {
            throw new InvalidArgumentException(
                "create_hash(): Expected a string"
            );
        }
        if (\function_exists('random_bytes')) {
            try {
                $salt_raw = \random_bytes(self::PBKDF2_SALT_BYTES);
            } catch (Error $e) {
                $salt_raw = false;
            } catch (Exception $e) {
                $salt_raw = false;
            } catch (TypeError $e) {
                $salt_raw = false;
            }
        } else {
            $salt_raw = \mcrypt_create_iv(self::PBKDF2_SALT_BYTES, MCRYPT_DEV_URANDOM);
        }
        if ($salt_raw === false) {
            throw new CannotPerformOperationException(
                "Random number generator failed. Not safe to proceed."
            );
        }

        $PBKDF2_Output = self::pbkdf2(
            self::PBKDF2_HASH_ALGORITHM,
            $password,
            $salt_raw,
            self::PBKDF2_ITERATIONS,
            self::PBKDF2_OUTPUT_BYTES,
            true
        );

        return self::PBKDF2_HASH_ALGORITHM .
            ":" .
            self::PBKDF2_ITERATIONS .
            ":" .
            self::PBKDF2_OUTPUT_BYTES .
            ":" .
            \base64_encode($salt_raw) .
            ":" .
            \base64_encode($PBKDF2_Output);
    }
    
    /**
     * Verify that a password matches the stored hash
     *
     * @param string $password
     * @param string $hash
     * @return bool
     */
    public static function verify_password($password, $hash)
    {
        if (!\is_string($password) || !\is_string($hash)) {
            throw new InvalidArgumentException(
                "verify_password(): Expected two strings"
            );
        }
        $params = \explode(":", $hash);
        if (\count($params) !== self::HASH_SECTIONS) {
            throw new InvalidHashException(
                "Fields are missing from the password hash."
            );
        }

        $pbkdf2 = \base64_decode($params[self::HASH_PBKDF2_INDEX], true);
        if ($pbkdf2 === false) {
            throw new InvalidHashException(
                "Base64 decoding of pbkdf2 output failed."
            );
        }

        $salt_raw = \base64_decode($params[self::HASH_SALT_INDEX], true);
        if ($salt_raw === false) {
            throw new InvalidHashException(
                "Base64 decoding of salt failed."
            );
        }

        $storedOutputSize = (int) $params[self::HASH_SIZE_INDEX];
        if (self::ourStrlen($pbkdf2) !== $storedOutputSize) {
            throw new InvalidHashException(
                "PBKDF2 output length doesn't match stored output length."
            );
        }

        $iterations = (int) $params[self::HASH_ITERATION_INDEX];
        if ($iterations < 1) {
            throw new InvalidHashException(
                "Invalid number of iterations. Must be >= 1."
            );
        }
 
        return self::slow_equals(
            $pbkdf2,
            self::pbkdf2(
                $params[self::HASH_ALGORITHM_INDEX],
                $password,
                $salt_raw,
                $iterations,
                self::ourStrlen($pbkdf2),
                true
            )
        );
    }
    
    /**
     * Compares two strings $a and $b in length-constant time.
     * 
     * @param string $a
     * @param string $b
     * @return bool
     */
    public static function slow_equals($a, $b)
    {
        if (!\is_string($a) || !\is_string($b)) {
            throw new InvalidArgumentException(
                "slow_equals(): expected two strings"
            );
        }
        if (\function_exists('hash_equals')) {
            return \hash_equals($a, $b);
        }
        
        // PHP < 5.6 polyfill:
        $diff = self::ourStrlen($a) ^ self::ourStrlen($b);
        for($i = 0; $i < self::ourStrlen($a) && $i < self::ourStrlen($b); $i++) {
            $diff |= \ord($a[$i]) ^ \ord($b[$i]);
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
        // Type checks:
        if (!\is_string($algorithm)) {
            throw new InvalidArgumentException(
                "pbkdf2(): algorithm must be a string"
            );
        }
        if (!\is_string($password)) {
            throw new InvalidArgumentException(
                "pbkdf2(): password must be a string"
            );
        }
        if (!\is_string($salt)) {
            throw new InvalidArgumentException(
                "pbkdf2(): salt must be a string"
            );
        }
        // Coerce strings to integers with no information loss or overflow
        $count += 0;
        $key_length += 0;

        $algorithm = \strtolower($algorithm);
        if (!\in_array($algorithm, \hash_algos(), true)) {
            throw new CannotPerformOperationException(
                "Invalid or unsupported hash algorithm."
            );
        }

        // Whitelist, or we could end up with people using CRC32.
        $ok_algorithms = array(
            "sha1", "sha224", "sha256", "sha384", "sha512",
            "ripemd160", "ripemd256", "ripemd320", "whirlpool"
        );
        if (!\in_array($algorithm, $ok_algorithms, true)) {
            throw new CannotPerformOperationException(
                "Algorithm is not a secure cryptographic hash function."
            );
        }

        if ($count <= 0 || $key_length <= 0) {
            throw new CannotPerformOperationException(
                "Invalid PBKDF2 parameters."
            );
        }
    
        if (\function_exists("hash_pbkdf2")) {
            // The output length is in NIBBLES (4-bits) if $raw_output is false!
            if (!$raw_output) {
                $key_length = $key_length * 2;
            }
            return \hash_pbkdf2($algorithm, $password, $salt, $count, $key_length, $raw_output);
        }
    
        $hash_length = self::ourStrlen(\hash($algorithm, "", true));
        $block_count = \ceil($key_length / $hash_length);
    
        $output = "";
        for($i = 1; $i <= $block_count; $i++) {
            // $i encoded as 4 bytes, big endian.
            $last = $salt . \pack("N", $i);
            // first iteration
            $last = $xorsum = \hash_hmac($algorithm, $last, $password, true);
            // perform the other $count - 1 iterations
            for ($j = 1; $j < $count; $j++) {
                $xorsum ^= ($last = \hash_hmac($algorithm, $last, $password, true));
            }
            $output .= $xorsum;
        }
    
        if($raw_output) {
            return self::ourSubstr($output, 0, $key_length);
        } else {
            return \bin2hex(self::ourSubstr($output, 0, $key_length));
        }
    }

    /*
     * We need these strlen() and substr() functions because when
     * 'mbstring.func_overload' is set in php.ini, the standard strlen() and
     * substr() are replaced by mb_strlen() and mb_substr().
     */

    /**
     * Calculate the length of a string
     * 
     * @param string $str
     * @return int
     */
    private static function ourStrlen($str)
    {
        static $exists = null;
        if ($exists === null) {
            $exists = \function_exists('mb_strlen');
        }
        
        if (!\is_string($str)) {
            throw new InvalidArgumentException(
                "ourStrlen() expects a string"
            );
        }
        
        if ($exists) {
            $length = \mb_strlen($str, '8bit');
            if ($length === false) {
                throw new CannotPerformOperationException();
            }
            return $length;
        } else {
            return \strlen($str);
        }
    }

    /**
     * Substring
     * 
     * @param string $str
     * @param int $start
     * @param int $length
     * @return string
     */
    private static function ourSubstr($str, $start, $length = null)
    {
        static $exists = null;
        if ($exists === null) {
            $exists = \function_exists('mb_substr');
        }
        // Type validation:
        if (!\is_string($str)) {
            throw new InvalidArgumentException(
                "ourSubstr() expects a string"
            );
        }
        
        if ($exists) {
            // mb_substr($str, 0, NULL, '8bit') returns an empty string on PHP
            // 5.3, so we have to find the length ourselves.
            if (!isset($length)) {
                if ($start >= 0) {
                    $length = self::ourStrlen($str) - $start;
                } else {
                    $length = -$start;
                }
            }

            return \mb_substr($str, $start, $length, '8bit');
        }

        // Unlike mb_substr(), substr() doesn't accept NULL for length
        if (isset($length)) {
            return \substr($str, $start, $length);
        } else {
            return \substr($str, $start);
        }
    }
}
