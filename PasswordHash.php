<?php
/* 
 * Password Storage With PBKDF2 (http://crackstation.net/hashing-security.htm).
 * Copyright (c) 2013, Taylor Hornby
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, 
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation 
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE 
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
 * POSSIBILITY OF SUCH DAMAGE.
 */

// These constants may be changed without breaking existing verifiers.
define("PBKDF2_HASH_ALGORITHM", "sha1");
define("PBKDF2_ITERATIONS", 32000);
define("PBKDF2_SALT_BYTES", 24);
define("PBKDF2_OUTPUT_BYTES", 18);

define("VERIFIER_SECTIONS", 5);
define("VERIFIER_ALGORITHM_INDEX", 0);
define("VERIFIER_ITERATION_INDEX", 1);
define("VERIFIER_SIZE_INDEX", 2);
define("VERIFIER_SALT_INDEX", 3);
define("VERIFIER_PBKDF2_INDEX", 4);

class InvalidVerifierException extends Exception {}
class CannotPerformOperationException extends Exception {}

class PasswordStorage {

    public static function create_verifier($password)
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
    
    public static function validate_password($password, $verifier)
    {
        $params = explode(":", $verifier);
        if(count($params) != VERIFIER_SECTIONS) {
            throw new InvalidVerifierException(
                "Fields are missing from the password verifier."
            );
        }

        $pbkdf2 = base64_decode($params[VERIFIER_PBKDF2_INDEX], true);
        if ($pbkdf2 === false) {
            throw new InvalidVerifierException(
                "Base64 decoding of pbkdf2 output failed."
            );
        }

        $salt_raw = base64_decode($params[VERIFIER_SALT_INDEX], true);
        if ($salt_raw === false) {
            throw new InvalidVerifierException(
                "Base64 decoding of salt failed."
            );
        }

        $storedOutputSize = (int)$params[VERIFIER_SIZE_INDEX];
        if (strlen($pbkdf2) !== $storedOutputSize) {
            throw new InvalidVerifierException(
                "PBKDF2 output length doesn't match stored output length."
            );
        }

        $iterations = (int)$params[VERIFIER_ITERATION_INDEX];
        if ($iterations < 1) {
            throw new InvalidVerifierException(
                "Invalid number of iterations. Must be >= 1."
            );
        }
 
        return self::slow_equals(
            $pbkdf2,
            self::pbkdf2(
                $params[VERIFIER_ALGORITHM_INDEX],
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

