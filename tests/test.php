<?php
/* 
 * Password Hashing With PBKDF2 (http://crackstation.net/hashing-security.htm).
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
require_once('PasswordHash.php');
test();

function test()
{
    echo "Running PHP self tests...\n\n";

    $hash = PasswordHash::create_hash("foobar");

    $result = PasswordHash::validate_password("foobar", $hash);
    echo "Validating a good password...\n\n";
    if ($result)
    {
        echo "Validating correct password test passed\n\n";
    }
    else
    {
        echo "Validating correct password test FAILED\n\n";
        exit(1);
    }

    $result = PasswordHash::validate_password("barfoo", $hash);
    echo "Validating a bad password...\n\n";
    if ($result)
    {
        echo "Validating wrong password test FAILED";
        exit(1);
    }
    else
    {
        echo "Validation wrong password test passed";
    }

    echo "\n"; 
    echo $hash . "\n";
}

# FIXME: Make sure all of the test cases in ../../tests/test.php are in here too.

