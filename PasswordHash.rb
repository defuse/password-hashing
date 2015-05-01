# Password Storage With PBKDF2 (http://crackstation.net/hashing-security.htm).
# Copyright (c) 2013, Taylor Hornby
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without 
# modification, are permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice, 
# this list of conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation 
# and/or other materials provided with the distribution.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE 
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
# POSSIBILITY OF SUCH DAMAGE.

require 'securerandom'
require 'openssl'
require 'base64'

class InvalidHashError < StandardError
end

class CannotPerformOperationException < StandardError
end

# Password storage with PBKDF2-SHA1.
# Authors: @RedragonX (dicesoft.net), havoc AT defuse.ca 
# www: http://crackstation.net/hashing-security.htm
module PasswordStorage

  # The following constants can be changed without breaking existing hashes.
  PBKDF2_ITERATIONS = 32000
  PBKDF2_SALT_BYTES = 24
  PBKDF2_OUTPUT_BYTES = 18

  SECTION_DELIMITER = ':'
  HASH_SECTIONS = 5
  HASH_ALGORITHM_INDEX = 0
  HASH_ITERATIONS_INDEX = 1
  HASH_SIZE_INDEX = 2
  HASH_SALT_INDEX = 3
  HASH_PBKDF2_INDEX = 4

  def self.createHash( password )
    begin
      salt = SecureRandom.random_bytes( PBKDF2_SALT_BYTES )
    rescue NotImplementedError
      raise CannotPerformOperationException.new(
        "Random number generator not available."
      )
    end

    pbkdf2 = OpenSSL::PKCS5::pbkdf2_hmac_sha1(
      password,
      salt,
      PBKDF2_ITERATIONS,
      PBKDF2_OUTPUT_BYTES
    )

    parts = [
      "sha1",
      PBKDF2_ITERATIONS,
      pbkdf2.bytesize(),
      Base64.strict_encode64( salt ),
      Base64.strict_encode64( pbkdf2 )
    ]

    return parts.join( SECTION_DELIMITER )
  end

  def self.verifyPassword( password, hash )
    params = hash.split( SECTION_DELIMITER )

    if params.length != HASH_SECTIONS
      raise InvalidHashError.new(
        "Fields are missing from the password hash."
      )
    end

    if params[HASH_ALGORITHM_INDEX] != "sha1"
      raise CannotPerformOperationException.new(
        "Unsupported hash type."
      )
    end

    begin
      pbkdf2 = Base64.strict_decode64( params[HASH_PBKDF2_INDEX] )
    rescue ArgumentError
      raise InvalidHashError.new(
        "Base64 decoding of pbkdf2 output failed."
      )
    end

    begin
      salt = Base64.strict_decode64( params[HASH_SALT_INDEX] )
    rescue
      raise InvalidHashError.new(
        "Base64 decoding of salt failed."
      )
    end

    if pbkdf2.bytesize() != params[HASH_SIZE_INDEX].to_i
      raise InvalidHashError.new(
        "PBKDF2 output length doesn't match stored output length."
      )
    end

    iterations = params[HASH_ITERATIONS_INDEX].to_i
    if iterations < 1
      raise InvalidHashError.new(
        "Invalid number of iterations. Must be >= 1."
      )
    end

    testOutput = OpenSSL::PKCS5::pbkdf2_hmac_sha1(
      password,
      salt,
      iterations,
      pbkdf2.length
    )

    return slow_equals(pbkdf2, testOutput)
  end

  def self.slow_equals(a, b)
    cmp = b.bytes.to_a
    result = 0
    a.bytes.each_with_index {|c,i|
      result |= c ^ cmp[i]
    }
    result == 0
  end

  def self.runSelfTests
    puts "Sample hashes:"
    3.times { puts createHash("password") }

    puts "\nRunning Ruby self tests..."
    @@allPass = true

    correctPassword = 'aaaaaaaaaa'
    wrongPassword = 'aaaaaaaaab'
    hash = createHash(correctPassword)

    assert( verifyPassword( correctPassword, hash ) == true, "correct password" )
    assert( verifyPassword( wrongPassword, hash ) == false, "wrong password" )

    h1 = hash.split( SECTION_DELIMITER )
    h2 = createHash( correctPassword ).split( SECTION_DELIMITER )
    assert( h1[HASH_PBKDF2_INDEX] != h2[HASH_PBKDF2_INDEX], "different hash" )
    assert( h1[HASH_SALT_INDEX] != h2[HASH_SALT_INDEX], "different salt" )

    if @@allPass
      puts "*** ALL TESTS PASS ***"
    else
      puts "*** FAILURES ***"
    end

    return @@allPass
  end

  def self.assert( truth, msg )
    if truth
      puts "PASS [#{msg}]"
    else
      puts "FAIL [#{msg}]"
      @@allPass = false
    end
  end

end

if __FILE__ == $0
  PasswordStorage.runSelfTests
end

