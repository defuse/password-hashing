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

class InvalidVerifierError < StandardError
end

class CannotPerformOperationException < StandardError
end

# Password storage with PBKDF2-SHA1.
# Authors: @RedragonX (dicesoft.net), havoc AT defuse.ca 
# www: http://crackstation.net/hashing-security.htm
module PasswordStorage

  # The following constants can be changed without breaking existing verifiers.
  PBKDF2_ITERATIONS = 32000
  PBKDF2_SALT_BYTES = 24
  PBKDF2_OUTPUT_BYTES = 18

  SECTION_DELIMITER = ':'
  VERIFIER_SECTIONS = 5
  VERIFIER_ALGORITHM_INDEX = 0
  VERIFIER_ITERATIONS_INDEX = 1
  VERIFIER_SIZE_INDEX = 2
  VERIFIER_SALT_INDEX = 3
  VERIFIER_PBKDF2_INDEX = 4

  def self.createVerifier( password )
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

  def self.validatePassword( password, verifier )
    params = verifier.split( SECTION_DELIMITER )

    if params.length != VERIFIER_SECTIONS
      raise InvalidVerifierError.new(
        "Fields are missing from the password verifier."
      )
    end

    if params[VERIFIER_ALGORITHM_INDEX] != "sha1"
      raise CannotPerformOperationException.new(
        "Unsupported hash type."
      )
    end

    begin
      pbkdf2 = Base64.strict_decode64( params[VERIFIER_PBKDF2_INDEX] )
    rescue ArgumentError
      raise InvalidVerifierError.new(
        "Base64 decoding of pbkdf2 output failed."
      )
    end

    begin
      salt = Base64.strict_decode64( params[VERIFIER_SALT_INDEX] )
    rescue
      raise InvalidVerifierError.new(
        "Base64 decoding of salt failed."
      )
    end

    if pbkdf2.bytesize() != params[VERIFIER_SIZE_INDEX].to_i
      raise InvalidVerifierError.new(
        "PBKDF2 output length doesn't match stored output length."
      )
    end

    iterations = params[VERIFIER_ITERATIONS_INDEX].to_i
    if iterations < 1
      raise InvalidVerifierError.new(
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
    puts "Sample verifiers:"
    3.times { puts createVerifier("password") }

    puts "\nRunning Ruby self tests..."
    @@allPass = true

    correctPassword = 'aaaaaaaaaa'
    wrongPassword = 'aaaaaaaaab'
    verifier = createVerifier(correctPassword)

    assert( validatePassword( correctPassword, verifier ) == true, "correct password" )
    assert( validatePassword( wrongPassword, verifier ) == false, "wrong password" )

    h1 = verifier.split( SECTION_DELIMITER )
    h2 = createVerifier( correctPassword ).split( SECTION_DELIMITER )
    assert( h1[VERIFIER_PBKDF2_INDEX] != h2[VERIFIER_PBKDF2_INDEX], "different verifier" )
    assert( h1[VERIFIER_SALT_INDEX] != h2[VERIFIER_SALT_INDEX], "different salt" )

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

