
# Authors: Stephen Chavez (dicesoft.net), Taylor Hornby (defuse.ca).

require 'securerandom'
require 'openssl'
require 'base64'

class InvalidHashError < StandardError
end

class CannotPerformOperationException < StandardError
end

module PasswordStorage

  # The following constants can be changed without breaking existing hashes.
  PBKDF2_ITERATIONS = 64000
  PBKDF2_SALT_BYTES = 24
  PBKDF2_OUTPUT_BYTES = 18

  # These constants define the encoding and may not be changed.
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

    pbkdf2 = pbkdf2_hmac_sha1(
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

    testOutput = pbkdf2_hmac_sha1(
      password,
      salt,
      iterations,
      pbkdf2.bytesize()
    )

    return slow_equals(pbkdf2, testOutput)
  end

  def self.pbkdf2_hmac_sha1(password, salt, iterations, byte_length)
    begin
      return OpenSSL::PKCS5::pbkdf2_hmac_sha1(
        password,
        salt,
        iterations,
        byte_length
      )
    rescue OpenSSL::PKCS5::PKCS5Error
      # According to the Ruby source code, if OpenSSL's calculation of PBKDF2
      # fails, then it throws "ePKCS5" which I'm *guessing* is this (it's not
      # documented explicitly).
      raise CannotPerformOperationException.new(
        "OpenSSL failed to compute PBKDF2."
      )
    end
  end

  def self.slow_equals(a, b)
    if a.bytesize() != b.bytesize()
      return false
    else
      result = 0
      b_bytes = b.bytes.to_a
      a.bytes.each_with_index {|a_byte,i|
        result |= a_byte ^ b_bytes[i]
      }
      return result == 0
    end
  end

end
