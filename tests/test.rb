require_relative '../PasswordStorage.rb'

module Test

  def self.runTests
    truncatedHashTest()
    testHashFunctionChecking()
    testMoreThings()
  end

  def self.truncatedHashTest
    userString = "test_password"
    hash = PasswordStorage.createHash( userString )
    badHashLength = hash.length

    loop do
      badHashLength -= 1
      badHash = hash[0...badHashLength]

      raised = false
      begin
        PasswordStorage.verifyPassword( userString, badHash )
      rescue InvalidHashError
        raised = true
      end

      if !raised
        puts "Truncated hash test: FAIL (At hash length of #{badHashLength})"
        exit(1)
      end
     break if badHash[ badHashLength - 3, 1] == ':'
    end

    puts "Truncated hash test: pass"
  end

  def self.testHashFunctionChecking
    hash = PasswordStorage.createHash("foobar")
    hash = hash.sub("sha1:", "sha256:")
    raised = false
    begin
      PasswordStorage.verifyPassword("foobar", hash)
    rescue CannotPerformOperationException
      raised = true
    end

    if raised
      puts "Algorithm swap: pass"
    else
      puts "Algorithm swap: FAIL"
      exit(1)
    end
  end

  def self.testMoreThings
    correctPassword = 'aaaaaaaaaa'
    wrongPassword = 'aaaaaaaaab'
    hash = PasswordStorage.createHash(correctPassword)

    assert( PasswordStorage.verifyPassword( correctPassword, hash ) == true, "correct password" )
    assert( PasswordStorage.verifyPassword( wrongPassword, hash ) == false, "wrong password" )

    h1 = hash.split( PasswordStorage::SECTION_DELIMITER )
    h2 = PasswordStorage.createHash( correctPassword ).split( PasswordStorage::SECTION_DELIMITER )
    assert( h1[PasswordStorage::HASH_PBKDF2_INDEX] != h2[PasswordStorage::HASH_PBKDF2_INDEX], "different hash" )
    assert( h1[PasswordStorage::HASH_SALT_INDEX] != h2[PasswordStorage::HASH_SALT_INDEX], "different salt" )

    puts "More things: pass"
  rescue RuntimeError => e
    puts "More things: fail"
    raise e
  end

  def self.assert( truth, msg )
    if truth
      # do nothing
    else
      raise RuntimeError.new("FAILURE: [#{msg}]")
    end
  end

end

Test.runTests()
