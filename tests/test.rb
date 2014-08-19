require_relative '../PasswordHash.rb'

module Test

  def self.runTests
    truncatedHashTest()
    testHashFunctionChecking()
  end

  def self.truncatedHashTest
    userString = "awesomeBooks!"
    hash = PasswordStorage.createVerifier( userString )
    badHashLength = hash.length

    loop do
      badHashLength -= 1
      badHash = hash[0...badHashLength]

      raised = false
      begin
        PasswordStorage.validatePassword( userString, badHash )
      rescue InvalidVerifierError
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
    hash = PasswordStorage.createVerifier("foobar")
    hash = hash.sub("sha1:", "sha256:")
    raised = false
    begin
      PasswordStorage.validatePassword("foobar", hash)
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

end

Test.runTests()
