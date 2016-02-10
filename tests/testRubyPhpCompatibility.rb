require_relative '../PasswordStorage.rb'

module TestRubyAndPhpCompatiblity
  def self.testRubyHash()
    userString = "test_password"
    rubyHash = PasswordStorage.createHash( userString )

    result = system(*["php", "./tests/phpVerify.php", userString, rubyHash])
    # System returns true if zero, false if non-zero exit status.
    if result
      puts 'Ruby hash validating in PHP: pass'
    else
      puts 'Ruby hash validating in PHP: FAIL'
      exit(1)
    end

    # Test an incorrect password too
    badPassword = "badpw"
    result = system(*["php", "./tests/phpVerify.php", badPassword, rubyHash])
    if result == false
      puts "Ruby hash validating bad password in PHP: pass"
    else
      puts "Ruby hash validating bad password in PHP: FAIL"
      exit(1)
    end
  end

  def self.testPHPHash()
    testData = `php ./tests/phpHashMaker.php`
    testData = testData.split(' ')

    testPw = testData[1]
    testHash = testData[2]

    if testPw.length != testData[0].to_i
      puts "Unicode test is invalid"
      exit(1)
    end

    if PasswordStorage.verifyPassword(testPw, testHash)
      puts "PHP hash validating in Ruby: pass"
    else
      puts "PHP hash validating in Ruby: FAIL"
      exit(1)
    end

    badPw = "baddd"

    if !PasswordStorage.verifyPassword(badPw, testHash)
      puts "PHP hash validating bad password in Ruby: pass"
    else
      puts "PHP hash validating bad password in Ruby: FAIL"
      exit(1)
    end
  end
end

TestRubyAndPhpCompatiblity.testPHPHash()
TestRubyAndPhpCompatiblity.testRubyHash()
