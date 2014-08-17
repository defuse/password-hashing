require_relative '../PasswordHash.rb'

module TestRubyAndPhpCompatiblity
  def self.testRubyHash()
    userString = "RedragonX!"
    rubyHash = PasswordHash.createHash( userString )

    result = system(*["php", "tests/phpValidate.php", userString, rubyHash])
    # System returns true if zero, false if non-zero exit status.
    if result
      puts 'Ruby hash validating in PHP: pass'
    else
      puts 'Ruby hash validating in PHP: FAIL'
      exit(1)
    end

    # Test an incorrect password too
    badPassword = "badpw"
    result = system(*["php", "tests/phpValidate.php", badPassword, rubyHash])
    if result == false
      puts "Ruby hash validating bad password in PHP: pass"
    else
      puts "Ruby hash validating bad password in PHP: FAIL"
      exit(1)
    end
  end

  def self.testPHPHash()
    testData = `php tests/phpHashMaker.php`
    testData = testData.split(' ')

    testPw = testData[0]
    testHash = testData[1]

    if PasswordHash.validatePassword(testPw, testHash)
      puts "PHP hash validating in Ruby: pass"
    else
      puts "PHP hash validating in Ruby: FAIL"
      exit(1)
    end

    badPw = "baddd"

    if !PasswordHash.validatePassword(badPw, testHash)
      puts "PHP hash validating bad password in Ruby: pass"
    else
      puts "PHP hash validating bad password in Ruby: FAIL"
      exit(1)
    end
  end
end

TestRubyAndPhpCompatiblity.testPHPHash()
TestRubyAndPhpCompatiblity.testRubyHash()
