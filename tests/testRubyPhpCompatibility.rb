require_relative '../PasswordHash.rb'

module TestRubyAndPhpCompatiblity
  def self.testRubyHash()
    puts 'Creating a hash using the Ruby implementation...'

    userString = "RedragonX!"
    rubyHash = PasswordHash.createHash( userString )
    puts rubyHash

    puts ''
    puts 'Now validating this hash using a PHP implementation'
    result = system *%W(php tests/phpValidate.php #{userString} #{rubyHash})
    if !result
      puts 'ERROR: validation failed for a Ruby hash in PHP implementation!!!'
      exit(1)
    else
      puts 'SUCCESS: Hash validation passed '
    end

    # Test an incorrect password too
    badPassword = "badpw"
    puts 'Now testing a bad password using a PHP implementation'
    result = system *%W(php tests/phpValidate.php #{badPassword} #{rubyHash})
    if !result
      puts 'SUCCESS: The PHP implementation did not accept a bad password.'
    else
      puts 'ERROR: bad password test failed for a Ruby hash in PHP implementation!!!'
      exit(1)
    end

    puts ''
    puts '----------------------------------------'
    puts ''
  end

  def self.testPHPHash()

    puts 'Now testing a random PHP hash with a Ruby implementation...'
    puts ''

    testData = `php tests/phpHashMaker.php`
    testData = testData.split(' ')

    testPw = testData[0]
    testHash = testData[1]

    puts "Using #{testPw} as the password and using #{testHash} as the PHP hash "
    puts ''

    if PasswordHash.validatePassword(testPw, testHash)
      puts 'SUCCESS: PHP hash validation passed!'
    else
      puts 'ERROR: PHP hash validation failed!!!'
      exit(1)
    end

    puts ''
    puts 'Now testing a bad password with a Ruby implementation...'
    puts ''

    badPw = "baddd"

    if !PasswordHash.validatePassword(badPw, testHash)
      puts 'SUCCESS: The Ruby implementation did not accept a bad password.'
    else
      puts 'ERROR: bad password test failed for a Ruby hash in PHP implementation!!!'
      exit(1)
    end
  end
end

TestRubyAndPhpCompatiblity.testRubyHash()
TestRubyAndPhpCompatiblity.testPHPHash()
