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
      puts 'warning: validation failed for a Ruby hash in PHP implementation!!!'
      # FIXME: Why is this a 'warning'?
      # FIXME: If any of the tests fail, exit(1), if success, exit(0)
    end

    # FIXME: Test an incorrect password too!

    puts '----------------------------------------'
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
      puts 'PHP hash validation passed!'
    else
      puts 'PHP hash validation failed!!!'
    end

    # FIXME: Test an incorrect password too!

  end
end

TestRubyAndPhpCompatiblity.testRubyHash()
TestRubyAndPhpCompatiblity.testPHPHash()
