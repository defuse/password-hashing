var
    PasswordStorage = require('../PasswordHash').instance,
    $all_tests_pass = true
    ;

// Test vector raw output.
PasswordStorage.pbkdf2('sha1', 'password', 'salt', 2, 20, function(err, $a){
    var $b;

    $b = "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957";
    if ($a.toString('hex') === $b) {
        console.log("Test vector 1: pass\n");
    } else {
        console.log("Test vector 1: FAIL\n");
        $all_tests_pass = false;
    }

    // Test vector hex output.
    PasswordStorage.pbkdf2("sha1", "password", "salt", 2, 20, function(err , $a){

        $b = "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957";
        if ($a === $b) {
            console.log("Test vector 2: pass\n");
        } else {
            console.log("Test vector 2: FAIL\n");
            $all_tests_pass = false;
        }

        $hash = PasswordStorage.createVerifier("correct_password", function(err, $hash) {
            // Right password returns true.
            PasswordStorage.validatePassword("correct_password", $hash, function(err, $result){
                if ($result === true)
                {
                    console.log("Correct password: pass\n");
                }
                else
                {
                    console.log("Correct password: FAIL\n");
                    $all_tests_pass = false;
                }

                // Wrong password returns false.
                PasswordStorage.validatePassword("wrong_password", $hash, function(err, $result){
                    if ($result === false)
                    {
                        console.log("Wrong password: pass\n");
                    }
                    else
                    {
                        console.log("Wrong password: FAIL\n");
                        $all_tests_pass = false;
                    }

                    // Bad verifier raises InvalidVerifierException
                    PasswordStorage.validatePassword("password", "", function($raised) {
                        if ($raised) {
                            console.log("Bad hash: pass\n");
                        } else {
                            console.log("Bad hash: FAIL\n");
                            $all_tests_pass = false;
                        }

                        // Make sure truncated hashes don't validate.
                        var $badHashLength = $hash.length;
                        var $truncateTest = true;

                        function keepGoing(finish){

                            $badHashLength -= 1;
                            $badHash = $hash.slice(0, $badHashLength);
                            $raised = false;

                            PasswordStorage.validatePassword("correct_password", $badHash, function(err){
                                if (!err) {
                                    console.log("Truncated hash test: FAIL " +
                                        "(At hash length of " + $badHashLength + ") \n");
                                    $truncateTest = false;
                                    $all_tests_pass = false;
                                    return finish();
                                }
                                // The loop goes on until it is two characters away from the last : it
                                // finds. This is because the PBKDF2 function requires a hash that's at
                                // least 2 characters long. This will be changed once exceptions are
                                // implemented.
                                //
                                if ($badHash[$badHashLength - 3] === ':') {
                                    return finish();
                                }

                                keepGoing(finish);
                            });

                        }

                        keepGoing(function(){

                            if ($truncateTest) {
                                console.log("Truncated hash test: pass\n");
                            }

                            // Make sure changing the algorithm breaks the hash.
                            PasswordStorage.createVerifier("foobar", function(err, $hash){
                                $hash = $hash.replace("sha1:", "sha256:");
                                PasswordStorage.validatePassword("foobar", $hash, function(err, result){
                                   if (result === false) {
                                        console.log("Algorithm swap: pass\n");
                                    } else {
                                        console.log("Algorithm swap: FAIL\n");
                                        $all_tests_pass = false;
                                    }

                                    if (!$all_tests_pass) {
                                        process.exit(1);
                                    }
                                });

                            });

                        });

                    });

                });

            });

        });

    });
}, true);

