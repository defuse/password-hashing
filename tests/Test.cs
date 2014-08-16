using System;
using System.Text;
using PasswordSecurity;

class Test
{
    public static void Main()
    {
        truncatedHashTest();
        basicTests();
        testHashFunctionChecking();
    }

    // Make sure truncated hashes don't validate.
    private static void truncatedHashTest()
    {
        string userString = "C# is cray cray!";
        string goodHash = PasswordHash.CreateHash(userString);
        string badHash = "";

        int badHashLength = goodHash.Length;
        bool badResult = false;

        do {
            badHashLength -= 1;
            badHash = goodHash.Substring(0, badHashLength);
            badResult = PasswordHash.ValidatePassword(userString, badHash);

            if (badResult != false) {
                Console.WriteLine("Truncated hash test: FAIL " +
                    "(At hash length of " + badHashLength + ")");
                System.Environment.Exit(1);
            }

        // The loop goes on until it is two characters away from the last : it
        // finds. This is because the PBKDF2 function requires a hash that's at
        // least 2 characters long. This will be changed once exceptions are
        // implemented.
        } while (badHash[badHashLength - 3] != ':');

        if (badResult == false) {
            Console.WriteLine("Truncated hash test: pass");
        }
    }

    private static void basicTests()
    {
        // Print out 10 hashes
        for(int i = 0; i < 10; i++) {
            Console.WriteLine(PasswordHash.CreateHash("p\r\nassw0Rd!"));
        }

        // Test password validation
        bool failure = false;
        Console.WriteLine("Running basic tests...");
        for(int i = 0; i < 10; i++)
        {
            string password = "" + i;
            string hash = PasswordHash.CreateHash(password);
            string secondHash = PasswordHash.CreateHash(password);
            if(hash == secondHash) {
                Console.WriteLine("FAILURE: TWO HASHES ARE EQUAL!");
                failure = true;
            }
            String wrongPassword = ""+(i+1);
            if(PasswordHash.ValidatePassword(wrongPassword, hash)) {
                Console.WriteLine("FAILURE: WRONG PASSWORD ACCEPTED!");
                failure = true;
            }
            if(!PasswordHash.ValidatePassword(password, hash)) {
                Console.WriteLine("FAILURE: GOOD PASSWORD NOT ACCEPTED!");
                failure = true;
            }
        }
        if(failure) {
            Console.WriteLine("TESTS FAILED!");
            System.Environment.Exit(1);
        }
        else {
            Console.WriteLine("TESTS PASSED!");
        }

    }

    private static void testHashFunctionChecking()
    {
        string hash = PasswordHash.CreateHash("foobar");
        hash = hash.Replace("sha1:", "sha256:");
        if (PasswordHash.ValidatePassword("foobar", hash) == false) {
            Console.WriteLine("Algorithm swap: pass");
        } else {
            Console.WriteLine("Algorithm swap: FAIL");
            System.Environment.Exit(1);
        }
    }
}
