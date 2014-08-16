using System;
using System.Text;
using PasswordSecurity;

class Test 
{
    public static void Main() 
    {
        truncatedHashTest();
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
}
