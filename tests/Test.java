public class Test {
    public static void main(String[] args) {
        truncatedHashTest();

    }

    // Make sure truncated hashes don't validate.
    public static void truncatedHashTest() {
        String userString = "password!";
        String goodHash = "";
        String badHash = "";
        int badHashLength = 0;
        boolean badResult = false;

        try {
            goodHash = PasswordHash.createHash(userString);
        }
        catch (Exception e) {
            System.err.println(e.getMessage());
            System.exit(1);
        }
        badHashLength = goodHash.length();
        
        do {
            badHashLength -= 1;
            badHash = goodHash.substring(0, badHashLength);
            
            try {
                badResult = PasswordHash.validatePassword(userString, badHash);
            } catch (Exception e) {
                System.err.println(e.getMessage());
                System.exit(1);
            }

            if (badResult != false) {
                System.err.println("Truncated hash test: FAIL " + 
                    "(At hash length of " +
                    badHashLength + ")"
                    );
                System.exit(1);
            }

        // The loop goes on until it is two characters away from the last : it
        // finds. This is because the PBKDF2 function requires a hash that's at
        // least 2 characters long.
        } while (badHash.charAt(badHashLength - 3) != ':');
        
        if (badResult == false) {
            System.out.println("Truncated hash test: pass");
        }
    }
}
