import java.io.*;

class PasswordHashPair {
    public String password;
    public String hash;
}

public class JavaAndPHPCompatibility {

    public static void main(String[] args)
    {
        javaGoodHashTest();
        javaBadHashTest();
        testGoodPHPHash();
        testBadPHPHash();
    }

    private static void javaGoodHashTest()
    {
        String password = "test_password";
        String javaHash = "";

        try {
            javaHash = PasswordStorage.createHash(password);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            System.exit(1);
        }

        if (phpVerify(password, javaHash)) {
            System.out.println("Java hash validating in PHP: pass");
        } else {
            System.out.println("Java hash validating in PHP: FAIL");
            System.exit(1);
        }
    }

    private static void javaBadHashTest()
    {
        String password = "test_password!";
        String javaHash = "";

        try {
            javaHash = PasswordStorage.createHash(password);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            System.exit(1);
        }

        if (phpVerify("wrongPassword", javaHash) == false) {
            System.out.println("Java hash validating bad password in PHP: pass");
        } else {
            System.out.println("Java hash validating bad password in PHP: FAIL");
            System.exit(1);
        }
    }

    private static void testGoodPHPHash()
    {
        PasswordHashPair pair = getPHPHash();
        try {
            if (PasswordStorage.verifyPassword(pair.password, pair.hash)) {
                System.out.println("PHP hash validating in Java: pass");
            } else {
                System.out.println("PHP hash validating in Java: FAIL");
                System.exit(1);
            }
        } catch (Exception e) {
                System.out.println(e.getMessage());
                System.exit(1);
        }
    }

    private static void testBadPHPHash()
    {
        PasswordHashPair pair = getPHPHash();
        try {
            if (!PasswordStorage.verifyPassword("wrongPassword", pair.hash)) {
                System.out.println("PHP hash validating bad password in Java: pass");
            } else {
                System.out.println("PHP hash validating bad password in Java: FAIL");
                System.exit(1);
            }
        } catch (Exception e) {
                System.out.println(e.getMessage());
                System.exit(1);
        }
    }

    private static boolean phpVerify(String password, String hash)
    {
        Process phpTest = null;
        ProcessBuilder pb = new ProcessBuilder(
            "php",
            "tests/phpVerify.php",
            password,
            hash
        );

        // We're run with the cwd as tests/ by runtests.sh. Since PHP's require
        // paths are relative to the cwd, we have to set it's cwd up one level:
        pb.directory(new File(".."));

        try {
            phpTest = pb.start();
        } catch (IOException e) {
            System.out.println(e.getMessage());
            System.exit(1);
        }

        try {
            phpTest.waitFor();
        } catch (Exception e) {
            System.out.println(e.getMessage());
            System.exit(1);
        }

        return phpTest.exitValue() == 0;
    }

    private static PasswordHashPair getPHPHash()
    {
        Process phpTest = null;
        ProcessBuilder pb = new ProcessBuilder(
            "php",
            "tests/phpHashMaker.php"
        );

        pb.directory(new File(".."));

        try {
            phpTest = pb.start();
        } catch (IOException e) {
            System.out.println(e.getMessage());
            System.exit(1);
        }

        BufferedReader stdInput = new BufferedReader(new InputStreamReader(phpTest.getInputStream()));
        String s = null;
        try {
            s = stdInput.readLine();
        } catch (IOException e) {
            System.out.println(e.getMessage());
            System.exit(1);
        }

        try {
            phpTest.waitFor();
        } catch (Exception e) {
            System.out.println(e.getMessage());
            System.exit(1);
        }

        String[] testData = s.split(" ");
        PasswordHashPair pair = new PasswordHashPair();
        pair.password = testData[1];
        pair.hash = testData[2];

        if (testData[1].length() != Integer.parseInt(testData[0])) {
            System.out.println("Unicode test is invalid.");
            System.exit(1);
        }

        return pair;
    }
}
