import java.io.*;

public class JavaAndPHPCompatibility {
    
    public static void main(String[] args)
    {
        testJavaHash();
        testPHPHash();
    }
    
    private static void testJavaHash() {
        javaGoodHashTest();
        javaBadHashTest();
    }
    
    private static void testPHPHash() {
        testGoodPHPHash();
        testBadPHPHash();
    }

    private static void javaGoodHashTest()
    {
        String userString = "RedragonX!";
        String javaHash = "";

        try {
            javaHash = PasswordHash.createHash(userString); 
        } catch (Exception e) {
            System.out.println("ERROR: validation failed for a Java hash in PHP implementation!!!");
            System.out.println(e.getMessage());
            System.exit(1);
        }

        Process phpTest = null;
        ProcessBuilder pb = new ProcessBuilder("/usr/bin/php",
            "tests/phpValidate.php",
            userString,
            javaHash
            );

        // set working dir for php...
        pb.directory(new File(".."));

        // good password test...
        try {
            phpTest = pb.start();
        } catch (IOException e) {
            System.out.println("ERROR: validation failed for a Java hash in PHP implementation!!!");
            System.out.println(e.getMessage());
            System.exit(1);
        }

        // wait for the php process.
        try {
            phpTest.waitFor();
        } catch (Exception e) {
            System.out.println("ERROR: validation failed for a Java hash in PHP implementation!!!");
            System.out.println(e.getMessage());
            System.exit(1);
        }

        if (phpTest.exitValue() == 1) { 
            System.out.println("ERROR: validation failed for a Java hash in PHP implementation!!!");
            System.exit(1);
        } else {
            System.out.println("SUCCESS: Hash validation passed");
        }
    }
    
    private static void javaBadHashTest() {
        String userString = "RedragonX!";
        String javaHash = "";

        try {
            javaHash = PasswordHash.createHash(userString); 
        } catch (Exception e) {
            System.out.println("ERROR: bad password test failed for a Ruby hash in PHP implementation!!!");
            System.out.println(e.getMessage());
            System.exit(1);
        }

        Process phpTest = null;
        ProcessBuilder pb = new ProcessBuilder("/usr/bin/php",
            "tests/phpValidate.php",
            "badPW",
            javaHash
            );

        // set working dir for php...
        pb.directory(new File(".."));

        // bad password test...
        try {
            phpTest = pb.start();
        } catch (IOException e) {
            System.out.println("ERROR: bad password test failed for a Ruby hash in PHP implementation!!!");
            System.out.println(e.getMessage());
            System.exit(1);
        }

        // wait for the php process.
        try {
            phpTest.waitFor();
        } catch (Exception e) {
            System.out.println("ERROR: bad password test failed for a Ruby hash in PHP implementation!!!");
            System.out.println(e.getMessage());
            System.exit(1);
        }

        if (phpTest.exitValue() == 1) { 
            System.out.println("SUCCESS: The PHP implementation did not accept a bad password.");
        } else {
            System.out.println("ERROR: bad password test failed for a Ruby hash in PHP implementation!!!");
            System.exit(1);
        }
    }
    
    private static void testGoodPHPHash() {
        String[] testData = null;

        Process phpTest = null;
        ProcessBuilder pb = new ProcessBuilder("/usr/bin/php",
            "tests/phpHashMaker.php"
            );

        // set working dir for php...
        pb.directory(new File(".."));

        // good password test...
        try {
            phpTest = pb.start();
        } catch (IOException e) {
            System.out.println("ERROR: PHP hash validation failed in a Java implementation!!!");
            System.out.println(e.getMessage());
            System.exit(1);
        }

        // read the output from the command
        BufferedReader stdInput = new BufferedReader(new InputStreamReader(phpTest.getInputStream()));
        String s = null;
        String tempData = null;
        try {
            while ((tempData = stdInput.readLine()) != null) {
                s = tempData;
            }
        } catch (IOException e) {
            System.out.println("ERROR: PHP hash validation failed in a Java implementation!!!");
            System.out.println(e.getMessage());
            System.exit(1);
        }

        // wait for the php process.
        try {
            phpTest.waitFor();
        } catch (Exception e) {
            System.out.println("ERROR: PHP hash validation failed in a Java implementation!!!");
            System.out.println(e.getMessage());
            System.exit(1);
        }

        testData = s.split(" ");

        try {
            if (PasswordHash.validatePassword(testData[0], testData[1])) { 
                System.out.println("SUCCESS: PHP hash validation in a Java implementation passed");
            } else {
                System.out.println("ERROR: bad password test failed for a PHP hash in a Java implementation!!!");
                System.exit(1);
            }
        } catch (Exception e) {
                System.out.println("ERROR: bad password test failed for a PHP hash in a Java implementation!!!");
                System.out.println(e.getMessage());
                System.exit(1);
        }
    }

    private static void testBadPHPHash() {
        String[] testData = null;

        Process phpTest = null;
        ProcessBuilder pb = new ProcessBuilder("/usr/bin/php",
            "tests/phpHashMaker.php"
            );

        // set working dir for php...
        pb.directory(new File(".."));

        // bad password test...
        try {
            phpTest = pb.start();
        } catch (IOException e) {
            System.out.println("ERROR: bad password test failed for a PHP hash in Java implementation!!!");
            System.out.println(e.getMessage());
            System.exit(1);
        }

        // read the output from the command
        BufferedReader stdInput = new BufferedReader(new InputStreamReader(phpTest.getInputStream()));
        String s = null;
        String tempData = null;
        try {
            while ((tempData = stdInput.readLine()) != null) {
                s = tempData;
            }
        } catch (IOException e) {
            System.out.println("ERROR: bad password test failed for a PHP hash in Java implementation!!!");
            System.out.println(e.getMessage());
            System.exit(1);
        }

        // wait for the php process.
        try {
            phpTest.waitFor();
        } catch (Exception e) {
            System.out.println("ERROR: PHP hash validation failed in a Java implementation!!!");
            System.out.println(e.getMessage());
            System.exit(1);
        }

        testData = s.split(" ");

        try {
            if (!PasswordHash.validatePassword("badPW", testData[1])) { 
                System.out.println("SUCCESS: The Java implementation did not accept a bad password.");
            } else {
                System.out.println("ERROR: bad password test failed for a PHP hash in a Java implementation!!!");
                System.exit(1);
            }
        } catch (Exception e) {
                System.out.println("ERROR: bad password test failed for a PHP hash in a Java implementation!!!");
                System.out.println(e.getMessage());
                System.exit(1);
        }
    }
}
