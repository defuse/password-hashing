using PasswordSecurity;
using System;
using System.Text;
using System.Diagnostics;

class CSharpAndPHPCompatibility
{
    private struct CommandExecResult
    {
        public int exitCode;
        public string stdOut;
    }

    public static void Main()
    {
       testCSharpHashes();
       testPHPHashes();
    }

    private static void testCSharpHashes()
    {
        string userPW = "test_password";
        string goodHash = PasswordStorage.CreateHash(userPW);

        // Good password.
        string args = "tests/phpVerify.php" + " " + userPW + " " + goodHash;
        CommandExecResult goodHashExecution = RunCommand("php", args);
        if (goodHashExecution.exitCode == 0)
        {
            Console.WriteLine("C# hash valdating in PHP: pass");
        }
        else if (goodHashExecution.exitCode == 1)
        {
            Console.WriteLine("C# hash validating in PHP: FAIL");
            System.Environment.Exit(1);
        }

        // Bad password.
        args = "tests/phpVerify.php" + " " + "wrongPassword" + " " + goodHash;
        CommandExecResult badHashExecution = RunCommand("php", args);
        if (badHashExecution.exitCode == 0)
        {
            Console.WriteLine("C# hash validating wrong password in PHP: FAIL");
            System.Environment.Exit(1);
        }
        else if (badHashExecution.exitCode == 1)
        {
            Console.WriteLine("C# hash validating wrong password in PHP: pass");
        }
    }

    private static void testPHPHashes()
    {
        string[] testData = null;
        char[] useDelimiter = { ' ' };

        // Good password.
        CommandExecResult goodHashExecution = RunCommand("php", "tests/phpHashMaker.php");
        testData = goodHashExecution.stdOut.Split(useDelimiter);

        if (testData[1].Length != Int32.Parse(testData[0])) {
            Console.WriteLine("Unicode test is invalid.");
            System.Environment.Exit(1);
        }

        if (PasswordStorage.VerifyPassword(testData[1], testData[2]))
        {
            Console.WriteLine("PHP hash validating in C#: pass");
        }
        else
        {
            Console.WriteLine("PHP hash validating in C#: FAIL");
            System.Environment.Exit(1);
        }

        // Bad password.
        CommandExecResult badHashExecution = RunCommand("php", "tests/phpHashMaker.php");
        testData = badHashExecution.stdOut.Split(useDelimiter);

        if (testData[1].Length != Int32.Parse(testData[0])) {
            Console.WriteLine("Unicode test is invalid.");
            System.Environment.Exit(1);
        }

        if (PasswordStorage.VerifyPassword("wrongPassword", testData[2]))
        {
            Console.WriteLine("The C# implementation accepts BAD PHP hashes: FAIL");
            System.Environment.Exit(1);
        }
        else
        {
            Console.WriteLine("The C# implementation will not accept bad PHP hashes: pass");
        }
    }

    private static CommandExecResult RunCommand(String processName, String args)
    {
        Process p = new Process();
        string output = "";

        p.StartInfo.FileName = processName;
        p.StartInfo.WorkingDirectory = "..";
        p.StartInfo.Arguments = args;
        p.StartInfo.UseShellExecute = false;
        p.StartInfo.RedirectStandardOutput = true;
        try
        {
            p.Start();

            output = p.StandardOutput.ReadToEnd();
            p.WaitForExit();
        }
        catch (Exception e)
        {
            Console.WriteLine(e.Message);
            System.Environment.Exit(1);
        }

        CommandExecResult cmdResult;
        cmdResult.exitCode = p.ExitCode;
        cmdResult.stdOut = output;

        return cmdResult;
    }
}
