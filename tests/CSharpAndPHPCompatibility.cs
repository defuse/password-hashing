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
        // good C# hash test 
        string userPW = "RedragonX!";
        string goodHash = PasswordHash.CreateHash(userPW);

        string args = "tests/phpValidate.php" +
            " " +
            userPW +
            " " +
            goodHash;

        CommandExecResult goodHashExecution = RunCommand("php", args);

        if (goodHashExecution.exitCode == 0)
        {
            Console.WriteLine("The PHP implementation accepts C# hashes: pass");
        }
        else if (goodHashExecution.exitCode == 1)
        {
            Console.WriteLine("The PHP implementation does not accept C# hashes: FAIL");
            System.Environment.Exit(1);
        }

        string badPW = "ctfred";
        // bad c# hash test
        args = "tests/phpValidate.php" +
            " " +
            badPW +
            " " +
            goodHash;

        CommandExecResult badHashExecution = RunCommand("php", args);

        if (badHashExecution.exitCode == 0)
        {
            Console.WriteLine("The PHP implementation accepts BAD C# hashes: FAIL");
            System.Environment.Exit(1);
        }
        else if (badHashExecution.exitCode == 1)
        {
            Console.WriteLine("The PHP implementation does not accept bad C# hashes: pass");
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

    private static void testPHPHashes()
    {
        // good PHP hash test 
        string[] testData = null;
        char[] useDelimiter = { ' ' };
        string args = "tests/phpHashMaker.php";

        CommandExecResult goodHashExecution = RunCommand("php", args);

        testData = goodHashExecution.stdOut.Split(useDelimiter);

        if ( PasswordHash.ValidatePassword(testData[0], testData[1]) )
        {
            Console.WriteLine("The C# implementation accepts PHP hashes: pass");
        }
        else
        {
            Console.WriteLine("The C# implementation does not accept PHP hashes: FAIL");
            System.Environment.Exit(1);
        }

        // bad PHP hash test
        CommandExecResult badHashExecution = RunCommand("php", args);
        string badPW = "badPW";

        testData = badHashExecution.stdOut.Split(useDelimiter);

        if ( PasswordHash.ValidatePassword(badPW, testData[1]) )
        {
            Console.WriteLine("The C# implementation accepts BAD PHP hashes: FAIL");
            System.Environment.Exit(1);
        }
        else
        {
            Console.WriteLine("The C# implementation will not accept bad PHP hashes: pass");
        }
    }
}
