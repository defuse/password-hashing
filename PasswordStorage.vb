Imports System
Imports System.Text
Imports System.Security.Cryptography

Namespace PasswordSecurity

    Class InvalidHashException
        Inherits Exception

        ' Default constructor
        Sub New()
        End Sub

        Sub New(message As String)
            MyBase.New(message)
        End Sub

        Sub New(message As String, innerException As Exception)
            MyBase.New(message, innerException)
        End Sub

    End Class

    Class CannotPerformOperationException
        Inherits Exception

        ' Default constructor
        Sub New()
        End Sub

        Sub New(message As String)
            MyBase.New(message)
        End Sub

        Sub New(message As String, innerException As Exception)
            MyBase.New(message, innerException)
        End Sub
    End Class

    Public Class PasswordStorage

        'These constants may be changed without breaking existing hashes.
        Public Const SALT_BYTES As Integer = 24
        Public Const HASH_BYTES As Integer = 18
        Public Const PBKDF2_ITERATIONS As Integer = 64000

        ' These constants define the encoding And may Not be changed.
        Public Const HASH_SECTIONS As Integer = 5
        Public Const HASH_ALGORITHM_INDEX As Integer = 0
        Public Const ITERATION_INDEX As Integer = 1
        Public Const HASH_SIZE_INDEX As Integer = 2
        Public Const SALT_INDEX As Integer = 3
        Public Const PBKDF2_INDEX As Integer = 4

        Public Shared Function CreateHash(password As String) As String

            Dim salt(SALT_BYTES) As Byte
            Try

                Using csprng = New RNGCryptoServiceProvider()
                    csprng.GetBytes(salt)
                End Using

            Catch ex As CryptographicException
                Throw New CannotPerformOperationException("Random number generator not available", ex)
            Catch ex As ArgumentException
                Throw New CannotPerformOperationException("Invalid argument given to random number generator", ex)
            End Try

            Dim hash() As Byte = PBKDF2(password, salt, PBKDF2_ITERATIONS, HASH_BYTES)

            ' format: algorithm:iteration:hashSize:salt:hash
            Dim parts As String = "sha1:" + PBKDF2_ITERATIONS.ToString() + ":" + hash.Length.ToString() + ":" + Convert.ToBase64String(salt) + ":" + Convert.ToBase64String(hash)
            Return parts

        End Function

        Public Shared Function VerifyPassword(password As String, goodHash As String) As Boolean
            Dim delimter() As Char = {":"}
            Dim split As String() = goodHash.Split(delimter)

            If split.Length <> HASH_SECTIONS Then
                Throw New InvalidHashException("Fields are missing from the password hash")
            End If

            ' We only support SHA1 with VB.NET
            If split(HASH_ALGORITHM_INDEX) <> "sha1" Then
                Throw New CannotPerformOperationException("Unsupported hash type.")
            End If

            Dim iterations As Integer = 0
            Try
                iterations = Integer.Parse(split(ITERATION_INDEX))
            Catch ex As ArgumentException
                Throw New CannotPerformOperationException("Invalid argument given to Int32.Parse", ex)
            Catch ex As FormatException
                Throw New InvalidHashException("Could not parse the iteration count as an integer.", ex)
            Catch ex As OverflowException
                Throw New InvalidHashException("The iteration count is too large to be represented.", ex)
            End Try

            If iterations < 1 Then
                Throw New InvalidHashException("Invalid number of interations. Must be >= 1.")
            End If

            Dim salt() As Byte = Nothing
            Try
                salt = Convert.FromBase64String(split(SALT_INDEX))
            Catch ex As ArgumentException
                Throw New CannotPerformOperationException("Invalid argument given to Convert.FromBase64String.", ex)
            Catch ex As FormatException
                Throw New InvalidHashException("Base64 decoding of salt failed.", ex)
            End Try

            Dim hash() As Byte = Nothing
            Try
                hash = Convert.FromBase64String(split(PBKDF2_INDEX))
            Catch ex As ArgumentException
                Throw New CannotPerformOperationException("Invalid argument given to Convert.FromBase64String.", ex)
            Catch ex As FormatException
                Throw New InvalidHashException("Base64 decoding of pbkdf2 output failed.", ex)
            End Try

            Dim storedHashSize As Integer = 0
            Try
                storedHashSize = Integer.Parse(split(HASH_SIZE_INDEX))
            Catch ex As ArgumentException
                Throw New CannotPerformOperationException("Invalid argument given to Integer.Parse.", ex)
            Catch ex As FormatException
                Throw New InvalidHashException("The hash size is too large to be represented.", ex)
            End Try

            If storedHashSize <> hash.Length Then
                Throw New InvalidHashException("Hash length doesn't match stored hash length.")
            End If

            Dim testHash() As Byte = PBKDF2(password, salt, iterations, hash.Length)
            Return SlowEquals(hash, testHash)
        End Function

        Private Shared Function SlowEquals(a() As Byte, b() As Byte) As Boolean
            Dim diff As UInteger = CUInt(a.Length) Xor CUInt(b.Length)
            Dim i = 0
            While i < a.Length And i < b.Length
                diff = diff Or CUInt(a(i) Xor b(i))
                i = i + 1
            End While
            Return diff = 0
        End Function

        Private Shared Function PBKDF2(password As String, salt() As Byte, iterations As Integer, outputBytes As Integer)
            Using pbkdf2DerivedBytes = New Rfc2898DeriveBytes(password, salt)
                pbkdf2DerivedBytes.IterationCount = iterations
                Return pbkdf2DerivedBytes.GetBytes(outputBytes)
            End Using
        End Function

    End Class

End Namespace


