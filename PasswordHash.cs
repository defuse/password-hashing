/* 
 * Password Hashing With PBKDF2 (http://crackstation.net/hashing-security.htm).
 * Copyright (c) 2013, Taylor Hornby
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, 
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation 
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE 
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
 * POSSIBILITY OF SUCH DAMAGE.
 */

using System;
using System.Text;
using System.Security.Cryptography;

namespace PasswordHash
{
    /// <summary>
    /// Salted password hashing with PBKDF2-SHA1.
    /// Author: havoc AT defuse.ca
    /// www: http://crackstation.net/hashing-security.htm
    /// Compatibility: .NET 3.0 and later.
    /// </summary>
    public class PasswordHash
    {
        /// <summary>
        /// The underlying BLOCK_SIZE of the pbkdf2 implementation.  As of 2014-07-20, the
        /// .NET Framework implementation uses SHA1, which has a block size of 20.
        /// </summary>
        public const int BLOCK_SIZE = 20;

        // The following constants may be changed without breaking existing hashes.
        public const int SALT_BYTE_SIZE = 24;
        /// <summary>
        /// HASH_BYTE_SIZE should *not* be greater than <see cref="BLOCK_SIZE"/>.  A HASH_BYTE_SIZE greater than block size makes
        /// the defender's job more difficult, without making the attackers job more difficult, because the defender
        /// must calculate all blocks, but the attacker only has to check the first block.  Instead,
        /// increase the iteration count and salt size to make the attacker's job more difficult.
        /// </summary>
        public const int HASH_BYTE_SIZE = BLOCK_SIZE;
        public const int PBKDF2_ITERATIONS = 1000;

        public const int ITERATION_INDEX = 0;
        public const int SALT_INDEX = 1;
        public const int PBKDF2_INDEX = 2;

        /// <summary>
        /// Creates a salted PBKDF2 hash of the password.
        /// </summary>
        /// <param name="password">The password to hash.</param>
        /// <param name="pbkdf2Iterations">The number of iterations of the pbkdf2 algorithm. Higher numbers take longer to create and validate, and are thus harder to crack.</param>
        /// <param name="saltBytes">The length of the salt in bytes. As a rule of thumb, the salt should be at least as long as <see cref="hashBytes"/>.</param>
        /// <param name="hashBytes">The length of the final password hash in bytes. This should *not* exceed <see cref="BLOCK_SIZE"/>.</param>
        /// <returns>The hash of the password.</returns>
        public static string CreateHash(string password, int pbkdf2Iterations = PBKDF2_ITERATIONS, int saltBytes = SALT_BYTE_SIZE, int hashBytes = HASH_BYTE_SIZE)
        {
            // Generate a random salt
            RNGCryptoServiceProvider csprng = new RNGCryptoServiceProvider();
            byte[] salt = new byte[saltBytes];
            csprng.GetBytes(salt);

            // Hash the password and encode the parameters
            byte[] hash = PBKDF2(password, salt, pbkdf2Iterations, hashBytes);
            return pbkdf2Iterations + ":" +
                Convert.ToBase64String(salt) + ":" +
                Convert.ToBase64String(hash);
        }

        /// <summary>
        /// Validates a password given a hash of the correct one.
        /// </summary>
        /// <param name="password">The password to check.</param>
        /// <param name="correctHash">A hash of the correct password.</param>
        /// <returns>True if the password is correct. False otherwise.</returns>
        public static bool ValidatePassword(string password, string correctHash)
        {
            // Extract the parameters from the hash
            char[] delimiter = { ':' };
            string[] split = correctHash.Split(delimiter);
            int iterations = Int32.Parse(split[ITERATION_INDEX]);
            byte[] salt = Convert.FromBase64String(split[SALT_INDEX]);
            byte[] hash = Convert.FromBase64String(split[PBKDF2_INDEX]);

            byte[] testHash = PBKDF2(password, salt, iterations, hash.Length);
            return SlowEquals(hash, testHash);
        }

        /// <summary>
        /// Compares two byte arrays in length-constant time. This comparison
        /// method is used so that password hashes cannot be extracted from
        /// on-line systems using a timing attack and then attacked off-line.
        /// </summary>
        /// <param name="a">The first byte array.</param>
        /// <param name="b">The second byte array.</param>
        /// <returns>True if both byte arrays are equal. False otherwise.</returns>
        private static bool SlowEquals(byte[] a, byte[] b)
        {
            uint diff = (uint)a.Length ^ (uint)b.Length;
            for (int i = 0; i < a.Length && i < b.Length; i++)
                diff |= (uint)(a[i] ^ b[i]);
            return diff == 0;
        }

        /// <summary>
        /// Computes the PBKDF2-SHA1 hash of a password.
        /// </summary>
        /// <param name="password">The password to hash.</param>
        /// <param name="salt">The salt.</param>
        /// <param name="iterations">The PBKDF2 iteration count.</param>
        /// <param name="outputBytes">The length of the hash to generate, in bytes.</param>
        /// <returns>A hash of the password.</returns>
        private static byte[] PBKDF2(string password, byte[] salt, int iterations, int outputBytes)
        {
            Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(password, salt);
            pbkdf2.IterationCount = iterations;
            return pbkdf2.GetBytes(outputBytes);
        }
    }
} 
