using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace Product.EncryptionBridge
{
    public static class PasswordEncryption
    {
        /*
         * Usage:
         * Create account: [Username] [Password]
         * Password = PasswordEncryption.Hash(Password, PasswordEncryption.CreateSalt()); // Create hash of this password with a random salt
         * Store this hashed password together with the username somewhere (db record, memory dictionary, etc)
         *
         * Login: [Username] [Password]
         * If the username exists in the db/memory grab the hash that was saved with this username record
         * if (PasswordEncryption.ComparePasswordToHash(Password, hash) == true) //if its true, then the password is correct
         */

        /// <summary>
        /// Create's and returns a random secure salt.
        /// </summary>
        /// <returns>The salt in base64 string format.</returns>
        public static string CreateSalt()
        {
            byte[] salt = new byte[16];
            new RNGCryptoServiceProvider().GetBytes(salt);
            return Convert.ToBase64String(salt);
        }

        /// <summary>
        /// Create's a secure hash based on the given password and salt.
        /// </summary>
        /// <param name="password">The password</param>
        /// <param name="salt">The salt (generate with CreateSalt())</param>
        /// <returns>The hash in base64 string format.</returns>
        public static string Hash(string password, string salt)
        {
            // Get the salt bytes from base64 string
            byte[] saltBytes = Convert.FromBase64String(salt);

            // Create the hash based on the salt with 10 000 iterations to slow down hash generation.
            // This way less passwords can be tried in a second, thus increasing security while not being too slow to affect the user.
            Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(password, saltBytes, 10000);
            byte[] hash = pbkdf2.GetBytes(20);

            // The salt + hash to be stored away
            byte[] hashBytes = new byte[36];

            // Place the bytes in their respective places
            Array.Copy(saltBytes, 0, hashBytes, 0, 16); // starting index 0 for the next 16 indexes (the salt)
            Array.Copy(hash, 0, hashBytes, 16, 20); // starting index 16 for the next 20 indexes (the actual hash)

            // Return the base64 string
            return Convert.ToBase64String(hashBytes);
        }

        /// <summary>
        /// Compares the password against the base64 string format salt prepended hash if they are identical to eachother.
        /// </summary>
        /// <param name="password">plaintext password</param>
        /// <param name="base64Hash">base64 string format hash</param>
        /// <returns>True/False based on if its identical or not.</returns>
        public static bool ComparePasswordToHash(string password, string base64Hash)
        {
            var salt = GetSaltFromHash(base64Hash);
            if (salt != null)
            {
                // Create a new hash with the given plaintext password and the salt, and check if its identical to our stored hash
                var newHash = Hash(password, salt);
                return CompareHash(base64Hash, newHash);
            }

            return false;
        }

        private static string GetSaltFromHash(string hash)
        {
            var hashBytes = Convert.FromBase64String(hash);
            if (hashBytes.Length == 36) return Convert.ToBase64String(hashBytes.Take(16).ToArray());
            return null;
        }

        private static bool CompareHash(string hash1, string hash2)
        {
            return CompareHash(Convert.FromBase64String(hash1), Convert.FromBase64String(hash2));
        }

        private static bool CompareHash(IReadOnlyList<byte> originalHash, IReadOnlyList<byte> otherHash)
        {
            // Ignore the prepended salt because we need to check the actual password hash
            for (int i = 16; i < 36; i++)
            {
                if (originalHash[i] != otherHash[i])
                {
                    return false;
                }
            }

            return true;
        }
    }
}
