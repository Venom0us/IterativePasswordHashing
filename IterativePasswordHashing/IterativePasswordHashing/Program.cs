using System;
using System.Diagnostics;
using Product.EncryptionBridge;

namespace Product
{
    class Program
    {
        /* Slow approach hashing 
         * Some example usage and bench marks
         */

        static void Main(string[] args)
        {
            Stopwatch sw = new Stopwatch();

            // Create random guid password
            string password = Guid.NewGuid().ToString();
            
            sw.Start();
            string storedHash = PasswordEncryption.Hash(password, PasswordEncryption.CreateSalt());
            sw.Stop();

            Console.WriteLine("Salted hash with password ["+ password + "]: " + storedHash);
            Console.WriteLine("Time taken: " + sw.Elapsed);
            sw.Reset();
            Console.WriteLine();
            sw.Start();
            Console.WriteLine("Check if the hash is the same when generated again based on same salt: " + PasswordEncryption.ComparePasswordToHash(password, storedHash));
            Console.WriteLine("Time taken: " + sw.Elapsed);
            Console.ReadLine();
        }
    }
}