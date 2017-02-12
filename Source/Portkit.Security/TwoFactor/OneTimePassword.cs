using System;
using Portkit.Security.Crypto;

namespace Portkit.Security.TwoFactor
{
    public class OneTimePassword
    {
        private readonly MacAlgorithmProvider _mac;

        public OneTimePassword(IHashAlgorithm hashAlgorithm, string secret)
        {
            var key = Base32.Decode(secret);
            _mac = new MacAlgorithmProvider(key, hashAlgorithm);
        }

        public string Generate(long counter, int digits = 6)
        {
            var counterBytes = BitConverter.GetBytes(counter);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(counterBytes);
            }

            var hash = _mac.ComputeHash(counterBytes);
            var offset = hash[hash.Length - 1] & 0xf;

            // Convert the 4 bytes into an integer, ignoring the sign.
            var binary = ((hash[offset] & 0x7f) << 24)
                         | (hash[offset + 1] << 16)
                         | (hash[offset + 2] << 8)
                         | (hash[offset + 3]);

            var token = binary % (int) Math.Pow(10, digits);
            return token.ToString().PadLeft(digits, '0');
        }
    }
}