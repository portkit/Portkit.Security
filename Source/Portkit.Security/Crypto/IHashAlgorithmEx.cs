namespace Portkit.Security.Crypto
{
    public static class IHashAlgorithmEx
    {
        public static byte[] ComputeHash(this IHashAlgorithm hashAlgorithm, byte[] buffer)
        {
            return hashAlgorithm.ComputeHash(buffer, 0, buffer.Length);
        }
    }
}