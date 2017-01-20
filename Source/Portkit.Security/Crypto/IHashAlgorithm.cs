namespace Portkit.Security.Crypto
{
    public interface IHashAlgorithm
    {
        byte[] ComputeHash(byte[] buffer, int offset, int count);

        IHashAlgorithm Reset();
    }
}