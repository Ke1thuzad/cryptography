using Cryptography.SymmetricAlgorithms.DES;

namespace Cryptography.SymmetricAlgorithms.DEAL.Adapters
{
    public class DesBlockCipherAdapter : Cryptography.IBlockCipherAdapter
    {
        public int BlockSize => 8;
        public int KeySize => 8;

        public byte[] EncryptBlock(byte[] block, byte[] key)
        {
            Des des = new Des();
            des.SetKey(key);
            return des.Encrypt(block).Result;
        }

        public byte[] DecryptBlock(byte[] block, byte[] key)
        {
            Des des = new Des();
            des.SetKey(key);
            return des.Decrypt(block).Result;
        }
    }
}