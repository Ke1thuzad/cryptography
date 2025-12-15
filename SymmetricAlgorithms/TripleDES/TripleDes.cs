using Cryptography.SymmetricAlgorithms.DES;
using Cryptography.Utility;

namespace Cryptography.SymmetricAlgorithms.TripleDES;

public class TripleDes : ISymmetricKeyAlgorithm
{
    readonly Des des1;
    readonly Des des2;
    readonly Des des3;
    readonly bool useThreeKeys;
    
    public int BlockSize => 8;
    
    public TripleDes(bool useThreeKeys = true)
    {
        this.useThreeKeys = useThreeKeys;
        des1 = new Des();
        des2 = new Des();
        des3 = useThreeKeys ? new Des() : des1;
    }
    
    public TripleDes(IKeyExpander keyExpander1, ICipherTransform cipherTransform1,
                    IKeyExpander keyExpander2, ICipherTransform cipherTransform2,
                    IKeyExpander keyExpander3, ICipherTransform cipherTransform3,
                    bool useThreeKeys = true)
    {
        this.useThreeKeys = useThreeKeys;
        des1 = new Des(keyExpander1, cipherTransform1);
        des2 = new Des(keyExpander2, cipherTransform2);
        des3 = useThreeKeys ? new Des(keyExpander3, cipherTransform3) : des1;
    }

    public void SetKey(byte[] key)
    {
        if (useThreeKeys)
        {
            if (key.Length != 21 && key.Length != 24)
                throw new ArgumentException("3-key Triple DES requires 21 or 24 byte key");

            int keyPartSize = key.Length / 3;
            
            byte[] key1 = new byte[keyPartSize];
            byte[] key2 = new byte[keyPartSize];
            byte[] key3 = new byte[keyPartSize];
            
            Buffer.BlockCopy(key, 0, key1, 0, keyPartSize);
            Buffer.BlockCopy(key, keyPartSize, key2, 0, keyPartSize);
            Buffer.BlockCopy(key, 2 * keyPartSize, key3, 0, keyPartSize);

            des1.SetKey(keyPartSize == 7 ? BitOperations.ExtendKeyWithParity(key1) : key1);
            des2.SetKey(keyPartSize == 7 ? BitOperations.ExtendKeyWithParity(key2) : key2);
            des3.SetKey(keyPartSize == 7 ? BitOperations.ExtendKeyWithParity(key3) : key3);
        }
        else
        {
            if (key.Length != 14 && key.Length != 16)
                throw new ArgumentException("2-key Triple DES requires 14 or 16 byte key");

            int keyPartSize = key.Length / 2;
            
            byte[] key1 = new byte[keyPartSize];
            byte[] key2 = new byte[keyPartSize];
            
            Buffer.BlockCopy(key, 0, key1, 0, keyPartSize);
            Buffer.BlockCopy(key, keyPartSize, key2, 0, keyPartSize);

            des1.SetKey(keyPartSize == 7 ? BitOperations.ExtendKeyWithParity(key1) : key1);
            des2.SetKey(keyPartSize == 7 ? BitOperations.ExtendKeyWithParity(key2) : key2);
        }
    }

    // DES-EDE3
    public async Task<byte[]> Encrypt(byte[] block)
    {
        byte[] step1 = await des1.Encrypt(block);
        byte[] step2 = await des2.Decrypt(step1);
        byte[] step3 = await des3.Encrypt(step2);
        return step3;
    }

    public async Task<byte[]> Decrypt(byte[] block)
    {
        byte[] step1 = await des3.Decrypt(block);
        byte[] step2 = await des2.Encrypt(step1);
        byte[] step3 = await des1.Decrypt(step2);
        return step3;
    }
}