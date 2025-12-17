namespace Cryptography.SymmetricAlgorithms.RC4;

public class Rc4 : ISymmetricKeyAlgorithm
{
    byte[] sBox;
    int x;
    int y;

    public int BlockSize => 1;

    public void SetKey(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length is 0 or > 256)
            throw new ArgumentException("Key length must be between 1 and 256 bytes.");

        sBox = new byte[256];
        for (int i = 0; i < 256; i++)
        {
            sBox[i] = (byte)i;
        }

        int j = 0;
        for (int i = 0; i < 256; i++)
        {
            j = (j + sBox[i] + key[i % key.Length]) & 0xFF;
            (sBox[i], sBox[j]) = (sBox[j], sBox[i]);
        }

        x = 0;
        y = 0;
    }

    public Task<byte[]> Encrypt(byte[] block)
    {
        if (sBox == null)
            throw new InvalidOperationException("Key not set. Call SetKey first.");
        
        byte[] result = new byte[block.Length];
        ProcessBytes(block, result);
        
        return Task.FromResult(result);
    }

    public Task<byte[]> Decrypt(byte[] block) => Encrypt(block);

    void ProcessBytes(byte[] input, byte[] output)
    {
        for (int i = 0; i < input.Length; i++)
        {
            x = (x + 1) & 0xFF;
            y = (y + sBox[x]) & 0xFF;

            (sBox[x], sBox[y]) = (sBox[y], sBox[x]);

            byte k = sBox[(sBox[x] + sBox[y]) & 0xFF];
            
            output[i] = (byte)(input[i] ^ k);
        }
    }
}