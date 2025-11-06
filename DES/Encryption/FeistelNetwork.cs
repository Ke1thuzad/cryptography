namespace Cryptography.DES.Encryption;

public class FeistelNetwork
{
    readonly ICipherTransform cipher;
    readonly IKeyExpander keyExpander;
    byte[]? key;
    byte[][]? roundKeys;
    
    public FeistelNetwork(ICipherTransform cipher, IKeyExpander keyExpander)
    {
        this.cipher = cipher;
        this.keyExpander = keyExpander;
    }
    
    public FeistelNetwork(ICipherTransform cipher, IKeyExpander keyExpander, byte[] key)
    {
        this.cipher = cipher;
        this.keyExpander = keyExpander;
        Key = key;
    }

    public byte[]? Key {
        get => key;
        set {
            key = value ?? throw new ArgumentNullException(nameof(value));
            roundKeys = keyExpander.ExpandKeyToRounds(key);
        }
    }

    public byte[] ProcessRounds(byte[] block, bool encrypt = true) 
    {
        if (roundKeys == null)
            throw new InvalidOperationException("Key not set. Set Key property first.");
            
        if (block.Length != 8)
            throw new ArgumentException("Feistel Networks accepts only 8-byte blocks");

        int size = block.Length;

        byte[] left = block[..(size / 2)];
        byte[] right = block[(size / 2)..];

        for (int round = 0; round < 16; round++) 
        {
            byte[] temp = (byte[])right.Clone();

            right = Utility.XORBytes(left, cipher.TransformBlock(right, roundKeys[encrypt ? round : 15 - round]));

            left = temp;
        }

        return right.Concat(left).ToArray();
    }
}