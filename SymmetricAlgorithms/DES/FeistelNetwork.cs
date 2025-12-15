using Cryptography.Utility;

namespace Cryptography.SymmetricAlgorithms.DES;

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

    public byte[] ProcessRounds(byte[] block, bool encrypt = true) {
        if (roundKeys == null)
            throw new InvalidOperationException("Key not set. Set Key property first.");

        int size = block.Length;

        byte[] left = block[..(size / 2)];
        byte[] right = block[(size / 2)..];

        for (int round = 0; round < roundKeys.Length; round++) 
        {
            if (encrypt) {
                byte[] temp = (byte[])right.Clone();

                right = BitOperations.XORBytes(left, cipher.TransformBlock(right, roundKeys[round]));

                left = temp;
            }
            else {
                byte[] temp = (byte[])left.Clone();

                left = BitOperations.XORBytes(right, cipher.TransformBlock(left, roundKeys[roundKeys.Length - 1 - round]));

                right = temp;
                
            }
        }
        
        return left.Concat(right).ToArray();
    }
}