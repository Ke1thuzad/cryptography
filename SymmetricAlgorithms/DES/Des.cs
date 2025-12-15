using Cryptography.Utility;

namespace Cryptography.SymmetricAlgorithms.DES;

public class Des : ISymmetricKeyAlgorithm
{
    readonly FeistelNetwork feistelNetwork;
    
    public int BlockSize => 8;
    
    public Des()
    {
        IKeyExpander keyExpander = new KeySchedule();
        ICipherTransform cipherTransform = new Feistel();
        feistelNetwork = new FeistelNetwork(cipherTransform, keyExpander);
    }
    
    public Des(IKeyExpander keyExpander, ICipherTransform cipherTransform)
    {
        feistelNetwork = new FeistelNetwork(cipherTransform, keyExpander);
    }

    public void SetKey(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);

        if (key.Length != 8 && key.Length != 7)
            throw new ArgumentException("DES key must be 7/8 bytes (56/64 bits)");
        
        feistelNetwork.Key = BitOperations.ExtendKeyWithParity(key);
    }

    public Task<byte[]> Encrypt(byte[] block)
    {
        if (feistelNetwork.Key == null)
            throw new InvalidOperationException("Key not set. Call SetKey first.");

        ArgumentNullException.ThrowIfNull(block);

        if (block.Length != BlockSize)
            throw new ArgumentException($"Block size must be {BlockSize} bytes");

        byte[] permutedBlock = BitOperations.PermuteBits(block, DesTables.IP);
        
        byte[] processedBlock = feistelNetwork.ProcessRounds(permutedBlock, encrypt: true);
        
        byte[] result = BitOperations.PermuteBits(processedBlock, DesTables.IPInv);
        
        return Task.FromResult(result);
    }

    public Task<byte[]> Decrypt(byte[] block)
    {
        if (feistelNetwork.Key == null)
            throw new InvalidOperationException("Key not set. Call SetKey first.");

        ArgumentNullException.ThrowIfNull(block);

        if (block.Length != BlockSize)
            throw new ArgumentException($"Block size must be {BlockSize} bytes");

        byte[] permutedBlock = BitOperations.PermuteBits(block, DesTables.IP);
        
        byte[] processedBlock = feistelNetwork.ProcessRounds(permutedBlock, encrypt: false);
        
        byte[] result = BitOperations.PermuteBits(processedBlock, DesTables.IPInv);
        
        return Task.FromResult(result);
    }
}