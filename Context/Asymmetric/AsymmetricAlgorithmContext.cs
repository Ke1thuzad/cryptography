using Cryptography.Utility;

namespace Cryptography.Context.Asymmetric;

public class AsymmetricAlgorithmContext
{
    readonly IAsymmetricCipher cipher;
    readonly int keySizeBytes;
    readonly int maxDataBlockSize;
    const int PaddingOverhead = 11;

    public AsymmetricAlgorithmContext(IAsymmetricCipher cipher)
    {
        if (!cipher.HasKey) throw new ArgumentException("Keys required");
        this.cipher = cipher;
        
        keySizeBytes = (cipher.KeySizeBits + 7) / 8;
        maxDataBlockSize = keySizeBytes - PaddingOverhead;
    }

    public async Task Encrypt(string inFile, string outFile)
    {
        int batchSize = 1000;
        int bufferSize = maxDataBlockSize * batchSize;
        
        await ProcessFile(inFile, outFile, bufferSize, EncryptBytesParallel);
    }

    public async Task Decrypt(string inFile, string outFile)
    {
        int batchSize = 1000;
        int bufferSize = keySizeBytes * batchSize;
        
        await ProcessFile(inFile, outFile, bufferSize, DecryptBytesParallel);
    }

    public async Task<byte[]> Encrypt(byte[] data) => await Task.Run(() => EncryptBytesParallel(data));

    byte[] EncryptBytesParallel(byte[] data)
    {
        if (data.Length == 0) 
            return [];

        int blockSize = maxDataBlockSize;
        int outputBlockSize = keySizeBytes;
        
        int blockCount = (data.Length + blockSize - 1) / blockSize;
        byte[] result = new byte[blockCount * outputBlockSize];

        Parallel.For(0, blockCount, i =>
        {
            int offset = i * blockSize;
            int currentSize = Math.Min(blockSize, data.Length - offset);
            
            byte[] chunk = new byte[currentSize];
            Buffer.BlockCopy(data, offset, chunk, 0, currentSize);

            byte[] encryptedChunk = cipher.Encrypt(chunk);

            Buffer.BlockCopy(encryptedChunk, 0, result, i * outputBlockSize, outputBlockSize);
        });

        return result;
    }

    public async Task<byte[]> Decrypt(byte[] data) => await Task.Run(() => DecryptBytesParallel(data));

    byte[] DecryptBytesParallel(byte[] data)
    {
        if (data.Length == 0) 
            return [];
        
        if (data.Length % keySizeBytes != 0) 
            throw new ArgumentException("Invalid data length");

        int blockSize = keySizeBytes;
        int blockCount = data.Length / blockSize;

        byte[][] decryptedBlocks = new byte[blockCount][];

        Parallel.For(0, blockCount, i =>
        {
            byte[] chunk = new byte[blockSize];
            Buffer.BlockCopy(data, i * blockSize, chunk, 0, blockSize);

            decryptedBlocks[i] = cipher.Decrypt(chunk);
        });

        long totalLen = 0;
        for (int i = 0; i < blockCount; i++) totalLen += decryptedBlocks[i].Length;

        byte[] result = new byte[totalLen];
        int currentOffset = 0;
        for (int i = 0; i < blockCount; i++)
        {
            byte[] block = decryptedBlocks[i];
            Buffer.BlockCopy(block, 0, result, currentOffset, block.Length);
            currentOffset += block.Length;
        }

        return result;
    }

    static async Task ProcessFile(string inPath, string outPath, int bufSize, Func<byte[], byte[]> processFunc)
    {
        byte[] buffer = new byte[bufSize];
        await using FileStream input = new(inPath, FileMode.Open, FileAccess.Read);
        await using FileStream output = new(outPath, FileMode.Create, FileAccess.Write);

        int bytesRead;
        while ((bytesRead = await input.ReadAsync(buffer.AsMemory(0, bufSize))) > 0)
        {
            byte[] chunk = new byte[bytesRead];
            Buffer.BlockCopy(buffer, 0, chunk, 0, bytesRead);
            
            byte[] processed = await Task.Run(() => processFunc(chunk));
            
            await output.WriteAsync(processed);
        }
    }
}