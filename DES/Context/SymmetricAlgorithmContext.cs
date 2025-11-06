using System.Runtime.InteropServices;

namespace Cryptography.DES.Context;

public class SymmetricAlgorithmContext
{
    readonly CipherMode cipherMode;
    readonly Padding padding;
    readonly int algorithmBlockSize;

    public SymmetricAlgorithmContext(ISymmetricKeyAlgorithm algorithm, byte[] key, CipherMode.Mode cipherMode, Padding.Mode paddingMode,
        [Optional] byte[] initializationVector, [Optional] params object[] additionalArguments) {
        algorithm.SetKey(key);
        algorithmBlockSize = algorithm.BlockSize;
        
        this.cipherMode = new CipherMode(cipherMode, algorithm, initializationVector);
        padding = new Padding(paddingMode, algorithmBlockSize);
    }

    public async Task<byte[]> Encrypt(byte[] data) {
        byte[] paddedData = padding.Apply(data);
        return await cipherMode.Encrypt(paddedData);
    }

    public async Task<byte[]> Decrypt(byte[] data) {
        if (data.Length % algorithmBlockSize != 0) {
            throw new ArgumentException("Data length must be multiple of block size");
        }

        byte[] decrypted = await cipherMode.Decrypt(data);
        return padding.Remove(decrypted);
    }

    public async Task Encrypt(string inputFilepath, string outputFilepath) {
        const int bufferSize = 1 << 23;
        byte[] buffer = new byte[bufferSize];

        await using FileStream input = new(inputFilepath, FileMode.Open, FileAccess.Read);
        await using FileStream output = new(outputFilepath, FileMode.Create, FileAccess.Write);

        int bytesRead;
        while ((bytesRead = await input.ReadAsync(buffer.AsMemory(0, bufferSize))) > 0) {
            byte[] dataChunk = new byte[bytesRead];
            Buffer.BlockCopy(buffer, 0, dataChunk, 0, bytesRead);

            byte[] encrypted;
            if (cipherMode.CurrentMode != CipherMode.Mode.RandomDelta)
                encrypted = await EncryptParallel(dataChunk);
            else
                encrypted = await Encrypt(dataChunk);
            
            await output.WriteAsync(encrypted);
        }
    }

    public async Task Decrypt(string inputFilepath, string outputFilepath) {
        const int bufferSize = 1 << 23;
        byte[] buffer = new byte[bufferSize];

        await using FileStream input = new(inputFilepath, FileMode.Open, FileAccess.Read);
        await using FileStream output = new(outputFilepath, FileMode.Create, FileAccess.Write);

        int bytesRead;
        while ((bytesRead = await input.ReadAsync(buffer.AsMemory(0, bufferSize))) > 0) {
            if (bytesRead % algorithmBlockSize != 0) {
                throw new InvalidDataException("Encrypted data size must be multiple of block size");
            }
            
            byte[] dataChunk = new byte[bytesRead];
            Buffer.BlockCopy(buffer, 0, dataChunk, 0, bytesRead);
            
            byte[] decrypted;
            if (cipherMode.CurrentMode != CipherMode.Mode.RandomDelta)
                decrypted = await DecryptParallel(dataChunk);
            else
                decrypted = await Decrypt(dataChunk);
            
            await output.WriteAsync(padding.Remove(decrypted));
        }
    }

    async Task<byte[]> EncryptParallel(byte[] data) {
        byte[] paddedData = padding.Apply(data);
        int blockSize = algorithmBlockSize;
        int blockCount = paddedData.Length / blockSize;
        byte[] result = new byte[paddedData.Length];

        await Task.Run(() => {
            Parallel.For(0, blockCount, (i) => {
                byte[] block = new byte[blockSize];
                Buffer.BlockCopy(paddedData, i * blockSize, block, 0, blockSize);
                
                byte[] encryptedBlock = cipherMode.Encrypt(block).Result;
                Buffer.BlockCopy(encryptedBlock, 0, result, i * blockSize, blockSize);
            });
        });

        return result;
    }

    async Task<byte[]> DecryptParallel(byte[] data) {
        int blockSize = algorithmBlockSize;
        int blockCount = data.Length / blockSize;
        byte[] result = new byte[data.Length];

        await Task.Run(() => {
            Parallel.For(0, blockCount, (i) => {
                byte[] block = new byte[blockSize];
                Buffer.BlockCopy(data, i * blockSize, block, 0, blockSize);
                
                byte[] decryptedBlock = cipherMode.Decrypt(block).Result;
                Buffer.BlockCopy(decryptedBlock, 0, result, i * blockSize, blockSize);
            });
        });

        return result;
    }
}