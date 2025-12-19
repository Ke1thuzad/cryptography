using Cryptography;
using Cryptography.Context.Symmetric;
using Xunit;

namespace Tests.Context;

public class SymmetricAlgorithmContextTests
{
    class TestSymmetricAlgorithm : ISymmetricKeyAlgorithm
    {
        byte[] key;
        public int BlockSize => 8;

        public void SetKey(byte[] key) => this.key = key;

        public Task<byte[]> Encrypt(byte[] block)
        {
            var result = new byte[block.Length];
            for (int i = 0; i < block.Length; i++)
                result[i] = (byte)(block[i] ^ key[i % key.Length]);
            return Task.FromResult(result);
        }

        public Task<byte[]> Decrypt(byte[] block) => Encrypt(block);
    }

    [Theory]
    [InlineData(CipherMode.Mode.ECB, null)]
    [InlineData(CipherMode.Mode.CBC, new byte[] { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 })]
    [InlineData(CipherMode.Mode.PCBC, new byte[] { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 })]
    [InlineData(CipherMode.Mode.CFB, new byte[] { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 })]
    [InlineData(CipherMode.Mode.OFB, new byte[] { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 })]
    [InlineData(CipherMode.Mode.CTR, new byte[] { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 })]
    [InlineData(CipherMode.Mode.RandomDelta, new byte[] { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 })]
    public async Task EncryptDecrypt_SingleBlock_ReturnsOriginalData(CipherMode.Mode mode, byte[] iv)
    {
        var algorithm = new TestSymmetricAlgorithm();
        var key = new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
        algorithm.SetKey(key);
        
        var context = new SymmetricAlgorithmContext(algorithm, key, mode, Padding.Mode.PKCS7, iv);
        var originalData = new byte[] { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };

        var encrypted = await context.Encrypt(originalData);
        var decrypted = await context.Decrypt(encrypted);

        Assert.Equal(originalData, decrypted);
    }

    [Theory]
    [InlineData(CipherMode.Mode.ECB, null)]
    [InlineData(CipherMode.Mode.CBC, new byte[] { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 })]
    [InlineData(CipherMode.Mode.PCBC, new byte[] { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 })]
    [InlineData(CipherMode.Mode.CFB, new byte[] { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 })]
    [InlineData(CipherMode.Mode.OFB, new byte[] { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 })]
    [InlineData(CipherMode.Mode.CTR, new byte[] { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 })]
    [InlineData(CipherMode.Mode.RandomDelta, new byte[] { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 })]
    public async Task EncryptDecrypt_MultipleBlocks_ReturnsOriginalData(CipherMode.Mode mode, byte[] iv)
    {
        var algorithm = new TestSymmetricAlgorithm();
        var key = new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
        algorithm.SetKey(key);
        
        var context = new SymmetricAlgorithmContext(algorithm, key, mode, Padding.Mode.PKCS7, iv);
        var originalData = new byte[24];
        new Random(42).NextBytes(originalData);

        var encrypted = await context.Encrypt(originalData);
        var decrypted = await context.Decrypt(encrypted);

        Assert.Equal(originalData, decrypted);
    }

    [Theory]
    [InlineData(Padding.Mode.Zeros)]
    [InlineData(Padding.Mode.ANSI_X923)]
    [InlineData(Padding.Mode.PKCS7)]
    [InlineData(Padding.Mode.ISO10126)]
    public async Task EncryptDecrypt_WithDifferentPadding_ReturnsOriginalData(Padding.Mode paddingMode)
    {
        var algorithm = new TestSymmetricAlgorithm();
        var key = new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
        algorithm.SetKey(key);
        
        var context = new SymmetricAlgorithmContext(algorithm, key, CipherMode.Mode.CBC, paddingMode, new byte[8]);
        var originalData = new byte[15];
        new Random(42).NextBytes(originalData);

        var encrypted = await context.Encrypt(originalData);
        var decrypted = await context.Decrypt(encrypted);

        Assert.Equal(originalData, decrypted);
    }

    [Fact]
    public async Task Encrypt_SamePlaintextBlocksECB_ProducesSameCiphertextBlocks()
    {
        var algorithm = new TestSymmetricAlgorithm();
        var key = new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
        algorithm.SetKey(key);
        
        var context = new SymmetricAlgorithmContext(algorithm, key, CipherMode.Mode.ECB, Padding.Mode.PKCS7, null);
        var originalData = new byte[16];
        Array.Fill(originalData, (byte)0x42);

        var encrypted = await context.Encrypt(originalData);

        Assert.Equal(encrypted[0..8], encrypted[8..16]);
    }

    [Fact]
    public async Task Encrypt_DifferentIV_ProducesDifferentCiphertext()
    {
        var algorithm = new TestSymmetricAlgorithm();
        var key = new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
        algorithm.SetKey(key);
        
        var originalData = new byte[16];
        new Random(42).NextBytes(originalData);

        var context1 = new SymmetricAlgorithmContext(algorithm, key, CipherMode.Mode.CBC, Padding.Mode.PKCS7, new byte[] { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 });
        var context2 = new SymmetricAlgorithmContext(algorithm, key, CipherMode.Mode.CBC, Padding.Mode.PKCS7, new byte[] { 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22 });

        var encrypted1 = await context1.Encrypt(originalData);
        var encrypted2 = await context2.Encrypt(originalData);

        Assert.NotEqual(encrypted1, encrypted2);
    }

    [Fact]
    public async Task Encrypt_WithDifferentBlockSizes_WorksCorrectly()
    {
        var algorithm = new TestSymmetricAlgorithm();
        var key = new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
        algorithm.SetKey(key);
        
        var context = new SymmetricAlgorithmContext(algorithm, key, CipherMode.Mode.CFB, Padding.Mode.PKCS7, new byte[8]);

        var testSizes = new[] { 1, 7, 8, 15, 16, 23, 24, 31, 32 };

        foreach (var size in testSizes)
        {
            var originalData = new byte[size];
            new Random(size).NextBytes(originalData);

            var encrypted = await context.Encrypt(originalData);
            var decrypted = await context.Decrypt(encrypted);
            
            Assert.Equal(originalData, decrypted);
        }
    }

    [Fact]
    public async Task EncryptionAndDecryption_UseSameKeystream()
    {
        var algorithm = new TestSymmetricAlgorithm();
        var key = new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
        algorithm.SetKey(key);
        
        var context = new SymmetricAlgorithmContext(algorithm, key, CipherMode.Mode.OFB, Padding.Mode.PKCS7, new byte[8]);
        var originalData = new byte[24];
        new Random(42).NextBytes(originalData);

        var encrypted = await context.Encrypt(originalData);
        var modifiedCiphertext = (byte[])encrypted.Clone();
        modifiedCiphertext[0] ^= 0x01;
        
        var decryptedOriginal = await context.Decrypt(encrypted);
        var decryptedModified = await context.Decrypt(modifiedCiphertext);

        Assert.Equal(originalData, decryptedOriginal);
        Assert.Equal(originalData[0] ^ 0x01, decryptedModified[0]);
        Assert.Equal(originalData[1], decryptedModified[1]);
    }

    [Fact]
    public async Task Encrypt_ParallelExecution_ProducesCorrectResult()
    {
        var algorithm = new TestSymmetricAlgorithm();
        var key = new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
        algorithm.SetKey(key);
        
        var context = new SymmetricAlgorithmContext(algorithm, key, CipherMode.Mode.CTR, Padding.Mode.PKCS7, new byte[8]);
        var originalData = new byte[1000];
        new Random(42).NextBytes(originalData);

        var encrypted = await context.Encrypt(originalData);
        var decrypted = await context.Decrypt(encrypted);

        Assert.Equal(originalData, decrypted);
    }

    [Fact]
    public async Task Counter_IncrementsCorrectly()
    {
        var algorithm = new TestSymmetricAlgorithm();
        var key = new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
        algorithm.SetKey(key);
        
        var counter = new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE };
        var context = new SymmetricAlgorithmContext(algorithm, key, CipherMode.Mode.CTR, Padding.Mode.PKCS7, counter);
        var originalData = new byte[16];

        var encrypted = await context.Encrypt(originalData);
        var decrypted = await context.Decrypt(encrypted);
        
        Assert.Equal(originalData, decrypted);
    }

    [Fact]
    public async Task Encrypt_SameDataDifferentContext_ProducesDifferentCiphertext()
    {
        var key = new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
        var originalData = new byte[16];
        new Random(42).NextBytes(originalData);

        var algorithm1 = new TestSymmetricAlgorithm();
        algorithm1.SetKey(key);
        var context1 = new SymmetricAlgorithmContext(algorithm1, key, CipherMode.Mode.RandomDelta, Padding.Mode.PKCS7, null);

        var algorithm2 = new TestSymmetricAlgorithm();
        algorithm2.SetKey(key);
        var context2 = new SymmetricAlgorithmContext(algorithm2, key, CipherMode.Mode.RandomDelta, Padding.Mode.PKCS7, null);

        var encrypted1 = await context1.Encrypt(originalData);
        var encrypted2 = await context2.Encrypt(originalData);

        Assert.NotEqual(encrypted1, encrypted2);
    }

    [Fact]
    public async Task EmptyData_WithVariousModes_ReturnsEmpty()
    {
        var modes = new[] {
            CipherMode.Mode.ECB, CipherMode.Mode.CBC, CipherMode.Mode.CTR,
            CipherMode.Mode.CFB, CipherMode.Mode.OFB, CipherMode.Mode.PCBC,
            CipherMode.Mode.RandomDelta
        };

        foreach (var mode in modes)
        {
            var algorithm = new TestSymmetricAlgorithm();
            var key = new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
            algorithm.SetKey(key);
            
            byte[] iv = mode == CipherMode.Mode.ECB ? null : new byte[8];
            var context = new SymmetricAlgorithmContext(algorithm, key, mode, Padding.Mode.PKCS7, iv);
            var emptyData = Array.Empty<byte>();

            var encrypted = await context.Encrypt(emptyData);
            var decrypted = await context.Decrypt(encrypted);
            
            Assert.Empty(decrypted);
        }
    }

    [Fact]
    public async Task VeryLargeData_PerformanceTest()
    {
        var algorithm = new TestSymmetricAlgorithm();
        var key = new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
        algorithm.SetKey(key);
        
        var context = new SymmetricAlgorithmContext(algorithm, key, CipherMode.Mode.CTR, Padding.Mode.PKCS7, new byte[8]);
        var largeData = new byte[10 * 1024 * 1024];
        new Random(42).NextBytes(largeData);

        var encrypted = await context.Encrypt(largeData);
        var decrypted = await context.Decrypt(encrypted);
        
        Assert.Equal(largeData, decrypted);
    }

    [Fact]
    public async Task InvalidBlockSize_ThrowsException()
    {
        var algorithm = new TestSymmetricAlgorithm();
        var key = new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
        algorithm.SetKey(key);
        
        var context = new SymmetricAlgorithmContext(algorithm, key, CipherMode.Mode.CBC, Padding.Mode.PKCS7, new byte[8]);
        var invalidData = new byte[7];

        await Assert.ThrowsAsync<ArgumentException>(async () => await context.Decrypt(invalidData));
    }
}