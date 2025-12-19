using Cryptography.SymmetricAlgorithms.DEAL;

namespace Tests.CipherAlgorithms;

public class DealTests
{
    [Theory]
    [InlineData(16)]
    [InlineData(24)]
    [InlineData(32)]
    public void Constructor_ValidKeySizes_ShouldNotThrow(int keySize)
    {
        Deal deal = new Deal(keySize);
        Assert.NotNull(deal);
    }

    [Fact]
    public void Constructor_InvalidKeySize_ShouldThrow()
    {
        Assert.Throws<ArgumentException>(() => new Deal(20));
    }

    [Theory]
    [InlineData(16)]
    [InlineData(24)]
    [InlineData(32)]
    public void SetKey_ValidKeyLength_ShouldNotThrow(int keySize)
    {
        var deal = new Deal(keySize);
        var key = new byte[keySize];
        deal.SetKey(key);
    }

    [Theory]
    [InlineData(16, 15)]
    [InlineData(16, 17)]
    [InlineData(24, 23)]
    [InlineData(24, 25)]
    [InlineData(32, 31)]
    [InlineData(32, 33)]
    public void SetKey_InvalidKeyLength_ShouldThrow(int expectedSize, int actualSize)
    {
        var deal = new Deal(expectedSize);
        var key = new byte[actualSize];
        Assert.Throws<ArgumentException>(() => deal.SetKey(key));
    }

    [Fact]
    public async Task Encrypt_WithoutSetKey_ShouldThrow()
    {
        var deal = new Deal(16);
        var block = new byte[16];
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await deal.Encrypt(block));
    }

    [Fact]
    public async Task Decrypt_WithoutSetKey_ShouldThrow()
    {
        var deal = new Deal(16);
        var block = new byte[16];
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await deal.Decrypt(block));
    }

    [Theory]
    [InlineData(15)]
    [InlineData(17)]
    public async Task Encrypt_InvalidBlockSize_ShouldThrow(int blockSize)
    {
        var deal = new Deal(16);
        var key = new byte[16];
        deal.SetKey(key);
        var block = new byte[blockSize];
        await Assert.ThrowsAsync<ArgumentException>(async () => await deal.Encrypt(block));
    }

    [Theory]
    [InlineData(15)]
    [InlineData(17)]
    public async Task Decrypt_InvalidBlockSize_ShouldThrow(int blockSize)
    {
        var deal = new Deal(16);
        var key = new byte[16];
        deal.SetKey(key);
        var block = new byte[blockSize];
        await Assert.ThrowsAsync<ArgumentException>(async () => await deal.Decrypt(block));
    }

    [Theory]
    [InlineData(16)]
    [InlineData(24)]
    [InlineData(32)]
    public async Task EncryptDecrypt_SingleBlock_ShouldReturnOriginal(int keySize)
    {
        var deal = new Deal(keySize);
        var key = new byte[keySize];
        new Random(42).NextBytes(key);
        deal.SetKey(key);
        
        var original = new byte[16];
        new Random(42).NextBytes(original);

        var encrypted = await deal.Encrypt(original);
        var decrypted = await deal.Decrypt(encrypted);

        Assert.Equal(original, decrypted);
    }


    [Fact]
    public void BlockSize_ShouldReturn16()
    {
        var deal = new Deal(16);
        Assert.Equal(16, deal.BlockSize);
    }
}