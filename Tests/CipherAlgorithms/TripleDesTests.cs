using Cryptography.SymmetricAlgorithms.TripleDES;

namespace Tests.CipherAlgorithms;

public class TripleDesTests
{
    [Fact]
    public void Constructor_Default_ShouldNotThrow()
    {
        var tripleDes = new TripleDes();
        Assert.NotNull(tripleDes);
    }

    [Fact]
    public void Constructor_ThreeKeysTrue_ShouldCreateThreeInstances()
    {
        var tripleDes = new TripleDes(useThreeKeys: true);
        Assert.NotNull(tripleDes);
    }

    [Fact]
    public void Constructor_ThreeKeysFalse_ShouldCreateTwoInstances()
    {
        var tripleDes = new TripleDes(useThreeKeys: false);
        Assert.NotNull(tripleDes);
    }

    [Theory]
    [InlineData(true, 21)]
    [InlineData(true, 24)]
    [InlineData(false, 14)]
    [InlineData(false, 16)]
    public void SetKey_ValidKeyLength_ShouldNotThrow(bool useThreeKeys, int keySize)
    {
        var tripleDes = new TripleDes(useThreeKeys);
        var key = new byte[keySize];
        tripleDes.SetKey(key);
    }

    [Theory]
    [InlineData(true, 20)]
    [InlineData(true, 25)]
    [InlineData(false, 13)]
    [InlineData(false, 17)]
    public void SetKey_InvalidKeyLength_ShouldThrow(bool useThreeKeys, int keySize)
    {
        var tripleDes = new TripleDes(useThreeKeys);
        var key = new byte[keySize];
        Assert.Throws<ArgumentException>(() => tripleDes.SetKey(key));
    }

    [Fact]
    public async Task Encrypt_WithoutSetKey_ShouldThrow()
    {
        var tripleDes = new TripleDes();
        var block = new byte[8];
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await tripleDes.Encrypt(block));
    }

    [Fact]
    public async Task Decrypt_WithoutSetKey_ShouldThrow()
    {
        var tripleDes = new TripleDes();
        var block = new byte[8];
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await tripleDes.Decrypt(block));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task EncryptDecrypt_SingleBlock_ShouldReturnOriginal(bool useThreeKeys)
    {
        var tripleDes = new TripleDes(useThreeKeys);
        var keySize = useThreeKeys ? 24 : 16;
        var key = new byte[keySize];
        new Random(42).NextBytes(key);
        tripleDes.SetKey(key);
        
        var original = new byte[8];
        new Random(42).NextBytes(original);

        var encrypted = await tripleDes.Encrypt(original);
        var decrypted = await tripleDes.Decrypt(encrypted);

        Assert.Equal(original, decrypted);
    }

    [Fact]
    public void BlockSize_ShouldReturn8()
    {
        var tripleDes = new TripleDes();
        Assert.Equal(8, tripleDes.BlockSize);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Encrypt_DifferentKeys_ShouldProduceDifferentResults(bool useThreeKeys)
    {
        var tripleDes1 = new TripleDes(useThreeKeys);
        var tripleDes2 = new TripleDes(useThreeKeys);
        
        var keySize = useThreeKeys ? 24 : 16;
        var key1 = new byte[keySize];
        var key2 = new byte[keySize];
        
        new Random(42).NextBytes(key1);
        new Random(43).NextBytes(key2);

        tripleDes1.SetKey(key1);
        tripleDes2.SetKey(key2);
        
        var original = new byte[8];
        new Random(42).NextBytes(original);

        var encrypted1 = await tripleDes1.Encrypt(original);
        var encrypted2 = await tripleDes2.Encrypt(original);

        Assert.NotEqual(encrypted1, encrypted2);
    }
}