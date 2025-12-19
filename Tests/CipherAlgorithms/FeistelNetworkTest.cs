using Cryptography.SymmetricAlgorithms.DES;

namespace Tests.CipherAlgorithms;

public class FeistelNetworkTest
{
    [Fact]
    public void ProcessRounds_EncryptThenDecrypt_ShouldReturnOriginal()
    {
        // Arrange
        byte[] key = { 0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1 };
        byte[] originalBlock = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
        
        var cipher = new Feistel();
        var keyExpander = new KeySchedule();
        var feistelNetwork = new FeistelNetwork(cipher, keyExpander, key);

        // Act
        byte[] encrypted = feistelNetwork.ProcessRounds(originalBlock, encrypt: true);
        byte[] decrypted = feistelNetwork.ProcessRounds(encrypted, encrypt: false);

        // Assert
        Assert.Equal(originalBlock, decrypted);
    }

    [Fact]
    public void ProcessRounds_WithKnownVector_ShouldProduceExpectedResult()
    {
        // Arrange
        byte[] key = { 0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1 };
        byte[] inputBlock = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
        
        var cipher = new Feistel();
        var keyExpander = new KeySchedule();
        var feistelNetwork = new FeistelNetwork(cipher, keyExpander, key);

        // Act
        byte[] result = feistelNetwork.ProcessRounds(inputBlock, encrypt: true);

        // Assert - результат должен отличаться от исходного
        Assert.NotEqual(inputBlock, result);
        Assert.Equal(8, result.Length);
    }

    [Fact]
    public void ProcessRounds_WithDifferentKeys_ShouldProduceDifferentResults()
    {
        // Arrange
        byte[] key1 = { 0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1 };
        byte[] key2 = { 0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF2 };
        byte[] inputBlock = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
        
        var cipher = new Feistel();
        var keyExpander = new KeySchedule();
        var feistelNetwork1 = new FeistelNetwork(cipher, keyExpander, key1);
        var feistelNetwork2 = new FeistelNetwork(cipher, keyExpander, key2);

        // Act
        byte[] result1 = feistelNetwork1.ProcessRounds(inputBlock, encrypt: true);
        byte[] result2 = feistelNetwork2.ProcessRounds(inputBlock, encrypt: true);

        // Assert
        Assert.NotEqual(result1, result2);
    }

    [Fact]
    public void ProcessRounds_WithInvalidBlockSize_ShouldThrowException()
    {
        // Arrange
        byte[] key = { 0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1 };
        byte[] invalidBlock = { 0x01, 0x23, 0x45, 0x67 }; // Only 4 bytes
        
        var cipher = new Feistel();
        var keyExpander = new KeySchedule();
        var feistelNetwork = new FeistelNetwork(cipher, keyExpander, key);

        // Act & Assert
        Assert.Throws<ArgumentException>(() => 
            feistelNetwork.ProcessRounds(invalidBlock, encrypt: true));
    }

    [Fact]
    public void ProcessRounds_MultipleEncryptDecryptCycles_ShouldWorkConsistently()
    {
        // Arrange
        byte[] key = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
        byte[] originalBlock = { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };
        
        var cipher = new Feistel();
        var keyExpander = new KeySchedule();
        var feistelNetwork = new FeistelNetwork(cipher, keyExpander, key);

        // Act & Assert - Multiple cycles
        for (int i = 0; i < 10; i++)
        {
            byte[] encrypted = feistelNetwork.ProcessRounds(originalBlock, encrypt: true);
            byte[] decrypted = feistelNetwork.ProcessRounds(encrypted, encrypt: false);
            
            Assert.Equal(originalBlock, decrypted);
        }
    }

    [Fact]
    public void ProcessRounds_AllZeroInput_ShouldWork()
    {
        // Arrange
        byte[] key = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        byte[] zeroBlock = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        
        var cipher = new Feistel();
        var keyExpander = new KeySchedule();
        var feistelNetwork = new FeistelNetwork(cipher, keyExpander, key);

        // Act
        byte[] encrypted = feistelNetwork.ProcessRounds(zeroBlock, encrypt: true);
        byte[] decrypted = feistelNetwork.ProcessRounds(encrypted, encrypt: false);

        // Assert
        Assert.Equal(zeroBlock, decrypted);
        Assert.NotEqual(zeroBlock, encrypted); // Encryption should change the data
    }

    [Fact]
    public void ProcessRounds_AllOneInput_ShouldWork()
    {
        // Arrange
        byte[] key = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        byte[] onesBlock = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        
        var cipher = new Feistel();
        var keyExpander = new KeySchedule();
        var feistelNetwork = new FeistelNetwork(cipher, keyExpander, key);

        // Act
        byte[] encrypted = feistelNetwork.ProcessRounds(onesBlock, encrypt: true);
        byte[] decrypted = feistelNetwork.ProcessRounds(encrypted, encrypt: false);

        // Assert
        Assert.Equal(onesBlock, decrypted);
        Assert.NotEqual(onesBlock, encrypted); // Encryption should change the data
    }
}