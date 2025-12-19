using Cryptography.Context.Symmetric;
using Cryptography.SymmetricAlgorithms.AESRijndael;

namespace Tests.CipherAlgorithms;

public class AesTests : TestBase
{
    [Theory]
    [MemberData(nameof(TestData.GetBlockCipherParams), MemberType = typeof(TestData))]
    public async Task Aes256_EncryptDecrypt_AllModes(CipherMode.Mode mode, Padding.Mode padding) {
        byte[] key = new byte[32];
        byte[] iv = new byte[32];
        Random.Shared.NextBytes(key);
        Random.Shared.NextBytes(iv);
        var aes = new Rijndael(256);
        var context = new SymmetricAlgorithmContext(aes, key, mode, padding, iv);

        string inputFile = CreateTempFile("AES 256 Data " + Guid.NewGuid());
        string encFile = GetTempFilePath();
        string decFile = GetTempFilePath();

        await context.Encrypt(inputFile, encFile);
        await context.Decrypt(encFile, decFile);

        await AssertFilesEqual(inputFile, decFile, padding);
    }

    [Fact]
    public void Aes_InvalidKeySize_ThrowsException() {
        var aes = new Rijndael(128);
        byte[] invalidKey = new byte[10];
        Assert.Throws<ArgumentException>(() => aes.SetKey(invalidKey));
    }
}