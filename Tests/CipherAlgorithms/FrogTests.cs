using Cryptography.Context.Symmetric;
using Cryptography.SymmetricAlgorithms.FROG;

namespace Tests.CipherAlgorithms;

public class FrogTests : TestBase
{
    [Theory]
    [MemberData(nameof(TestData.GetBlockCipherParams), MemberType = typeof(TestData))]
    public async Task Frog16_EncryptDecrypt_AllModes(CipherMode.Mode mode, Padding.Mode padding)
    {
        byte[] key = new byte[32]; 
        byte[] iv = new byte[16];
        Random.Shared.NextBytes(key);
        Random.Shared.NextBytes(iv);

        var frog = new Frog(16);
        var context = new SymmetricAlgorithmContext(frog, key, mode, padding, iv);

        string inputFile = CreateTempFile("FROG Standard Data");
        string encFile = GetTempFilePath();
        string decFile = GetTempFilePath();

        await context.Encrypt(inputFile, encFile);
        await context.Decrypt(encFile, decFile);

        await AssertFilesEqual(inputFile, decFile, padding);
    }

    [Fact]
    public async Task Frog32_EncryptDecrypt_CustomBlockSize()
    {
        byte[] key = new byte[64];
        byte[] iv = new byte[32];
        Random.Shared.NextBytes(key);
        Random.Shared.NextBytes(iv);

        var frog = new Frog(32);
        var context = new SymmetricAlgorithmContext(frog, key, CipherMode.Mode.ECB, Padding.Mode.PKCS7, iv);

        string inputFile = CreateTempFile("FROG 32-byte Block Data");
        string encFile = GetTempFilePath();
        string decFile = GetTempFilePath();

        await context.Encrypt(inputFile, encFile);
        await context.Decrypt(encFile, decFile);

        await AssertFilesEqual(inputFile, decFile, Padding.Mode.PKCS7);
    }
}