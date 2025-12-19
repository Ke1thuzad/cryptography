using Cryptography.Context.Symmetric;
using Cryptography.SymmetricAlgorithms.DES;

namespace Tests.CipherAlgorithms;

public class DesTests : TestBase
{
    [Theory]
    [MemberData(nameof(TestData.GetBlockCipherParams), MemberType = typeof(TestData))]
    public async Task Des_EncryptDecrypt_AllModes(CipherMode.Mode mode, Padding.Mode padding)
    {
        byte[] key = new byte[8];
        byte[] iv = new byte[8];
        Random.Shared.NextBytes(key);
        Random.Shared.NextBytes(iv);

        var des = new Des();
        var context = new SymmetricAlgorithmContext(des, key, mode, padding, iv);

        string inputFile = CreateTempFile("DES Data " + Guid.NewGuid());
        string encFile = GetTempFilePath();
        string decFile = GetTempFilePath();

        await context.Encrypt(inputFile, encFile);
        await context.Decrypt(encFile, decFile);

        await AssertFilesEqual(inputFile, decFile, padding);
    }

    [Fact]
    public async Task Des_EmptyFile_HandledCorrectly()
    {
        byte[] key = new byte[8];
        byte[] iv = new byte[8];
        Random.Shared.NextBytes(key);
        Random.Shared.NextBytes(iv);

        var des = new Des();
        var context = new SymmetricAlgorithmContext(des, key, CipherMode.Mode.ECB, Padding.Mode.PKCS7, iv);

        string inputFile = CreateEmptyTempFile();
        string encFile = GetTempFilePath();
        string decFile = GetTempFilePath();

        await context.Encrypt(inputFile, encFile);
        await context.Decrypt(encFile, decFile);

        await AssertFilesEqual(inputFile, decFile, Padding.Mode.PKCS7);
    }
}