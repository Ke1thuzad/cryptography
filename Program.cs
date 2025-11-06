using Cryptography.DES.Context;

namespace Cryptography;

using Cryptography.DES.Encryption;

internal class Program
{
    static void Main(string[] args) {
        Des des = new();

        // byte[] key = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        byte[] key = [119, 99, 111, 30, 241, 164, 43, 34];

        // byte[] iv = (byte[])key.Clone();
        byte[] iv = [165, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        
        SymmetricAlgorithmContext context = new(des, key, CipherMode.Mode.ECB, Padding.Mode.PKCS7, iv);

        // context.Encrypt("test", "encryptedTest").Wait();
        //
        // context.Decrypt("encryptedTest", "decryptedTes").Wait();

        context.Encrypt("qewrew.mp4", "encryptedqewrew").Wait();
        
        context.Decrypt("encryptedqewrew", "decryptedqewrew.mp4").Wait();
        // context.Decrypt("image_encrypted.bin", "decrypted_image.jpg").Wait();
    }
}