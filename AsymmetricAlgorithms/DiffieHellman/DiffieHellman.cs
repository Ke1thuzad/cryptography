using System.Numerics;
using Cryptography.Utility;

namespace Cryptography.AsymmetricAlgorithms.DiffieHellman;

public class DiffieHellman(DiffieHellmanGroup group)
{
    readonly BigRandomNumberGenerator rng = new();
    
    public DiffieHellmanGroup Group { get; } = group;

    public BigInteger GeneratePrivateKey()
    {
        BigInteger key = rng.GetRandomBigInteger(2040);
        
        if (key <= 1)
            key = 2;
        
        return key;
    }

    public BigInteger CalculatePublicKey(BigInteger privateKey) => MathAlgorithms.ModExp(Group.G, privateKey, Group.P);

    public BigInteger CalculateSharedSecret(BigInteger otherPublicKey, BigInteger myPrivateKey) => MathAlgorithms.ModExp(otherPublicKey, myPrivateKey, Group.P);

    public byte[] DeriveSymmetricKey(BigInteger sharedSecret, int length)
    {
        byte[] bytes = sharedSecret.ToByteArray();
        byte[] key = new byte[length];
        
        int copyLen = Math.Min(bytes.Length, length);
        Array.Copy(bytes, key, copyLen);
        
        return key;
    }
}