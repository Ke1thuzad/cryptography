using System.Numerics;
using Cryptography.AsymmetricAlgorithms.DiffieHellman;

namespace Tests.CipherAlgorithms;

public class DiffieHellmanTests
{
    [Fact]
    public void DiffieHellman_Group14_ExchangeSuccess()
    {
        var group = DiffieHellmanGroup.Group14;
        var alice = new DiffieHellman(group);
        var bob = new DiffieHellman(group);

        BigInteger aPriv = alice.GeneratePrivateKey();
        BigInteger bPriv = bob.GeneratePrivateKey();

        BigInteger aPub = alice.CalculatePublicKey(aPriv);
        BigInteger bPub = bob.CalculatePublicKey(bPriv);

        BigInteger aSecret = alice.CalculateSharedSecret(bPub, aPriv);
        BigInteger bSecret = bob.CalculateSharedSecret(aPub, bPriv);

        Assert.Equal(aSecret, bSecret);
        Assert.True(aSecret > 0);

        byte[] keyA = alice.DeriveSymmetricKey(aSecret, 32);
        byte[] keyB = bob.DeriveSymmetricKey(bSecret, 32);

        Assert.Equal(keyA, keyB);
        Assert.Equal(32, keyA.Length);
    }
}