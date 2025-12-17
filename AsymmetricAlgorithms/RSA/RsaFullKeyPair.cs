using System.Numerics;
using Cryptography.Context.Asymmetric;

namespace Cryptography.AsymmetricAlgorithms.RSA;

public record class RsaFullKeyPair(
    BigInteger E, 
    BigInteger D, 
    BigInteger N, 
    BigInteger P, 
    BigInteger Q, 
    BigInteger DP, 
    BigInteger DQ, 
    BigInteger QInv
) : AsymmetricKeyPair;