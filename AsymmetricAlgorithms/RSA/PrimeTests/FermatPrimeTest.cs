using System.Numerics;

namespace Cryptography.AsymmetricAlgorithms.RSA.PrimeTests;

public class FermatPrimeTest : PrimeTestBase
{
    protected override int CalculateIterationsCount(double minProbability) => (int)Math.Ceiling(Math.Log(1.0 / (1.0 - minProbability), 2));

    protected override bool PerformSingleTest(BigInteger n, BigInteger a) => BigInteger.ModPow(a, n - 1, n) == 1;
}