using System.Numerics;
using Cryptography.Utility;

namespace Cryptography.AsymmetricAlgorithms.RSA.PrimeTests;

public class SolovayStrassenPrimeTest : PrimeTestBase
{
    protected override int CalculateIterationsCount(double minProbability) => (int)Math.Ceiling(Math.Log(1.0 / (1.0 - minProbability), 2));

    protected override bool PerformSingleTest(BigInteger n, BigInteger a)
    {
        BigInteger exponent = (n - 1) / 2;
        BigInteger euler = MathAlgorithms.ModExp(a, exponent, n);

        int jacobi = MathAlgorithms.JacobiSymbol(a, n);

        if (jacobi == 0) return false;

        BigInteger jacobiBig = jacobi == -1 ? n - 1 : 1;

        return euler == jacobiBig;
    }
}