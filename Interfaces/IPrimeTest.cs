using System.Numerics;

namespace Cryptography;

public interface IPrimeTest
{
    bool IsProbablyPrime(BigInteger n, double minProbability);
    double ActualProbability { get; }
    int IterationsCount { get; }
}