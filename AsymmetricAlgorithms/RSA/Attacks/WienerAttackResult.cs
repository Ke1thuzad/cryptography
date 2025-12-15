using System.Numerics;

namespace Cryptography.AsymmetricAlgorithms.RSA.Attacks;

public record struct Fraction(BigInteger Numerator, BigInteger Denominator)
{
    public override string ToString() => $"{Numerator}/{Denominator}";
}

public class WienerAttackResult
{
    public bool Success { get; init; }
    public BigInteger D { get; init; }
    public BigInteger Phi { get; init; }
    public List<Fraction> Convergents { get; init; } = new();
    public TimeSpan Duration { get; init; }
}