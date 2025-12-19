using System.Numerics;
using Cryptography.Utility;

namespace Tests.Utility;

public class MathAlgorithmsTests
{
    [Theory]
    [InlineData("2", "7", 1)]
    [InlineData("3", "7", -1)]
    [InlineData("0", "7", 0)]
    [InlineData("14", "7", 0)]
    [InlineData("5", "11", 1)]
    [InlineData("7", "11", -1)]
    public void LegendreSymbol_ReturnsCorrectValue(string aStr, string pStr, int expected)
    {
        var a = BigInteger.Parse(aStr);
        var p = BigInteger.Parse(pStr);
        var result = MathAlgorithms.LegendreSymbol(a, p);
        Assert.Equal(expected, result);
    }

    [Fact]
    public void LegendreSymbol_ThrowsForEvenPrime()
    {
        Assert.Throws<ArgumentException>(() => 
            MathAlgorithms.LegendreSymbol(2, 4));
    }

    [Theory]
    [InlineData("2", "15", 1)]
    [InlineData("7", "15", -1)]
    [InlineData("3", "15", 0)]
    [InlineData("1001", "9907", -1)]
    [InlineData("123456789", "987654321", 0)]
    public void JacobiSymbol_ReturnsCorrectValue(string aStr, string nStr, int expected)
    {
        var a = BigInteger.Parse(aStr);
        var n = BigInteger.Parse(nStr);
        var result = MathAlgorithms.JacobiSymbol(a, n);
        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData("48", "18", "6")]
    [InlineData("17", "5", "1")]
    [InlineData("0", "5", "5")]
    [InlineData("0", "0", "0")]
    [InlineData("-12", "18", "6")]
    [InlineData("1071", "462", "21")]
    [InlineData("12345678901234567890", "98765432109876543210", "900000000090")]
    public void Gcd_ReturnsCorrectValue(string aStr, string bStr, string expectedStr)
    {
        var a = BigInteger.Parse(aStr);
        var b = BigInteger.Parse(bStr);
        var expected = BigInteger.Parse(expectedStr);
        var result = MathAlgorithms.Gcd(a, b);
        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData("240", "46", "2")]
    [InlineData("17", "5", "1")]
    [InlineData("54", "24", "6")]
    [InlineData("12345", "6789", "3")]
    [InlineData("123456789012345", "98765432109876", "3")]
    public void ExtendedGcd_ReturnsCorrectGcdAndBezout(string aStr, string bStr, string expectedGcdStr)
    {
        var a = BigInteger.Parse(aStr);
        var b = BigInteger.Parse(bStr);
        var expectedGcd = BigInteger.Parse(expectedGcdStr);
        
        var (gcd, x, y) = MathAlgorithms.ExtendedGcd(a, b);
        
        Assert.Equal(expectedGcd, gcd);
        // Проверяем условие Безу
        Assert.Equal(gcd, a * x + b * y);
    }

    [Theory]
    [InlineData("3", "4", "5", "1")]
    [InlineData("2", "10", "7", "2")]
    [InlineData("5", "3", "13", "8")]
    [InlineData("7", "0", "11", "1")]
    [InlineData("123", "456", "789", "699")]
    [InlineData("123456789", "987654321", "1000000007", "652541198")]
    public void ModExp_ReturnsCorrectValue(string aStr, string pStr, string mStr, string expectedStr)
    {
        var a = BigInteger.Parse(aStr);
        var p = BigInteger.Parse(pStr);
        var m = BigInteger.Parse(mStr);
        var expected = BigInteger.Parse(expectedStr);
        
        var result = MathAlgorithms.ModExp(a, p, m);
        Assert.Equal(expected, result);
    }
}