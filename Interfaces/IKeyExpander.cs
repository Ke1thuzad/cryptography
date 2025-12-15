namespace Cryptography;

public interface IKeyExpander
{
    byte[][] ExpandKeyToRounds(byte[] key);
}