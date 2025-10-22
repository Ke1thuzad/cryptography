namespace Cryptography.DES;

public interface IKeyExpander
{
    byte[][] ExpandKeyToRounds(byte[] key);
}