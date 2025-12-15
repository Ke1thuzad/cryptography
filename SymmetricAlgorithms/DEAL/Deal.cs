using Cryptography.SymmetricAlgorithms.DEAL.Adapters;
using Cryptography.SymmetricAlgorithms.DES;

namespace Cryptography.SymmetricAlgorithms.DEAL
{
    public class Deal : ISymmetricKeyAlgorithm
    {
        readonly FeistelNetwork _feistelNetwork;
        readonly int _keySize;
        
        public int BlockSize => 16;

        public Deal(int keySize = 16)
        {
            if (keySize != 16 && keySize != 24 && keySize != 32)
                throw new ArgumentException("Key size must be 16 (DEAL-128), 24 (DEAL-192), or 32 (DEAL-256) bytes");

            _keySize = keySize;
            
            DesBlockCipherAdapter desAdapter = new();
            
            DealKeyExpander keyExpander = new(desAdapter, _keySize);
            DealFeistel cipherTransform = new(desAdapter);
            
            _feistelNetwork = new FeistelNetwork(cipherTransform, keyExpander);
        }

        public Deal(IKeyExpander keyExpander, ICipherTransform cipherTransform, int keySize = 16)
        {
            _keySize = keySize;
            _feistelNetwork = new FeistelNetwork(cipherTransform, keyExpander);
        }

        public void SetKey(byte[] key)
        {
            if (key.Length != _keySize)
                throw new ArgumentException($"Key must be {_keySize} bytes for DEAL-{_keySize * 8}");

            _feistelNetwork.Key = key;
        }

        public Task<byte[]> Encrypt(byte[] block)
        {
            if (_feistelNetwork.Key == null)
                throw new InvalidOperationException("Key not set. Call SetKey first.");

            if (block.Length != BlockSize)
                throw new ArgumentException($"Block size must be {BlockSize} bytes");

            byte[] result = _feistelNetwork.ProcessRounds(block, encrypt: true);
            return Task.FromResult(result);
        }

        public Task<byte[]> Decrypt(byte[] block)
        {
            if (_feistelNetwork.Key == null)
                throw new InvalidOperationException("Key not set. Call SetKey first.");

            if (block.Length != BlockSize)
                throw new ArgumentException($"Block size must be {BlockSize} bytes");

            byte[] result = _feistelNetwork.ProcessRounds(block, encrypt: false);
            return Task.FromResult(result);
        }
    }
}