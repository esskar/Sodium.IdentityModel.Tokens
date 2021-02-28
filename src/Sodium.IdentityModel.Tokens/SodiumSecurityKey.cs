using System;
using Microsoft.IdentityModel.Tokens;

namespace Sodium.IdentityModel.Tokens
{
    public sealed class SodiumSecurityKey : AsymmetricSecurityKey, IDisposable
    {
        private const int PrivateKeyLength = 64;
        private const int PublicKeyLength = 32;

        public static SodiumSecurityKey FromPrivateKey(byte[] privateKey)
        {
            if (privateKey.Length != PrivateKeyLength)
                throw new ArgumentException($"PrivateKey needs to have a length of {PrivateKeyLength} bytes.", nameof(privateKey));

            var publicKey = PublicKeyAuth.ExtractEd25519PublicKeyFromEd25519SecretKey(privateKey);
            return new SodiumSecurityKey(privateKey, publicKey);
        }

        public static SodiumSecurityKey FromPublicKey(byte[] publicKey)
        {
            return new SodiumSecurityKey(publicKey);
        }

        private SodiumSecurityKey()
        {
            CryptoProviderFactory.CustomCryptoProvider = new SodiumCryptoProvider();
            PublicKey = null!;
        }

        private SodiumSecurityKey(byte[] publicKey)
            : this()
        {
            if (publicKey.Length != PublicKeyLength)
                throw new ArgumentException($"PublicKey needs to have a length of {PublicKeyLength} bytes.");

            PublicKey = publicKey;
        }

        private SodiumSecurityKey(byte[] privateKey, byte[] publicKey)
            : this()
        {
            if (privateKey.Length != PrivateKeyLength)
                throw new ArgumentException($"PrivateKey needs to have a length of {PrivateKeyLength} bytes.", nameof(privateKey));

            if (publicKey.Length != PublicKeyLength)
                throw new ArgumentException($"PublicKey needs to have a length of {PublicKeyLength} bytes.", nameof(publicKey));

            PrivateKey = (byte[])privateKey.Clone();
            PublicKey = publicKey;
        }

        public string Curve => SodiumAlgorithms.Ed25519;

        public byte[] PublicKey { get; }

        internal byte[]? PrivateKey { get; private set; }

        public override int KeySize => PublicKey.Length;

        [Obsolete("HasPrivateKey method is deprecated, please use PrivateKeyStatus instead.")]
        public override bool HasPrivateKey => PrivateKeyStatus == PrivateKeyStatus.Exists;

        public override PrivateKeyStatus PrivateKeyStatus
            => PrivateKey != null ? PrivateKeyStatus.Exists : PrivateKeyStatus.DoesNotExist;

        public void Dispose()
        {
            if (PrivateKey == null) 
                return;

            Array.Clear(PrivateKey, 0, PrivateKey.Length);
            PrivateKey = null;
        }
    }
}
