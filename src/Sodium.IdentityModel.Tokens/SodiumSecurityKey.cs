using System;
using Microsoft.IdentityModel.Tokens;

namespace Sodium.IdentityModel.Tokens
{
    public sealed class SodiumSecurityKey : AsymmetricSecurityKey, IDisposable
    {
        public static SodiumSecurityKey FromPrivateKey(byte[] privateKey)
        {
            if (privateKey == null)
                throw new ArgumentNullException(nameof(privateKey));

            var publicKey = PublicKeyAuth.ExtractEd25519PublicKeyFromEd25519SecretKey(privateKey);
            return new SodiumSecurityKey(privateKey, publicKey);
        }

        private SodiumSecurityKey()
        {
            CryptoProviderFactory.CustomCryptoProvider = new SodiumCryptoProvider();
        }

        public SodiumSecurityKey(byte[] publicKey)
            : this()
        {
            PublicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
        }

        public SodiumSecurityKey(byte[] privateKey, byte[] publicKey)
            : this()
        {
            PrivateKey = privateKey ?? throw new ArgumentNullException(nameof(privateKey));
            PublicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
        }

        public string Curve => SodiumAlgorithms.Ed25519;

        public byte[] PublicKey { get; }

        internal byte[] PrivateKey { get; }

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
        }
    }
}
