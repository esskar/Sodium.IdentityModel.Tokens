using Microsoft.IdentityModel.Tokens;

namespace Sodium.IdentityModel.Tokens
{
    internal class SodiumSignatureProvider : SignatureProvider
    {
        public SodiumSignatureProvider(SodiumSecurityKey key, string algorithm)
            : base(key, algorithm) { }

        public override byte[] Sign(byte[] input)
            => PublicKeyAuth.SignDetached(input, ((SodiumSecurityKey)Key).PrivateKey);

        public override bool Verify(byte[] input, byte[] signature)
            => PublicKeyAuth.VerifyDetached(signature, input, ((SodiumSecurityKey)Key).PublicKey);
        protected override void Dispose(bool disposing)
        {
            if (disposing)
                ((SodiumSecurityKey)Key).Dispose();
        }
    }
}
