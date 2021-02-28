using System;
using System.Linq;
using Microsoft.IdentityModel.Tokens;

namespace Sodium.IdentityModel.Tokens
{
    public class SodiumCryptoProvider : ICryptoProvider
    {
        public bool IsSupportedAlgorithm(string algorithm, params object[] args)
            => GetSecurityKey(algorithm, args) != null;

        public object Create(string algorithm, params object[] args)
        {
            var key = GetSecurityKey(algorithm, args);
            if (key == null)
                throw new NotSupportedException();
            return new SodiumSignatureProvider(key, algorithm);
        }

        public void Release(object cryptoInstance)
        {
            if (cryptoInstance is IDisposable disposable)
                disposable.Dispose();
        }

        private static SodiumSecurityKey? GetSecurityKey(string algorithm, params object[] args)
        {
            if (algorithm == SodiumAlgorithms.EdDsa && args.FirstOrDefault() is SodiumSecurityKey key)
                return key;
            return null;
        }
    }
}
