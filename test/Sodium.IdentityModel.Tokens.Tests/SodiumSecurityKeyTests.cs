using System;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using NUnit.Framework;

namespace Sodium.IdentityModel.Tokens.Tests
{
    public class SodiumSecurityKeyTests
    {
        [Test]
        public void Ctor_ThrowsArgumentNullException_WhenPublicKeyIsNull()
            => Assert.Throws<ArgumentNullException>(() => new SodiumSecurityKey(null));

        [Test]
        public void Ctor_ThrowsArgumentNullException_WhenPrivateKeyIsNull()
            => Assert.Throws<ArgumentNullException>(() => new SodiumSecurityKey(Array.Empty<byte>(), null));

        
    }
}
