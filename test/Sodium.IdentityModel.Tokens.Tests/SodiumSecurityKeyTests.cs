using System;
using Microsoft.IdentityModel.Tokens;
using NUnit.Framework;

namespace Sodium.IdentityModel.Tokens.Tests
{
    public class SodiumSecurityKeyTests
    {
        private static readonly byte[] PrivateKey = Convert.FromBase64String("id/5fBMUNMEYCcM0FRDOY8hehR07pi4vgQAWu8Z9NRRP/aE8EdYdK5Vo5UvsBupZNo6Eh0iDCHZF5k5ellNCLg==");
        private static readonly byte[] PublicKey = Convert.FromBase64String("T/2hPBHWHSuVaOVL7AbqWTaOhIdIgwh2ReZOXpZTQi4=");

        [Test]
        public void FromPublicKey_ThrowsArgumentException_WhenPublicKeyTooShort()
            => Assert.Throws<ArgumentException>(() => SodiumSecurityKey.FromPublicKey(Array.Empty<byte>()));

        [Test]
        public void FromPrivateKey_ThrowsArgumentException_WhenPrivateKeyIsNull()
            => Assert.Throws<ArgumentException>(() => SodiumSecurityKey.FromPrivateKey(Array.Empty<byte>()));


        [Test]
        public void FromPublicKey_Sets_PublicKeyToInput()
        {
           var key = SodiumSecurityKey.FromPublicKey(PublicKey);
           CollectionAssert.AreEqual(PublicKey, key.PublicKey);
        }

        [Test]
        public void FromPublicKey_Sets_PrivateKeyToNull()
        {
            var key = SodiumSecurityKey.FromPublicKey(PublicKey);
            Assert.Null(key.PrivateKey);
        }

        [Test]
        public void FromPublicKey_Sets_CurveToEd25519()
        {
            var key = SodiumSecurityKey.FromPublicKey(PublicKey);
            Assert.AreEqual(SodiumAlgorithms.Ed25519, key.Curve);
        }

        [Test]
        public void FromPublicKey_HasNoPrivateKey()
        {
            var key = SodiumSecurityKey.FromPublicKey(PublicKey);
            Assert.AreEqual(PrivateKeyStatus.DoesNotExist, key.PrivateKeyStatus);
        }

        [Test]
        public void FromPrivateKey_Sets_PublicKey()
        {
            var key = SodiumSecurityKey.FromPrivateKey(PrivateKey);
            CollectionAssert.AreEqual(PublicKey, key.PublicKey);
        }

        [Test]
        public void FromPrivateKey_Sets_PrivateKeyToInput()
        {
            var key = SodiumSecurityKey.FromPrivateKey(PrivateKey);
            CollectionAssert.AreEqual(PrivateKey, key.PrivateKey);
        }

        [Test]
        public void FromPrivateKey_Sets_CurveToEd25519()
        {
            var key = SodiumSecurityKey.FromPrivateKey(PrivateKey);
            Assert.AreEqual(SodiumAlgorithms.Ed25519, key.Curve);
        }

        [Test]
        public void FromPrivateKey_HasPrivateKey()
        {
            var key = SodiumSecurityKey.FromPrivateKey(PrivateKey);
            Assert.AreEqual(PrivateKeyStatus.Exists, key.PrivateKeyStatus);
        }

        [Test]
        public void Dispose_ClearsPrivateKey()
        {
            var key = SodiumSecurityKey.FromPrivateKey(PrivateKey);
            var privateKey = key.PrivateKey;
            key.Dispose();
            CollectionAssert.AreEqual(new byte[64], privateKey);
        }
    }
}
