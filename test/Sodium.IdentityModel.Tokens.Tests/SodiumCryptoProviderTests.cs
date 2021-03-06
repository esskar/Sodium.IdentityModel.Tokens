﻿using System;
using Moq;
using NUnit.Framework;

namespace Sodium.IdentityModel.Tokens.Tests
{
    public class SodiumCryptoProviderTests
    {
        private SodiumCryptoProvider _provider;
        private SodiumSecurityKey _key;

        [SetUp]
        public void Initialize()
        {
            _provider = new SodiumCryptoProvider();
            _key = SodiumSecurityKey.FromPublicKey(Convert.FromBase64String("T/2hPBHWHSuVaOVL7AbqWTaOhIdIgwh2ReZOXpZTQi4="));
        }

        [Theory]
        [TestCase(SodiumAlgorithms.EdDsa)]
        public void IsSupportedAlgorithm_ReturnsTrue_WhenAlgorithmIsSupported(string algorithm)
            => Assert.IsTrue(_provider.IsSupportedAlgorithm(algorithm, _key));

        [Theory]
        [TestCase("eddsa")]
        [TestCase("EDDSA")]
        [TestCase("EdDsA")]
        public void IsSupportedAlgorithm_ReturnsFalse_WhenAlgorithmIsNotSupported(string algorithm)
            => Assert.IsFalse(_provider.IsSupportedAlgorithm(algorithm, _key));

        [Theory]
        [TestCase("eddsa")]
        [TestCase("EDDSA")]
        [TestCase("EdDsA")]
        public void Create_ThrowsNotSupportedException_WhenAlgorithmIsNotSupported(string algorithm)
            => Assert.Throws<NotSupportedException>(() => _provider.Create(algorithm, _key));

        [Test]
        public void Create_ThrowsNotSupportedException_WhenNoKeyIsSet()
            => Assert.Throws<NotSupportedException>(() => _provider.Create(SodiumAlgorithms.EdDsa));

        [Test]
        public void Create_ThrowsNotSupportedException_WhenKeyIsSetSodiumSecurityKey()
            => Assert.Throws<NotSupportedException>(() => _provider.Create(SodiumAlgorithms.EdDsa, new object()));

        [Test]
        public void Create_ReturnsSodiumSignatureProvider_WhenKeyAndAlgorithmIsSetCorrectly()
        {
            var actual = _provider.Create(SodiumAlgorithms.EdDsa, _key);
            Assert.IsInstanceOf<SodiumSignatureProvider>(actual);
        }

        [Test]
        public void Release_Disposes_WhenObjectIsDisposable()
        {
            var disposable = new Mock<IDisposable>();
            _provider.Release(disposable.Object);
            disposable.Verify(x => x.Dispose(), Times.Once);
        }

        [Test]
        public void Release_DoesNothing_WhenObjectIsNotDisposable()
        {
            var notDisposable = new Mock<INotDisposable>();
            _provider.Release(notDisposable.Object);
            notDisposable.Verify(x => x.Dispose(), Times.Never);
        }

        public interface INotDisposable
        {
            void Dispose();
        }
    }
}