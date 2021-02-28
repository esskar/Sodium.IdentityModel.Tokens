using System;
using Moq;
using NUnit.Framework;

namespace Sodium.IdentityModel.Tokens.Tests
{
    public class SodiumCryptoProviderTests
    {
        private SodiumCryptoProvider _provider;

        [SetUp]
        public void Initialize()
        {
            _provider = new SodiumCryptoProvider();
        }

        [Theory]
        [TestCase(SodiumAlgorithms.EdDsa)]
        public void IsSupportedAlgorithm_ReturnsTrue_WhenAlgorithmIsSupported(string algorithm)
            => Assert.IsTrue(_provider.IsSupportedAlgorithm(algorithm, new SodiumSecurityKey(Array.Empty<byte>())));

        [Theory]
        [TestCase("eddsa")]
        [TestCase("EDDSA")]
        [TestCase("EdDsA")]
        public void IsSupportedAlgorithm_ReturnsFalse_WhenAlgorithmIsNotSupported(string algorithm)
            => Assert.IsFalse(_provider.IsSupportedAlgorithm(algorithm, new SodiumSecurityKey(Array.Empty<byte>())));

        [Theory]
        [TestCase("eddsa")]
        [TestCase("EDDSA")]
        [TestCase("EdDsA")]
        public void Create_ThrowsNotSupportedException_WhenAlgorithmIsNotSupported(string algorithm)
            => Assert.Throws<NotSupportedException>(() => _provider.Create(algorithm, new SodiumSecurityKey(Array.Empty<byte>())));

        [Test]
        public void Create_ThrowsNotSupportedException_WhenNoKeyIsSet()
            => Assert.Throws<NotSupportedException>(() => _provider.Create(SodiumAlgorithms.EdDsa));

        [Test]
        public void Create_ThrowsNotSupportedException_WhenKeyIsSetSodiumSecurityKey()
            => Assert.Throws<NotSupportedException>(() => _provider.Create(SodiumAlgorithms.EdDsa, new object()));

        [Test]
        public void Create_ReturnsSodiumSignatureProvider_WhenKeyAndAlgorithmIsSetCorrectly()
        {
            var actual = _provider.Create(SodiumAlgorithms.EdDsa, new SodiumSecurityKey(Array.Empty<byte>()));
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