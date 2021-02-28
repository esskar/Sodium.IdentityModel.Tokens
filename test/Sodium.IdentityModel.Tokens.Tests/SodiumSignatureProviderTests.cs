using System;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using NUnit.Framework;

namespace Sodium.IdentityModel.Tokens.Tests
{
    public class SodiumSignatureProviderTests
    {
        [Theory]
        [TestCase(
            "esskar",
            "q6ZfKypb+s98WLUNuSjxBG0i2PUjsQKPwMdusbKcVCNteF/RVRu/z8xmdFTY/IRqf297h8nNFqTWxmDXDl7CCQ==", 
            "T/2hPBHWHSuVaOVL7AbqWTaOhIdIgwh2ReZOXpZTQi4=")]
        [TestCase(
            "Adam Caudill",
            "jVQ2rMviWKayUsEUDzjXuNxhlmGZRYGLclEraoAZ2G3+61b0DE1LmD2X3+7TeUhSclbDVn1rJTdX/PsyvvVvCw==", 
            "T/2hPBHWHSuVaOVL7AbqWTaOhIdIgwh2ReZOXpZTQi4=")]
        public void Verify_ReturnsTrue_ForValidSignatures(string text, string signature, string publicKey)
        {
            var key = new SodiumSecurityKey(Convert.FromBase64String(publicKey));
            var provider = new SodiumSignatureProvider(key, SodiumAlgorithms.EdDsa);
            var verified = provider.Verify(Encoding.UTF8.GetBytes(text), Convert.FromBase64String(signature));
            Assert.IsTrue(verified);
        }

        [Theory]
        [TestCase(
            "esskar",
            "q6ZfKypb+s98WLUNuSjxBG0i2PUjsQKPwMdusbKcVCNteF/RVRu/z8xmdFTY/IRqf297h8nNFqTWxmDXDl7CCQ==", 
            "id/5fBMUNMEYCcM0FRDOY8hehR07pi4vgQAWu8Z9NRRP/aE8EdYdK5Vo5UvsBupZNo6Eh0iDCHZF5k5ellNCLg==")]
        [TestCase(
            "Adam Caudill",
            "jVQ2rMviWKayUsEUDzjXuNxhlmGZRYGLclEraoAZ2G3+61b0DE1LmD2X3+7TeUhSclbDVn1rJTdX/PsyvvVvCw==", 
            "id/5fBMUNMEYCcM0FRDOY8hehR07pi4vgQAWu8Z9NRRP/aE8EdYdK5Vo5UvsBupZNo6Eh0iDCHZF5k5ellNCLg==")]
        public void Sign_ReturnsExpectedSignature(string text, string expectedSignature, string privateKey)
        {
            var key = SodiumSecurityKey.FromPrivateKey(Convert.FromBase64String(privateKey));
            var provider = new SodiumSignatureProvider(key, SodiumAlgorithms.EdDsa);
            var signature = provider.Sign(Encoding.UTF8.GetBytes(text));
            Assert.AreEqual(expectedSignature, Convert.ToBase64String(signature));
        }
    }
}
