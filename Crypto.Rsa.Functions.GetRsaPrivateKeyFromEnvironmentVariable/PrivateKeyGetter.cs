using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using System.IO;
using System.Security.Cryptography;
using static Org.BouncyCastle.Security.DotNetUtilities;
using static System.Environment;
using static System.String;

namespace Crypto.Rsa.Functions.GetRsaPrivateKeyFromEnvironmentVariable
{
    public static class PrivateKeyGetter
    {
        private const string EnvironmentVariableName = "RSA_PRIVATE_KEY_SPACE_DELIMITED";
        private const string Foot = "-----END RSA PRIVATE KEY-----";
        private const string Head = "-----BEGIN RSA PRIVATE KEY-----";

        public static RSAParameters PrivateKey(string environmentVariable = EnvironmentVariableName)
        {
            var key = GetKey(environmentVariable);
            using (var reader = new StringReader(key))
            {
                var pem = new PemReader(reader);
                var keys = (AsymmetricCipherKeyPair)pem.ReadObject();
                var privateKey = (RsaPrivateCrtKeyParameters)keys.Private;
                return ToRSAParameters(privateKey);
            }
        }

        private static string GetKey(string environmentVariable)
            => $"{Head}{NewLine}{GetKeyContent(environmentVariable)}{NewLine}{Foot}{NewLine}";

        private static string GetKeyContent(string environmentVariable)
            => Join(NewLine,
                GetEnvironmentVariable(environmentVariable).Split(' '));
    }
}
