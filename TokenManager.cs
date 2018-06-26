using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.IO;
//using System.Security.Cryptography;

//using Org.BouncyCastle.Crypto;
//using Org.BouncyCastle.Crypto.Parameters;
//using Org.BouncyCastle.OpenSsl;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Configuration;

namespace MJIoT_TokenIssuer
{
    public class TokenManager
    {

        private readonly ICertificateLoader _certificateLoader;

        public TokenManager()
        {
            //_certificateLoader = new LocalCertificateLoader();
            _certificateLoader = new LocalCertificateLoader();
        }

        private void HS256Test()
        {
            var payload = new Dictionary<string, object>()
            {
                { "sub", "mr.x@contoso.com" },
                { "exp", 1300819380 }
            };

            var secretKey = new byte[] { 115, 101, 99, 114, 101, 116, 49, 50, 51 };

            string token = Jose.JWT.Encode(payload, secretKey, Jose.JwsAlgorithm.HS256);
            //string re = "";
        }

        //signed
        private void RS256Test()
        {
            var payload = new Dictionary<string, object>()
            {
                { "sub", "mr.x@contoso.com" },
                { "exp", 1300819380 }
            };

            var filePath = Path.Combine(Directory.GetCurrentDirectory(), "Certificates", "mycert.pfx");
            var cert = new X509Certificate2(filePath, "qwerty1");

            var privateKey = cert.GetRSAPrivateKey();

            string token = Jose.JWT.Encode(payload, privateKey, Jose.JwsAlgorithm.RS256);//.Replace("TJuxjsI2", "TJuxisI2");

            //walidacja
            var publicKey = cert.GetRSAPublicKey();
            string json = Jose.JWT.Decode(token, publicKey);

            //string re = "";
        }



        public string CreateToken(IEnumerable<Claim> claims)
        {
            Dictionary<string, object> payload = claims.ToDictionary(k => k.Type, v => (object)v.Value);

            var cert = _certificateLoader.LoadCertificate();
            var privateKey = cert.GetRSAPrivateKey();

            string token = Jose.JWT.Encode(payload, privateKey, Jose.JwsAlgorithm.RS256);

            return token;
        } 


        //public string CreateToken(IEnumerable<Claim> claims, string certificateName, string rootFolder, string certificateFolder = "Certificates")
        //{
        //    RS256Test();

        //    string path = Path.Combine(rootFolder, certificateFolder, certificateName);
        //    string pemString = File.ReadAllText(path);
        //    string jwt = string.Empty;
        //    AsymmetricCipherKeyPair keyPair;

        //    using (StreamReader sr = new StreamReader(path))
        //    {
        //        PemReader pr = new PemReader(sr);
        //        keyPair = (AsymmetricCipherKeyPair)pr.ReadObject();
        //    }

        //    RSAParameters rsaParams = ToRSAParameters((RsaPrivateCrtKeyParameters)keyPair.Private);

        //    using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
        //    {
        //        rsa.ImportParameters(rsaParams);
        //        Dictionary<string, object> payload = claims.ToDictionary(k => k.Type, v => (object)v.Value);
        //        jwt = Jose.JWT.Encode(payload, rsa, Jose.JwsAlgorithm.RS256);
        //    }

        //    return jwt;
        //}

        //public RSAParameters ToRSAParameters(RsaKeyParameters rsaKey)
        //{
        //    RSAParameters rp = new RSAParameters { Modulus = rsaKey.Modulus.ToByteArrayUnsigned() };
        //    if (rsaKey.IsPrivate)
        //        rp.D = rsaKey.Exponent.ToByteArrayUnsigned();
        //    else
        //        rp.Exponent = rsaKey.Exponent.ToByteArrayUnsigned();
        //    return rp;
        //}

        //public RSAParameters ToRSAParameters(RsaPrivateCrtKeyParameters privKey)
        //{
        //    RSAParameters rp = new RSAParameters
        //    {
        //        Modulus = privKey.Modulus.ToByteArrayUnsigned(),
        //        Exponent = privKey.PublicExponent.ToByteArrayUnsigned(),
        //        D = privKey.Exponent.ToByteArrayUnsigned(),
        //        P = privKey.P.ToByteArrayUnsigned(),
        //        Q = privKey.Q.ToByteArrayUnsigned(),
        //        DP = privKey.DP.ToByteArrayUnsigned(),
        //        DQ = privKey.DQ.ToByteArrayUnsigned(),
        //        InverseQ = privKey.QInv.ToByteArrayUnsigned()
        //    };
        //    return rp;
        //}
    }
}
