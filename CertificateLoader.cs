﻿using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace MjIot.Client.TokenApi
{
    public interface ICertificateLoader
    {
        X509Certificate2 LoadCertificate();
    }



    public class LocalCertificateLoader : ICertificateLoader
    {
        private string _certificatePath;

        public LocalCertificateLoader()
        {
            _certificatePath = Path.Combine(Directory.GetCurrentDirectory(), "Certificates", "mycert.pfx");
        }

        public X509Certificate2 LoadCertificate()
        {
            var cert = new X509Certificate2(_certificatePath, GetCertificatePassword());
            return cert;
        }

        private string GetCertificatePassword()
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json");

            var configuration = builder.Build();
            return configuration["CertificatePassword"];
        }
    }





    public class AzureCertificateLoader : ICertificateLoader
    {
        public X509Certificate2 LoadCertificate()
        {
            X509Store certStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            certStore.Open(OpenFlags.ReadOnly);

            X509Certificate2Collection certCollection = certStore
                .Certificates
                .Find(X509FindType.FindByThumbprint,
                "D1556461D129C3F71D29A62A1FDC2EA85F58FFBB", // Generated by Azure
                false);

            if (certCollection.Count > 0)
            {
                X509Certificate2 cert = certCollection[0];

                return cert;
            }
            certStore.Dispose();

            return null;
        }
    }
}
