using System.IO;
using System.Security.Cryptography.X509Certificates;
using System;
using System.Net;
using System.Web;
using System.Net.Security;

namespace SamlSPInitiated.ServiceProvider
{
    public class Global : System.Web.HttpApplication
    {
        private const string SPKeyFile = "SPKey.pfx";
        private const string SPKeyPassword = "password";

        private const string IdPCertFile = "IdpCertificate.cer";

        public const string SPCertKey = "SPCertKey";
        public const string IdPCertKey = "IdPCertKey";

        /// <summary>
        /// Verifies the remote Secure Sockets Layer (SSL) certificate used for authentication.
        /// </summary>
        /// <param name="sender">An object that contains state information for this validation.</param>
        /// <param name="certificate">The certificate used to authenticate the remote party.</param>
        /// <param name="chain">The chain of certificate authorities associated with the remote certificate.</param>
        /// <param name="sslPolicyErrors">One or more errors associated with the remote certificate.</param>
        /// <returns>A System.Boolean value that determines whether the specified certificate is accepted for authentication.</returns>
        private static bool ValidateRemoteServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            // NOTE: This is a test application with self-signed certificates, so all certificates are trusted.
            return true;
        }

        /// <summary>
        /// Loads the certificate file.
        /// </summary>
        /// <param name="cacheKey">The cache key.</param>
        /// <param name="fileName">The certificate file name.</param>
        /// <param name="password">The password for this certificate file.</param>
        private void LoadCertificate(string cacheKey, string fileName, string password)
        {
            X509Certificate2 cert = new X509Certificate2(fileName, password, X509KeyStorageFlags.MachineKeySet);

            Application[cacheKey] = cert;
        }

        void Application_Start(object sender, EventArgs e)
        {
            // Set the server certificate validation callback.
            ServicePointManager.ServerCertificateValidationCallback = ValidateRemoteServerCertificate;

            // Load the IdP cert file.
            LoadCertificate(IdPCertKey, Path.Combine(HttpRuntime.AppDomainAppPath, IdPCertFile), null);

            // Load the SP cert file.
            LoadCertificate(SPCertKey, Path.Combine(HttpRuntime.AppDomainAppPath, SPKeyFile), SPKeyPassword);
        }
    }
}