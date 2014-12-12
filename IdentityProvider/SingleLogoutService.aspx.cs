using System.Security.Cryptography.X509Certificates;
using System.Web.Configuration;
using System;
using System.Web.Security;
using ComponentPro.Saml2;

namespace SamlSPInitiated.IdentityProvider
{
    public partial class SingleLogoutService : System.Web.UI.Page
    {
        protected override void OnLoad(EventArgs e)
        {
            base.OnLoad(e);

            try
            {
                #region Receive logout request

                X509Certificate2 x509Certificate = (X509Certificate2)Application[Global.SPCertKey];

                LogoutRequest logoutRequest = LogoutRequest.Create(Request, x509Certificate.PublicKey.Key);

                #endregion

                // Logout locally.
                FormsAuthentication.SignOut();
                Session.Abandon();

                // You can send a logout request to any other service providers here.
                // ...
                
                // Create a logout response
                LogoutResponse logoutResponse = new LogoutResponse();
                logoutResponse.Issuer = new Issuer(Util.GetAbsoluteUrl(this, "~/"));

                #region Send Logout Response

                // Send the logout response over HTTP redirect.
                string logoutUrl = WebConfigurationManager.AppSettings["LogoutServiceProviderUrl"];
                x509Certificate = (X509Certificate2)Application[Global.SPCertKey];

                logoutResponse.Redirect(Response, logoutUrl, logoutRequest.RelayState, x509Certificate.PrivateKey);

                #endregion
            }

            catch (Exception exception)
            {
                Trace.Write("IdP", "Error in single logout service", exception);
            }
        }
    }
}