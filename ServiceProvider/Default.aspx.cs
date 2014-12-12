using System.Security.Cryptography.X509Certificates;
using System.Web.Configuration;
using System.Xml;
using System;
using ComponentPro.Saml2;

namespace SamlSPInitiated.ServiceProvider
{
    public partial class _Default : System.Web.UI.Page
    {
        protected void btnLogout_Click(object sender, EventArgs e)
        {
            try
            {
                // Create a logout request.
                LogoutRequest logoutRequest = new LogoutRequest();
                logoutRequest.Issuer = new Issuer(Util.GetAbsoluteUrl(this, "~/"));
                logoutRequest.NameId = new NameId(Context.User.Identity.Name);

                // Send the logout request to the IdP over HTTP redirect.
                string logoutUrl = WebConfigurationManager.AppSettings["LogoutIdProviderUrl"];
                X509Certificate2 x509Certificate = (X509Certificate2)Application[Global.SPCertKey];

                // Logout locally.
                System.Web.Security.FormsAuthentication.SignOut();
                Session.Abandon();

                logoutRequest.Redirect(Response, logoutUrl, null, x509Certificate.PrivateKey);
            }

            catch (Exception exception)
            {
                Trace.Write("ServiceProvider", "Error on logout page", exception);
            }
        }
    }
}