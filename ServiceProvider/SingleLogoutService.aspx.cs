using System.Security.Cryptography.X509Certificates;
using System.Xml;
using ComponentPro.Saml2;

namespace SamlSPInitiated.ServiceProvider
{
    public partial class SingleLogoutService : System.Web.UI.Page
    {
        protected override void OnLoad(System.EventArgs e)
        {
            base.OnLoad(e);

            try
            {
                // Get the previously loaded certificate.
                X509Certificate2 x509Certificate = (X509Certificate2)Application[Global.IdPCertKey];

                LogoutResponse logoutResponse = LogoutResponse.Create(Request, x509Certificate.PublicKey.Key);
                
                // Do something here with the logoutResponse.
                // ...

                // Redirect to the default page.
                Response.Redirect("~/");
            }

            catch (System.Exception exception)
            {
                Trace.Write("ServiceProvider", "An error occurred", exception);
            }
        }
    }
}