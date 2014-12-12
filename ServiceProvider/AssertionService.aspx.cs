using System.Security.Cryptography.X509Certificates;
using System.Web.Configuration;
using System.Xml;
using System.Web;
using System.Web.Security;
using ComponentPro.Saml;
using ComponentPro.Saml2;
using ComponentPro.Saml2.Binding;

namespace SamlSPInitiated.ServiceProvider
{
    public partial class AssertionService : System.Web.UI.Page
    {
        /// <summary>
        /// Receives the SAML response from the identity provider.
        /// </summary>
        /// <param name="samlResponse">The SAML Response object.</param>
        /// <param name="relayState">The relay state object.</param>
        private void ExtractResponse(out ComponentPro.Saml2.Response samlResponse, out string relayState)
        {
            // Determine the identity provider to service provider binding type.
            // We use a query string parameter rather than having separate endpoints per binding.
            string bindingType = Request.QueryString[Util.BindingVarName];

            switch (bindingType)
            {
                case SamlBindingUri.HttpPost:
                    samlResponse = ComponentPro.Saml2.Response.Create(Request);
                    relayState = samlResponse.RelayState;
                    break;

                case SamlBindingUri.HttpArtifact:
                    Saml2ArtifactType0004 httpArtifact = Saml2ArtifactType0004.CreateFromHttpArtifactHttpForm(Request);

                    // Create an artifact resolve request.
                    ArtifactResolve artifactResolve = new ArtifactResolve();
                    artifactResolve.Issuer = new Issuer(Util.GetAbsoluteUrl(this, "~/"));
                    artifactResolve.Artifact = new Artifact(httpArtifact.ToString());

                    // Send the artifact resolve request and receive the artifact response.
                    string spArtifactResponderUrl = WebConfigurationManager.AppSettings["ArtifactIdProviderUrl"];

                    ArtifactResponse artifactResponse = ArtifactResponse.SendSamlMessageReceiveAftifactResponse(spArtifactResponderUrl, artifactResolve);

                    // Extract the authentication request from the artifact response.
                    samlResponse = new Response(artifactResponse.Message);
                    relayState = httpArtifact.RelayState;
                    break;

                default:
                    Trace.Write("ServiceProvider", "Invalid identity provider to service provider binding");
                    samlResponse = null;
                    relayState = null;
                    return;
            }

            // Verify the response's signature.
            X509Certificate2 x509Certificate = (X509Certificate2) Application[Global.IdPCertKey];

            if (!samlResponse.Validate(x509Certificate))
            {
                throw new System.ApplicationException("The SAML response signature failed to verify.");
            }
        }

        /// <summary>
        /// Processes a successful SAML response.
        /// </summary>
        private void SamlSuccessRedirect(ComponentPro.Saml2.Response samlResponse, string relayState)
        {
            // Extract the asserted identity from the SAML response.
            Assertion samlAssertion = (Assertion)samlResponse.Assertions[0];

            // Get the subject name identifier.
            string userName = samlAssertion.Subject.NameId.NameIdentifier;

            // Get the originally requested resource URL from the relay state.
            string resourceUrl = (string)SamlSettings.CacheProvider.Remove(relayState);

            if (resourceUrl == null)
            {
                Trace.Write("ServiceProvider", "Nothing in cache");

                return;
            }

            // Create a login context for the asserted identity.
            FormsAuthentication.SetAuthCookie(userName, false);

            // Redirect to the originally requested resource URL.
            Response.Redirect(resourceUrl, false);
        }

        /// <summary>
        /// Processes an error SAML response. 
        /// </summary>
        private void SamlErrorRedirect(ComponentPro.Saml2.Response samlResponse)
        {
            string errorMessage = null;

            if ((samlResponse.Status.StatusMessage != null))
            {
                errorMessage = samlResponse.Status.StatusMessage.Message;
            }

            string redirectUrl = string.Format("~/LoginChoice.aspx?{0}={1}", Util.ErrorVarName, HttpUtility.UrlEncode(errorMessage));

            Response.Redirect(redirectUrl, false);
        }

        protected override void OnLoad(System.EventArgs e)
        {
            base.OnLoad(e);

            try
            {
                ComponentPro.Saml2.Response samlResponse;
                string relayState;

                // Get the SAML response
                ExtractResponse(out samlResponse, out relayState);

                if (samlResponse == null) return;

                // It indicates a success or an error?
                if (samlResponse.IsSuccess())
                {
                    // Process the success response.
                    SamlSuccessRedirect(samlResponse, relayState);
                }
                else
                {
                    // Process the error response.
                    SamlErrorRedirect(samlResponse);
                }
            }

            catch (System.Exception exception)
            {
                Trace.Write("ServiceProvider", "Error in assertion consumer service", exception);
            }
        }
    }
}