using System.Security.Cryptography.X509Certificates;
using System.Web.Configuration;
using System;
using System.Web;
using System.Web.Security;
using ComponentPro.Saml;
using ComponentPro.Saml.Binding;
using ComponentPro.Saml2;
using ComponentPro.Saml2.Binding;

namespace SamlSPInitiated.ServiceProvider
{
    public partial class UserLogin : System.Web.UI.Page
    {
        /// <summary>
        /// Builds an authentication request.
        /// </summary>
        /// <returns>The authentication request.</returns>
        private AuthnRequest BuildAuthenticationRequest()
        {
            string issuerUrl = Util.GetAbsoluteUrl(this, "~/");
            // Construct the assertion Consumer Service Url.
            string assertionConsumerServiceUrl = string.Format("{0}?{1}={2}", Util.GetAbsoluteUrl(this, "~/AssertionService.aspx"), Util.BindingVarName, HttpUtility.UrlEncode(idpToSPBindingList.SelectedValue));

            // Create the authentication request.
            AuthnRequest authnRequest = new AuthnRequest();
            authnRequest.Destination = WebConfigurationManager.AppSettings["SingleSignonIdProviderUrl"];
            authnRequest.Issuer = new Issuer(issuerUrl);
            authnRequest.ForceAuthn = false;
            authnRequest.NameIdPolicy = new NameIdPolicy(null, null, true);
            authnRequest.ProtocolBinding = idpToSPBindingList.SelectedValue;
            authnRequest.AssertionConsumerServiceUrl = assertionConsumerServiceUrl;
            
            if (spToIdPBindingList.SelectedValue != SamlBindingUri.HttpRedirect)
            {
                // Get the certificate
                X509Certificate2 x509Certificate = (X509Certificate2)Application[Global.SPCertKey];

                // Sign the authentication request.
                authnRequest.Sign(x509Certificate);
            }
            return authnRequest;

        }

        protected override void OnLoad(System.EventArgs e)
        {
            base.OnLoad(e);

            string error = Request.QueryString[Util.ErrorVarName];
            if (error == null)
                error = string.Empty;

            // Display any error message resulting from a failed login if any.
            lblErrorMessage.Text = error;
        }

        /// <summary>
        /// Handles the IdpLogin button to requests login at the Identify Provider site.
        /// </summary>
        /// <param name="sender">The button object.</param>
        /// <param name="e">The event arguments.</param>
        protected void btnIdPLogin_Click(object sender, EventArgs e)
        {
            // Create the authentication request.
            AuthnRequest authnRequest = BuildAuthenticationRequest();

            // Create and cache the relay state so we remember which SP resource the user wishes 
            // to access after SSO.
            string spResourceUrl = Util.GetAbsoluteUrl(this, FormsAuthentication.GetRedirectUrl("", false));
            string relayState = Guid.NewGuid().ToString();
            SamlSettings.CacheProvider.Insert(relayState, spResourceUrl, new TimeSpan(1, 0, 0));

            // Send the authentication request to the identity provider over the selected binding.
            string idpUrl = string.Format("{0}?{1}={2}", WebConfigurationManager.AppSettings["SingleSignonIdProviderUrl"], Util.BindingVarName, HttpUtility.UrlEncode(spToIdPBindingList.SelectedValue));

            switch (spToIdPBindingList.SelectedValue)
            {
                case SamlBindingUri.HttpRedirect:
                    X509Certificate2 x509Certificate = (X509Certificate2)Application[Global.SPCertKey];

                    authnRequest.Redirect(Response, idpUrl, relayState, x509Certificate.PrivateKey);
                    break;

                case SamlBindingUri.HttpPost:
                    authnRequest.SendHttpPost(Response, idpUrl, relayState);

                    // Don't send this form.
                    Response.End();
                    break;

                case SamlBindingUri.HttpArtifact:
                    // Create the artifact.
                    string identificationUrl = Util.GetAbsoluteUrl(this, "~/");
                    Saml2ArtifactType0004 httpArtifact = new Saml2ArtifactType0004(SamlArtifact.GetSourceId(identificationUrl), SamlArtifact.GetHandle());

                    // Cache the authentication request for subsequent sending using the artifact resolution protocol.
                    SamlSettings.CacheProvider.Insert(httpArtifact.ToString(), authnRequest.GetXml(), new TimeSpan(1, 0, 0));

                    // Send the artifact.
                    httpArtifact.Redirect(Response, idpUrl, relayState);
                    break;
            }
        }

        protected void btnLogin_Click(object sender, EventArgs e)
        {
            if (FormsAuthentication.Authenticate(txtUserName.Text, txtPassword.Text))
            {
                FormsAuthentication.RedirectFromLoginPage(txtUserName.Text, false);
            }
            else
            {
                lblErrorMessage.Text = "The user name and password should be \"suser\" and \"password\".";
            }
        }
    }
}