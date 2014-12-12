using System;
using ComponentPro.Saml2;

namespace SamlSPInitiated.IdentityProvider
{
    public partial class SingleSignOnService : System.Web.UI.Page
    {
        // The session key for saving the SSO state during a local login.
        private const string SsoSessionKey = "sso";        

        protected override void OnLoad(System.EventArgs e)
        {
            base.OnLoad(e);

            try
            {
                // Load the Single Sign On state from the Session state.
                // If the saved authentication state is a null reference, receive the authentication request from the query string and form data.
                SsoAuthnState ssoState = (SsoAuthnState)Session[SsoSessionKey];

                if (ssoState == null)
                {
                    // Receive the authentication request.
                    AuthnRequest authnRequest;
                    string relayState;

                    Util.ProcessAuthnRequest(this, out authnRequest, out relayState);

                    if (authnRequest == null)
                    {
                        // No authentication request found.
                        return;
                    }

                    // Process the authentication request.
                    bool forceAuthn = authnRequest.ForceAuthn;
                    bool allowCreate = false;

                    if (authnRequest.NameIdPolicy != null)
                    {
                        allowCreate = authnRequest.NameIdPolicy.AllowCreate;
                    }

                    ssoState = new SsoAuthnState();
                    ssoState.AuthnRequest = authnRequest;
                    ssoState.RelayState = relayState;
                    ssoState.IdpProtocolBinding = SamlBindingUri.UriToBinding(authnRequest.ProtocolBinding);
                    ssoState.AssertionConsumerServiceURL = authnRequest.AssertionConsumerServiceUrl;

                    // Determine whether or not a local login is required.
                    bool requireLocalLogin = false;
                    
                    if (forceAuthn)
                    {
                        requireLocalLogin = true;
                    }
                    else
                    {
                        if (!User.Identity.IsAuthenticated & allowCreate)
                        {
                            requireLocalLogin = true;
                        }
                    }

                    // If a local login is required then save the authentication request 
                    // and initiate a local login.
                    if (requireLocalLogin)
                    {
                        // Save the SSO state.
                        Session[SsoSessionKey] = ssoState;

                        // Initiate a local login.
                        System.Web.Security.FormsAuthentication.RedirectToLoginPage();
                        return;
                    }
                }

                // Create a SAML response with the user's local identity, if any.
                ComponentPro.Saml2.Response samlResponse = Util.BuildResponse(this);

                // Send the SAML response to the service provider.
                Util.SendResponse(this, samlResponse, ssoState);
            }

            catch (Exception exception)
            {
                Trace.Write("IdentityProvider", "An Error occurred", exception);
            }
        }
    }
}