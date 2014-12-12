using System;
using System.Web.Configuration;
using System.Diagnostics;
using System.Web.UI;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using ComponentPro.Saml;
using ComponentPro.Saml.Binding;
using ComponentPro.Saml2;
using ComponentPro.Saml2.Binding;

namespace SamlSPInitiated.IdentityProvider
{
    public class Util
    {
        /// <summary>
        /// Processes the authentication request.
        /// </summary>
        /// <param name="authnRequest">The AuthnRequest object.</param>
        /// <param name="relayState">The relayState string.</param>
        public static void ProcessAuthnRequest(Page page, out AuthnRequest authnRequest, out string relayState)
        {
            // Use a single endpoint and use a query string parameter to determine the Service Provider to Identity Provider binding type.
            string bindingType = page.Request.QueryString["binding"];

            switch (bindingType)
            {
                case SamlBindingUri.HttpRedirect:
                    X509Certificate2 x509Certificate = (X509Certificate2)page.Application[Global.SPCertKey];

                    authnRequest = AuthnRequest.Create(page.Request.RawUrl, x509Certificate.PublicKey.Key);
                    relayState = authnRequest.RelayState;
                    return;

                case SamlBindingUri.HttpPost:
                    authnRequest = AuthnRequest.CreateFromHttpPost(page.Request);
                    relayState = authnRequest.RelayState;
                    break;

                case SamlBindingUri.HttpArtifact:
                    // Create an artifact resolve request.
                    Saml2ArtifactType0004 httpArtifact = Saml2ArtifactType0004.CreateFromHttpArtifactQueryString(page.Request);

                    // Create an artifact resolve request.
                    ArtifactResolve artifactResolve = new ArtifactResolve();
                    artifactResolve.Issuer = new Issuer(Util.GetAbsoluteUrl(page, "~/"));
                    artifactResolve.Artifact = new Artifact(httpArtifact.ToString());

                    string artifactServiceProviderUrl = WebConfigurationManager.AppSettings["ArtifactServiceProviderUrl"];

                    // Send the SAML Artifact Resolve Request and parse the received response.
                    ArtifactResponse artifactResponse = ArtifactResponse.SendSamlMessageReceiveAftifactResponse(artifactServiceProviderUrl, artifactResolve);

                    // Extract the authentication request from the received artifact response.
                    authnRequest = new AuthnRequest(artifactResponse.Message);
                    relayState = httpArtifact.RelayState;
                    break;

                default:
                    Trace.Write("IdentityProvider", "Invalid service provider to identity provider binding");
                    authnRequest = null;
                    relayState = null;
                    return;

            }

            if (authnRequest.IsSigned())
            {
                // Get the loaded certificate.
                X509Certificate2 x509Certificate = (X509Certificate2)page.Application[Global.SPCertKey];

                // And validate the authentication request with the certificate.
                if (!authnRequest.Validate(x509Certificate))
                {
                    throw new ApplicationException("The authentication request signature failed to verify.");
                }
            }
        }

        /// <summary>
        /// Builds the SAML response.
        /// </summary>
        /// <param name="authnRequest">The AuthnRequest object.</param>
        /// <returns>A SAML Response object.</returns>
        public static ComponentPro.Saml2.Response BuildResponse(Page page)
        {
            ComponentPro.Saml2.Response samlResponse = new ComponentPro.Saml2.Response();
            string issuerUrl = Util.GetAbsoluteUrl(page, "~/");

            samlResponse.Issuer = new Issuer(issuerUrl);

            if (page.User.Identity.IsAuthenticated)
            {
                samlResponse.Status = new Status(SamlPrimaryStatusCode.Success, null);

                Assertion samlAssertion = new Assertion();

                samlAssertion.Subject = new Subject(new NameId(page.User.Identity.Name));
                samlAssertion.Statements.Add(new AuthnStatement());
                samlResponse.Assertions.Add(samlAssertion);
            }
            else
            {
                samlResponse.Status = new Status(SamlPrimaryStatusCode.Responder, SamlSecondaryStatusCode.AuthnFailed, "The user is not authenticated at the identity provider");
            }

            return samlResponse;
        }

        /// <summary>
        /// Sends the SAML response to the Service Provider.
        /// </summary>
        /// <param name="samlResponse">The SAML response object.</param>
        /// <param name="relayState">The relay state.</param>
        public static void SendResponse(Page page, ComponentPro.Saml2.Response samlResponse, SsoAuthnState ssoState)
        {
            // Sign the SAML response 
            X509Certificate2 x509Certificate = (X509Certificate2)page.Application[Global.IdPCertKey];

            samlResponse.Sign(x509Certificate);

            // Send the SAML response to the service provider.
            switch (ssoState.IdpProtocolBinding)
            {
                case SamlBinding.HttpPost:
                    samlResponse.SendPostBindingForm(page.Response.OutputStream, ssoState.AssertionConsumerServiceURL, ssoState.RelayState);
                    break;

                case SamlBinding.HttpArtifact:
                    // Create the artifact.
                    string identificationUrl = Util.GetAbsoluteUrl(page, "~/");
                    Saml2ArtifactType0004 httpArtifact = new Saml2ArtifactType0004(SamlArtifact.GetSourceId(identificationUrl), SamlArtifact.GetHandle());

                    // Cache the authentication request for subsequent sending using the artifact resolution protocol. Sliding expiration time is 1 hour.
                    SamlSettings.CacheProvider.Insert(httpArtifact.ToString(), samlResponse.GetXml(), new TimeSpan(1, 0, 0));

                    // Send the artifact.
                    httpArtifact.SendPostForm(page.Response.OutputStream, ssoState.AssertionConsumerServiceURL,
                                              ssoState.RelayState);
                    break;

                default:
                    Trace.Write("IdentityProvider", "Invalid identity provider binding");
                    break;
            }
        }

        public static string GetAbsoluteUrl(Page page, string relativeUrl)
        {
            return new Uri(page.Request.Url, page.ResolveUrl(relativeUrl)).ToString();
        }        
    }
}