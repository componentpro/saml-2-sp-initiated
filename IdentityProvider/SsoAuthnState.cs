using ComponentPro.Saml2;

namespace SamlSPInitiated.IdentityProvider
{
    public class SsoAuthnState
    {
        AuthnRequest _authnRequest;
        public AuthnRequest AuthnRequest
        {
            get { return _authnRequest; }
            set { _authnRequest = value; }
        }

        string _relayState;
        public string RelayState
        {
            get { return _relayState; }
            set { _relayState = value; }
        }

        SamlBinding _idpProtocolBinding;
        public SamlBinding IdpProtocolBinding
        {
            get { return _idpProtocolBinding; }
            set { _idpProtocolBinding = value; }
        }

        string _assertionConsumerServiceUrl;
        public string AssertionConsumerServiceURL
        {
            get { return _assertionConsumerServiceUrl; }
            set { _assertionConsumerServiceUrl = value; }
        }
    }
}