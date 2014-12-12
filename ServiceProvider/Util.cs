using System;
using System.Web.UI;

namespace SamlSPInitiated.ServiceProvider
{
    public class Util
    {
        /// <summary>
        /// The query string variable that indicates the IdentityProvider to ServiceProvider binding.
        /// </summary>
        public const string BindingVarName = "binding";

        /// <summary>
        /// The query string parameter that contains error description for the login failure. 
        /// </summary>
        public const string ErrorVarName = "error";

        public static string GetAbsoluteUrl(Page page, string relativeUrl)
        {
            return new Uri(page.Request.Url, page.ResolveUrl(relativeUrl)).ToString();
        }
    }
}