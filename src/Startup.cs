using System;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Newtonsoft.Json;

namespace LdkServiceSample
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
        }

        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            app.Run(async context =>
            {
                try
                {
                    /*
                     * Handle CORS
                     */
                    // To allow Landmand.dk to call the service, it must whitelist the landmand.dk domains with CORS
                    // https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
                    // Including, but not limited to, handling the required OPTIONS requests, and allowing usage of the Authorization Header
                    // CORS support is non-trivial and is typically performed using a generic library / framework / middleware

                    /*
                     * Extract Authorization header
                     */
                    // Expect header:
                    // Authorization: Bearer 3Vj7b%2bJIEv5XIkbaXxDxA%...
                    var schemeToken = context.Request.Headers["Authorization"].SingleOrDefault() ?? string.Empty;
                    // Remove the "Bearer " prefix
                    var deflatedSamlToken = schemeToken.Substring("Bearer ".Length);

                    /*
                     * Decode token from Authorization header
                     */
                    // The token sent will be DeflatedSaml encoded, as described here:
                    // https://confluence.seges.dk/display/PUB/Service+Authorization "Encoding the token"
                    // This process must be reversed to recover the original SAML 1.1 token
                    // var token = DecodeDeflatedSaml(deflatedSamlToken);

                    /*
                     * Validate token
                     */
                    // The token is a SAML 1.1 token issued by DLBR Common Login ADFS.
                    // Here, the token xml signature should be validated, and the claimset contained within extracted.
                    // Validating the xml signature is non-trivial and is typically performed using a generic library / framework / middleware
                    // var principal = Validate(token);

                    // The token carries information about the end-user at the outermost claim level, 
                    // as well as information about the currently acting service account tunnelled in the "actor" claim.
                    // .NET Authentication middleware deserializes this into a ClaimsIdentity representing the end-user 
                    // with the acting service account available through the Actor property
                    // The result will be similar to
                    var principal =
                        new ClaimsPrincipal(
                            new ClaimsIdentity(
                                new[]
                                {
                                new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier","cvruser1@PROD.DLI"),
                                new Claim("http://claims.dlbr.dk/2012/02/cvrnumber","68309980")
                                },
                                authenticationType: "fake")
                            {
                                Actor = new ClaimsIdentity(
                                    new[]
                                    {
                                    new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier","poolLdk@PROD.DLI")
                                    },
                                    authenticationType: "fake")
                            });

                    /*
                     * Authorize caller and user
                     */
                    // With this information, the service can perform authorization decisions based on the end-user and/or the service account
                    // Authorize(principal);


                    /*
                     * Lookup data
                     */
                    // If authorization succeeds, look up data for the specific end-user
                    //var data = FindData(principal);
                    // Here, we create fake data based on the fake principal instead:
                    var serviceaccountNameIdentifier = principal.Identities.Single().Actor.Claims
                        .Single(c => c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier").Value;
                    var userNameIdentifier = principal.Identities.Single().Claims
                        .Single(c => c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier").Value;
                    var userCvr = principal.Identities.Single().Claims
                        .Single(c => c.Type == "http://claims.dlbr.dk/2012/02/cvrnumber").Value;
                    var data = new[]
                    {
                        new
                        {
                            Identifier = userNameIdentifier,
                            Data = $"User CVR was {userCvr}"
                        },
                        new
                        {
                            Identifier = serviceaccountNameIdentifier,
                            Data = string.Empty
                        }
                    };

                    /*
                     * Return data in JSON format
                     */
                    var jsonData = JsonConvert.SerializeObject(data, Formatting.Indented);

                    context.Response.StatusCode = 200;
                    context.Response.ContentType = "application/json; charset=utf-8";
                    await context.Response.WriteAsync(jsonData, Encoding.UTF8);

                }
                catch (Exception )
                {
                    context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                    await context.Response.WriteAsync("No/non-bearer/invalid token in Authorization header");
                }
            });
        }
    }
}
