// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Identity.Client;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Microsoft.Identity.Web
{
    /// <summary>
    /// Filter used on a Web app controller action to trigger incremental consent
    /// and handle conditional access.
    /// </summary>
    /// <example>
    /// When a user signs-in for the first time to a Web app, they are asked to consent
    /// to the default permissions. Later, when controller actions that want to call a Web
    /// api request more scopes, the user might have a consent. Also some Web APIs require conditional
    /// access, for isntance the user might need to perform multiple factor authentication. In both cases
    /// the user need to be presented a consent string again, which means ASP.NET Core needs to challenge
    /// the user.
    /// 
    /// On the following controller, this attribute ensures that, if a conditional
    /// access or incremental consent is needed, the scope "Mail.Send" is presented to the user. 
    /// <code>
    /// [AuthorizeForScopes(Scopes = new[] {"Mail.Send"})]
    /// public async Task&lt;IActionResult&gt; SendEmail()
    /// {
    /// }
    /// </code>
    /// </example>
    /// <remarks>There are two exclusive ways of specifying the scopes:
    /// <list type="bullet">
    /// <item>hardcoded in the code, by using the <see cref="Scopes"/> attribute</item>
    /// <item>by configuation, which enables configuration of Web APIS. 
    /// In that case, the property in the configuration is then specified through the 
    /// <see cref="ScopeKeySection"/> property describing the fully qualified name of the
    /// configuration item containing the scopes (for instance: "TodoList: TodoListScopes" if
    /// a configuration property named "TodoListScopes" exists in the section "TodoList"</item>
    /// </list></remarks>
    public class AuthorizeForScopesAttribute : ExceptionFilterAttribute
    {
        /// <summary>
        /// Scopes to request
        /// </summary>
        public string[] Scopes { get; set; }

        /// <summary>
        /// Fully qualified key (separated by ':') of the property in the configuration file 
        /// that holds the scopes value. The scopes are themselves separated by spaces.
        /// <example>
        /// If the configuration file contains:
        /// <code>
        ///  "TodoList": {
        ///    "TodoListScope": "api://a4c2469b-cf84-4145-8f5f-cb7bacf814bc/access_as_user",
        ///    "TodoListBaseAddress": "https://localhost:44351"
        ///  },
        /// </code>
        /// 
        /// The attribute on the controller can be:
        /// <code>
        /// [AuthorizeForScopes(ScopeKeySection = "TodoList:TodoListScope")]
        /// public async Task&lt;IActionResult&gt; DoSomethingCallingWebApi()
        /// {
        /// }
        /// </code>
        /// </example>
        /// </summary>
        public string ScopeKeySection { get; set; }

        /// <summary>
        /// Handles the MsalUiRequiredException
        /// </summary>
        /// <param name="context">Context provided by ASP.NET Core</param>
        public override void OnException(ExceptionContext context)
        {
            // Do not re-use the attribute param Scopes. For more info: https://github.com/Azure-Samples/active-directory-aspnetcore-webapp-openidconnect-v2/issues/273
            string[] incrementalConsentScopes = new string[] { };
            MsalUiRequiredException msalUiRequiredException = context.Exception as MsalUiRequiredException;

            if (msalUiRequiredException == null)
            {
                msalUiRequiredException = context.Exception?.InnerException as MsalUiRequiredException;
            }

            if (msalUiRequiredException != null)
            {
                if (CanBeSolvedByReSignInOfUser(msalUiRequiredException))
                {
                    // the users cannot provide both scopes and ScopeKeySection at the same time
                    if (!string.IsNullOrWhiteSpace(ScopeKeySection) && Scopes != null && Scopes.Length > 0)
                    {
                        throw new InvalidOperationException($"Either provide the '{nameof(ScopeKeySection)}' or the '{nameof(Scopes)}' to the 'AuthorizeForScopes'.");
                    }

                    // If the user wishes us to pick the Scopes from a particular config setting.
                    if (!string.IsNullOrWhiteSpace(ScopeKeySection))
                    {
                        // Load the injected IConfiguration
                        IConfiguration configuration = context.HttpContext.RequestServices.GetRequiredService<IConfiguration>();

                        if (configuration == null)
                        {
                            throw new InvalidOperationException($"The {nameof(ScopeKeySection)} is provided but the IConfiguration instance is not present in the services collection");
                        }

                        incrementalConsentScopes = new string[] { configuration.GetValue<string>(ScopeKeySection) };
                        
                        if (Scopes != null && Scopes.Length > 0 && incrementalConsentScopes != null && incrementalConsentScopes.Length > 0)
                        {
                           throw new InvalidOperationException("no scopes provided in scopes...");
                        }
                    }
                    else
                        incrementalConsentScopes = Scopes;

                    var properties = BuildAuthenticationPropertiesForIncrementalConsent(incrementalConsentScopes, msalUiRequiredException, context.HttpContext);
                    context.Result = new ChallengeResult(properties);
                }
            }

            base.OnException(context);
        }

        private bool CanBeSolvedByReSignInOfUser(MsalUiRequiredException ex)
        {
            // ex.ErrorCode != MsalUiRequiredException.UserNullError indicates a cache problem.
            // When calling an [Authenticate]-decorated controller we expect an authenticated
            // user and therefore its account should be in the cache. However in the case of an
            // InMemoryCache, the cache could be empty if the server was restarted. This is why
            // the null_user exception is thrown.

            return ex.ErrorCode.ContainsAny(new[] { MsalError.UserNullError, MsalError.InvalidGrantError });
        }

        /// <summary>
        /// Build Authentication properties needed for incremental consent.
        /// </summary>
        /// <param name="scopes">Scopes to request</param>
        /// <param name="ex">MsalUiRequiredException instance</param>
        /// <param name="context">current http context in the pipeline</param>
        /// <returns>AuthenticationProperties</returns>
        private AuthenticationProperties BuildAuthenticationPropertiesForIncrementalConsent(
            string[] scopes,
            MsalUiRequiredException ex,
            HttpContext context)
        {
            var properties = new AuthenticationProperties();

            // Set the scopes, including the scopes that ADAL.NET / MSAL.NET need for the token cache
            string[] additionalBuiltInScopes =
                {OidcConstants.ScopeOpenId,
                OidcConstants.ScopeOfflineAccess,
                OidcConstants.ScopeProfile};
            properties.SetParameter<ICollection<string>>(OpenIdConnectParameterNames.Scope,
                                                         scopes.Union(additionalBuiltInScopes).ToList());

            // Attempts to set the login_hint to avoid the logged-in user to be presented with an account selection dialog
            var loginHint = context.User.GetLoginHint();
            if (!string.IsNullOrWhiteSpace(loginHint))
            {
                properties.SetParameter(OpenIdConnectParameterNames.LoginHint, loginHint);

                var domainHint = context.User.GetDomainHint();
                properties.SetParameter(OpenIdConnectParameterNames.DomainHint, domainHint);
            }

            // Additional claims required (for instance MFA)
            if (!string.IsNullOrEmpty(ex.Claims))
            {
                properties.Items.Add(OidcConstants.AdditionalClaims, ex.Claims);
            }

            return properties;
        }
    }
}