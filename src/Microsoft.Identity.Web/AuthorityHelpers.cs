// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.AspNetCore.Http;
using System;

namespace Microsoft.Identity.Web
{
    internal static class AuthorityHelpers
    {
        /// <summary>
        /// Returns is the authority is an AzureAD v2.0 authority or not
        /// </summary>
        /// <param name="authority">String containing the authority</param>
        /// <returns><c>true</c> if the authority is a v2.0 authority, otherwise <c>false</c></returns>
        internal static bool IsV2Authority(string authority)
        {
            if (string.IsNullOrEmpty(authority))
                return false;

            return authority.EndsWith("/v2.0");
        }

        /// <summary>
        /// Build an authority string from the <see cref="MicrosoftIdentityOptions"/>
        /// which are provided as a configuration. This can be an Azure AD v2.0 authority
        /// or an Azure AD B2C authority depending on if <see cref="MicrosoftIdentityOptions.DefaultUserFlow"/>
        /// is empty or not.
        /// </summary>
        /// <param name="options">configuration options</param>
        /// <returns>The authority string of the form {instance}/{domain}[/{userFlow}]/v2.0"</returns>
        internal static string BuildAuthority(MicrosoftIdentityOptions options)
        {
            if (options == null)
                return null;

            // Cannot build authority without AAD Instance
            if (string.IsNullOrWhiteSpace(options.Instance))
                return null;

            var baseUri = new Uri(options.Instance);
            var pathBase = baseUri.PathAndQuery.TrimEnd('/');
            var domain = options.Domain;
            var tenantId = options.TenantId;

            // If there are user flows, then it must build a B2C authority 
            if (!string.IsNullOrWhiteSpace(options.DefaultUserFlow))
            {
                // Cannot build B2C authority without domain
                if (string.IsNullOrWhiteSpace(domain))
                    return null;

                var userFlow = options.DefaultUserFlow;
                return new Uri(baseUri, new PathString($"{pathBase}/{domain}/{userFlow}/v2.0")).ToString();
            }

            else
            {
                // Cannot build AAD authority without tenant id
                if (string.IsNullOrWhiteSpace(tenantId))
                    return null;

                return new Uri(baseUri, new PathString($"{pathBase}/{tenantId}/v2.0")).ToString();
            }
        }
    }
}
