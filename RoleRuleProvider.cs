using System;
using System.Linq;
using Orchard.ContentManagement;
using Orchard.Roles.Models;
using Orchard.Security;
using Orchard.Widgets.Services;

namespace PCG.RoleLayer
{
    public class RoleRuleProvider : IRuleProvider
    {
        private readonly IAuthenticationService _authenticationService;

        public RoleRuleProvider(IAuthenticationService authenticationService) {
            _authenticationService = authenticationService;
        }

        public void Process(RuleContext ruleContext) { 
            if (!String.Equals(ruleContext.FunctionName, "role", StringComparison.OrdinalIgnoreCase)) {
                return;
            }

            var user = _authenticationService.GetAuthenticatedUser();
            if (user == null) {
                ruleContext.Result = false;
                return;
            }

            var roles = ruleContext.Arguments.Cast<String>();
            var userRoles = user.As<UserRolesPart>().Roles;
            var matches = userRoles.Intersect(roles, StringComparer.OrdinalIgnoreCase).Count();
            if (matches < 1)
            {
                ruleContext.Result = false;
                return;
            }

            ruleContext.Result = true;
            return;
        }
    }
}