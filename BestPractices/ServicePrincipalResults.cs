using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BestPractices
{
    internal class ServicePrincipalResults
    {
        public string odatacontext { get; set; }
        public string id { get; set; }
        public bool appRoleAssignmentRequired { get; set; }
        public bool accountEnabled { get; set; }
        public List<AppRole> appRoles { get; set; }
    }
}
