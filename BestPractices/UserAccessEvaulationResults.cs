using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BestPractices
{
    public class UserAccessEvaulationResults
    {
        public string odatacontext { get; set; }
        public DateTime signInSessionsValidFromDateTime { get; set; }
        public DateTime refreshTokensValidFromDateTime { get; set; }
        public object deletedDateTime { get; set; }
        public bool accountEnabled { get; set; }
    }
}
