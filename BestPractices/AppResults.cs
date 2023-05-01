using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BestPractices
{
    internal class AppResults
    {
        public string odatacontext { get; set; }
        public List<Value> value { get; set; }
    }

    public class Value
    {
        public List<AppRole> appRoles { get; set; }
    }


}
