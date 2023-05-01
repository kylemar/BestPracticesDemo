using System.Collections.Generic;
using System.Text.Json;

namespace BestPractices
{
    public class GroupResults
    {
        public string odatacontext { get; set; }
        public List<string> value { get; set; }
    }
}
