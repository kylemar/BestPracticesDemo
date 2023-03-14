using System.Collections.Generic;
using System.Text.Json;

namespace BestPractices
{
    public class GroupResults
    {
        public string odatacontext { get; set; }
        public List<Group> value { get; set; }
    }

    public class Group
    {
        public string odatatype { get; set; }
        public string id { get; set; }
    }

}
