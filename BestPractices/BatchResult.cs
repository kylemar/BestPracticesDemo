using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static System.Windows.Forms.VisualStyles.VisualStyleElement.Tab;

namespace BestPractices
{
    public class Response
    {
        public string id { get; set; }
        public int status { get; set; }
        public object body { get; set; }
    }

    internal class BatchResult
    {
        public List<Response> responses { get; set; }
    }
}
