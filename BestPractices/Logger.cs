using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BestPractices
{
    /// <summary>
    /// Possibility the worlds most simple logger
    /// </summary>
    internal class Logger
    {
        string fileName;
        readonly StringBuilder sblog;

        public Logger(StringBuilder sbLog)
        {
            sblog = sbLog;
        }

        public void Start()
        {
            fileName = $"{DateTime.Now.ToString("yyyy-MM-dd-HH-mm-ss")}.log";
        }

        public void Log(string message)
        {
            string messageToShow;

            messageToShow = $"{DateTime.Now}-{message}";
            Console.WriteLine(messageToShow);
            sblog.AppendLine(messageToShow);
            File.AppendAllText(fileName, $"{messageToShow}\n");
        }
    }
}
