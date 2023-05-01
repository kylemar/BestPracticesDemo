using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BestPractices
{
    internal enum LogType
    {
        All,
        Screen,
        Console,
        File
    }
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
            fileName = $"{DateTime.Now:yyyy-MM-dd-HH-mm-ss}.log";
        }

        public void Log(string message, LogType logType = LogType.All )
        {
            string messageToShow;

            messageToShow = $"{DateTime.Now}-{message}";

            if (logType == LogType.All || logType == LogType.Console)
            {
                Console.WriteLine(messageToShow);
            }

            if (logType == LogType.All || logType == LogType.Screen)
            {
                if (sblog.Length > 65536)
                {
                    sblog.Clear();
                }
                sblog.AppendLine(messageToShow);
            }

            if (logType == LogType.All || logType == LogType.File)
            {
                try
                {
                    File.AppendAllText(fileName, $"{messageToShow}\n");
                }
                catch { }
            }
        }
    }
}
