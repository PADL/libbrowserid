using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Windows.Forms;

namespace msetupgui
{
    static class Program
    {
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Moonshot mainform = new Moonshot();
            if (mainform.NeedsElevate)
            {
                var info = new ProcessStartInfo(
                    Assembly.GetEntryAssembly().Location)
                {
                    Verb = "runas" // elevate privileges
                };

                var process = new Process
                {
                    EnableRaisingEvents = true, // enable WaitForExit()
                    StartInfo = info
                };

                process.Start();
                process.WaitForExit();
            }
            else if (!mainform.IsDisposed)
                Application.Run(mainform);
        }
    }
}
