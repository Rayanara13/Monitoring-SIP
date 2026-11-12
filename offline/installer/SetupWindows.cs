using Microsoft.Win32;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace IneiSetup
{
    internal static class SetupWindows
    {
        private const string Registration = @"Software\Microsoft\Windows\CurrentVersion\Uninstall\Inei";
        private static readonly string Local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        public static readonly string DefaultProgram = Path.Combine(Local, "Inei", "Program");
        public static readonly string DefaultData = Path.Combine(Local, "Inei", "Data");
        private static readonly string SetupFolder = Path.Combine(Local, "Inei", "Setup");
        private static readonly string CachedSetup = Path.Combine(SetupFolder, "IneiSetup.exe");

        public static InstallOptions Installed()
        {
            using (RegistryKey key = Registry.CurrentUser.OpenSubKey(Registration))
            {
                if (key == null) return null;
                string program = key.GetValue("InstallLocation") as string;
                string data = key.GetValue("IneiDataDirectory") as string;
                if (String.IsNullOrWhiteSpace(program) || String.IsNullOrWhiteSpace(data)) return null;
                return new InstallOptions { ProgramDirectory = program, DataDirectory = data,
                    Port = Convert.ToInt32(key.GetValue("IneiPort", 8000)),
                    Autostart = Equals(key.GetValue("IneiAutostart"), 1),
                    Desktop = Equals(key.GetValue("IneiDesktop"), 1),
                    Firewall = Equals(key.GetValue("IneiFirewall"), 1) };
            }
        }

        public static void ValidateDirectories(InstallOptions options)
        {
            foreach (string directory in new[] { options.ProgramDirectory, options.DataDirectory })
            {
                string path = SetupCore.FullLocalPath(directory).TrimEnd('\\') + "\\";
                string setup = SetupFolder.TrimEnd('\\') + "\\";
                if (path.StartsWith(setup, StringComparison.OrdinalIgnoreCase) ||
                    setup.StartsWith(path, StringComparison.OrdinalIgnoreCase))
                    throw new IOException("Выбранная папка пересекается с папкой установщика. Выберите другой каталог.");
            }
        }

        private static string Quote(string value) { return "\"" + value + "\""; }

        private static string Python(InstallOptions options)
        {
            return Path.Combine(options.ProgramDirectory, "runtime", "windows", "python.exe");
        }

        private static string RunArguments(InstallOptions options)
        {
            return "-u " + Quote(Path.Combine(options.ProgramDirectory, "run.py")) + " --data-dir " + Quote(options.DataDirectory);
        }

        public static string PanelUrl(InstallOptions options) { return "http://127.0.0.1:" + options.Port; }

        public static void OpenPanel(InstallOptions options)
        {
            Process.Start(new ProcessStartInfo(PanelUrl(options)) { UseShellExecute = true });
        }

        public static void StartAndVerify(InstallOptions options)
        {
            using (Process process = StartVerifiedProcess(options, false)) { }
        }

        public static Process StartVerifiedProcess(InstallOptions options, bool quiet)
        {
            var start = new ProcessStartInfo(Python(options), RunArguments(options)) {
                UseShellExecute = false, WorkingDirectory = options.ProgramDirectory,
                CreateNoWindow = quiet, RedirectStandardOutput = quiet, RedirectStandardError = quiet,
            };
            if (quiet)
            {
                var inherited = new List<string>();
                foreach (DictionaryEntry entry in start.EnvironmentVariables)
                {
                    string name = (string)entry.Key;
                    if (name.StartsWith("MONITORING_SIP_", StringComparison.OrdinalIgnoreCase) ||
                        name.StartsWith("FEDERATION_", StringComparison.OrdinalIgnoreCase) ||
                        name.StartsWith("VICTORIA_", StringComparison.OrdinalIgnoreCase) ||
                        name.StartsWith("INEI_", StringComparison.OrdinalIgnoreCase)) inherited.Add(name);
                }
                foreach (string name in inherited) start.EnvironmentVariables.Remove(name);
            }
            start.EnvironmentVariables["MONITORING_SIP_ROLE"] = "node";
            start.EnvironmentVariables["MONITORING_SIP_PORT"] = options.Port.ToString();
            if (quiet)
            {
                start.EnvironmentVariables["MONITORING_SIP_HOST"] = "127.0.0.1";
                start.EnvironmentVariables["FEDERATION_MASTER_IP"] = "";
                start.EnvironmentVariables["FEDERATION_INVITATION"] = "";
            }
            Process process = Process.Start(start);
            try
            {
                if (quiet)
                {
                    process.BeginOutputReadLine();
                    process.BeginErrorReadLine();
                }
                var timeout = Stopwatch.StartNew();
                while (!process.HasExited && timeout.Elapsed < TimeSpan.FromSeconds(25))
                {
                    try
                    {
                        var request = (HttpWebRequest)WebRequest.Create(PanelUrl(options) + "/login");
                        request.Proxy = null;
                        request.Timeout = 700;
                        request.ReadWriteTimeout = 700;
                        using (var response = (HttpWebResponse)request.GetResponse())
                        using (var reader = new StreamReader(response.GetResponseStream(), Encoding.UTF8))
                            if (response.StatusCode == HttpStatusCode.OK && reader.ReadToEnd().Contains("Иней")) return process;
                    }
                    catch (WebException) { }
                    Thread.Sleep(200);
                }
                throw new IOException("Иней не открыл панель на TCP-порту " + options.Port + ".");
            }
            catch
            {
                StopProcessTree(process);
                process.Dispose();
                throw;
            }
        }

        public static void StopProcessTree(Process process)
        {
            if (process.HasExited) return;
            using (Process stop = Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "taskkill.exe"),
                "/T /F /PID " + process.Id) {
                    UseShellExecute = false, CreateNoWindow = true,
                    RedirectStandardError = true, RedirectStandardOutput = true,
                })) stop.WaitForExit();
            process.WaitForExit(4000);
        }

        private static string ShortcutPath(Environment.SpecialFolder folder)
        {
            return Path.Combine(Environment.GetFolderPath(folder), "Иней.lnk");
        }

        private static void Shortcut(Environment.SpecialFolder folder, InstallOptions options, bool enabled)
        {
            string path = ShortcutPath(folder);
            if (!enabled) { File.Delete(path); return; }
            Directory.CreateDirectory(Path.GetDirectoryName(path));
            dynamic shell = Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell"));
            dynamic link = null;
            try
            {
                link = shell.CreateShortcut(path);
                link.TargetPath = Python(options);
                link.Arguments = RunArguments(options);
                link.WorkingDirectory = options.ProgramDirectory;
                link.Description = "Иней by Стёпчик";
                link.IconLocation = CachedSetup + ",0";
                link.Save();
            }
            finally
            {
                if (link != null) Marshal.FinalReleaseComObject(link);
                Marshal.FinalReleaseComObject(shell);
            }
        }

        private static string FirewallId(string directory)
        {
            using (var hash = SHA256.Create())
                return BitConverter.ToString(hash.ComputeHash(Encoding.UTF8.GetBytes(directory.ToUpperInvariant())))
                    .Replace("-", "").Substring(0, 16);
        }

        private static bool ApplyFirewall(InstallOptions options, bool enable)
        {
            string action = enable ? "--firewall-add" : "--firewall-remove";
            using (Process process = Process.Start(new ProcessStartInfo(Assembly.GetExecutingAssembly().Location,
                action + " " + FirewallId(options.ProgramDirectory) + " " + options.Port) {
                    UseShellExecute = true, Verb = "runas", WindowStyle = ProcessWindowStyle.Hidden,
                }))
            {
                process.WaitForExit();
                return process.ExitCode == 0;
            }
        }

        public static int FirewallCommand(string[] args)
        {
            int port;
            if (args.Length != 3 || !Regex.IsMatch(args[1], "^[A-F0-9]{16}$") ||
                !Int32.TryParse(args[2], out port) || port < 1 || port > 65535) return 2;
            string name = Quote("Inei server " + args[1]);
            if (args[0] == "--firewall-remove")
                return RunFirewall("delete rule name=" + name);
            int result = RunFirewall("set rule name=" + name + " new localport=" + port);
            return result == 0 ? 0 : RunFirewall("add rule name=" + name +
                " dir=in action=allow protocol=TCP localport=" + port + " profile=private");
        }

        private static int RunFirewall(string arguments)
        {
            using (Process process = Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "netsh.exe"),
                "advfirewall firewall " + arguments) { UseShellExecute = false, CreateNoWindow = true }))
            {
                process.WaitForExit();
                return process.ExitCode;
            }
        }

        public static List<string> Integrate(InstallOptions options, InstallOptions previous)
        {
            var warnings = new List<string>();
            bool firewall = previous != null && previous.Firewall;
            if (options.Firewall || firewall)
            {
                try
                {
                    if (!ApplyFirewall(options, options.Firewall)) throw new IOException();
                    firewall = options.Firewall;
                }
                catch (Exception) { warnings.Add("Правило брандмауэра не изменено. Проверьте права администратора."); }
            }
            try
            {
                Directory.CreateDirectory(SetupFolder);
                string installer = Assembly.GetExecutingAssembly().Location;
                if (!String.Equals(installer, CachedSetup, StringComparison.OrdinalIgnoreCase))
                    File.Copy(installer, CachedSetup, true);
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(Registration))
                {
                    key.SetValue("DisplayName", "Иней");
                    key.SetValue("DisplayVersion", SetupCore.PayloadVersion());
                    key.SetValue("DisplayIcon", CachedSetup + ",0");
                    key.SetValue("InstallLocation", options.ProgramDirectory);
                    key.SetValue("IneiDataDirectory", options.DataDirectory);
                    key.SetValue("IneiPort", options.Port);
                    key.SetValue("IneiAutostart", options.Autostart ? 1 : 0);
                    key.SetValue("IneiDesktop", options.Desktop ? 1 : 0);
                    key.SetValue("IneiFirewall", firewall ? 1 : 0);
                    key.SetValue("UninstallString", Quote(CachedSetup) + " --uninstall");
                    key.SetValue("ModifyPath", Quote(CachedSetup));
                }
                Shortcut(Environment.SpecialFolder.Programs, options, true);
                Shortcut(Environment.SpecialFolder.DesktopDirectory, options, options.Desktop);
                Shortcut(Environment.SpecialFolder.Startup, options, options.Autostart);
            }
            catch (Exception) { warnings.Add("Не удалось записать один из ярлыков или параметры обслуживания Windows."); }
            return warnings;
        }

        public static void Uninstall(InstallOptions options, bool removeData)
        {
            SetupCore.CheckPort(options.Port);
            string program = SetupCore.FullLocalPath(options.ProgramDirectory);
            string data = SetupCore.FullLocalPath(options.DataDirectory);
            if (Directory.Exists(program) && !File.Exists(Path.Combine(program, SetupCore.ProgramMarker)))
                throw new IOException("Папка программы не принадлежит установщику Инея.");
            if (removeData && Directory.Exists(data) && !File.Exists(Path.Combine(data, SetupCore.DataMarker)))
                throw new IOException("Папка данных не принадлежит установщику Инея.");
            if (options.Firewall && !ApplyFirewall(options, false))
                throw new IOException("Правило брандмауэра не снято. Проверьте права администратора.");
            if (Directory.Exists(program)) Directory.Delete(program, true);
            if (removeData && Directory.Exists(data)) Directory.Delete(data, true);
            Shortcut(Environment.SpecialFolder.Programs, options, false);
            Shortcut(Environment.SpecialFolder.DesktopDirectory, options, false);
            Shortcut(Environment.SpecialFolder.Startup, options, false);
            Registry.CurrentUser.DeleteSubKeyTree(Registration, false);
        }
    }
}
