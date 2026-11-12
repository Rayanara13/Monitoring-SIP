using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;

namespace IneiSetup
{
    internal static class SetupCoreTests
    {
        private static void Assert(bool value, string message)
        {
            if (!value) throw new Exception(message);
        }

        private static void Progress(int percent, string message) { }

        private static int FreePort()
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();
            return port;
        }

        private static int Main()
        {
            string root = Path.Combine(Path.GetTempPath(), "Inei setup тест " + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(root);
            var legacyListener = new TcpListener(IPAddress.Loopback, 0);
            try
            {
                string old = Path.Combine(root, "Старая установка");
                string program = Path.Combine(root, "Программа с пробелом");
                string data = Path.Combine(root, "Рабочие данные");
                legacyListener.Start();
                int legacyPort = ((IPEndPoint)legacyListener.LocalEndpoint).Port;
                int port = FreePort();
                Directory.CreateDirectory(Path.Combine(old, "users_data", ".managed-release"));
                Directory.CreateDirectory(data); // A user may select an existing empty folder.
                File.WriteAllText(Path.Combine(old, "auth.json"), "fixture auth bytes");
                File.WriteAllText(Path.Combine(old, "phones.json"), "fixture phone bytes");
                File.WriteAllText(Path.Combine(old, "users_data", "call_history.db"), "fixture history bytes");
                File.WriteAllText(Path.Combine(old, "users_data", ".managed-release", "active.json"), "legacy executable pointer");
                string legacyConfig = "MONITORING_SIP_PORT=" + legacyPort + "\nAPP_SECRET_KEY=fixture\n";
                File.WriteAllText(Path.Combine(old, ".env"), legacyConfig);
                var options = new InstallOptions { ProgramDirectory = program, DataDirectory = data, PreviousData = old, Port = port };
                InstallPlan initial = SetupCore.Plan(options);
                Assert(!Directory.Exists(program) && Directory.GetFileSystemEntries(data).Length == 0, "Preflight wrote to destination.");
                SetupCore.Install(initial, Progress, selected => {
                    Assert(File.Exists(Path.Combine(program, "runtime", "windows", "python.exe")), "Bundled Python missing.");
                    Assert(File.ReadAllText(Path.Combine(data, "auth.json")) == "fixture auth bytes", "Auth was not copied.");
                    Assert(File.ReadAllText(Path.Combine(data, "phones.json")) == "fixture phone bytes", "Cards were not copied.");
                    Assert(File.ReadAllText(Path.Combine(data, "users_data", "call_history.db")) == "fixture history bytes", "History was not copied.");
                    Assert(!Directory.Exists(Path.Combine(data, "users_data", ".managed-release")), "Old executable pointer was restored.");
                    Assert(File.ReadAllText(Path.Combine(data, ".env")).Contains("MONITORING_SIP_ROLE=node"), "Public role must be node.");
                    Assert(File.ReadAllText(Path.Combine(data, ".env")).Contains("APP_SECRET_KEY=fixture"), "Existing config was lost.");
                    Assert(SetupCore.ReadPort(data) == port, "The selected port was not written to the migrated config.");
                });
                Assert(File.Exists(Path.Combine(data, SetupCore.LicenseReceipt)), "Acceptance receipt missing.");
                Assert(File.ReadAllText(Path.Combine(initial.DataBackup, "auth.json")) == "fixture auth bytes", "Backup was not verified.");
                Assert(File.Exists(Path.Combine(old, "auth.json")), "Original installation was touched.");
                Assert(File.ReadAllText(Path.Combine(old, ".env")) == legacyConfig, "The original port config was changed.");
                Assert(File.ReadAllText(Path.Combine(initial.DataBackup, ".env")) == legacyConfig, "The backup did not retain the original port.");
                legacyListener.Stop();
                Console.WriteLine("PASS offline migration to a different port while the old port is occupied, with verified backup");

                options.PreviousData = null;
                File.WriteAllText(Path.Combine(program, "previous-program.txt"), "keep");
                File.WriteAllText(Path.Combine(data, "custom-config.txt"), "keep");
                InstallPlan failed = SetupCore.Plan(options);
                bool rolledBack = false;
                try
                {
                    SetupCore.Install(failed, Progress, selected => {
                        File.WriteAllText(Path.Combine(data, "new-failed-write.txt"), "discard");
                        throw new IOException("Injected boot failure");
                    });
                }
                catch (IOException error) { rolledBack = error.Message == "Injected boot failure"; }
                Assert(rolledBack, "Boot failure did not surface.");
                Assert(File.Exists(Path.Combine(program, "previous-program.txt")), "Program was not rolled back.");
                Assert(File.Exists(Path.Combine(data, "custom-config.txt")), "Data was not rolled back.");
                Assert(!File.Exists(Path.Combine(data, "new-failed-write.txt")), "Failed candidate data survived rollback.");
                Console.WriteLine("PASS failed startup restores previous program and data");

                InstallPlan repair = SetupCore.Plan(options);
                SetupCore.Install(repair, Progress, selected => { });
                Assert(!File.Exists(Path.Combine(program, "previous-program.txt")), "Repair did not replace application files.");
                Assert(File.ReadAllText(Path.Combine(data, "custom-config.txt")) == "keep", "Repair lost local data.");
                Assert(File.Exists(Path.Combine(repair.ProgramBackup, "previous-program.txt")), "Repair backup missing.");
                Console.WriteLine("PASS repair replaces files and preserves data");

                File.WriteAllText(Path.Combine(program, "old-after-repair.txt"), "original program");
                InstallPlan interrupted = SetupCore.Plan(options);
                string interruptedCode = program + ".setup-" + Guid.NewGuid().ToString("N");
                string interruptedData = data + ".setup-" + Guid.NewGuid().ToString("N");
                Directory.CreateDirectory(interruptedCode);
                Directory.CreateDirectory(interruptedData);
                File.WriteAllText(Path.Combine(interruptedCode, SetupCore.ProgramMarker), "interrupted candidate");
                SetupCore.RecordSwap(interrupted, interruptedCode, interruptedData);
                Directory.Move(program, interrupted.ProgramBackup);
                Directory.Move(data, interrupted.DataBackup);
                Directory.Move(interruptedCode, program); // Simulate interruption after replacing only the program.
                InstallPlan retry = SetupCore.Plan(options);
                try { SetupCore.Install(retry, Progress, selected => { throw new IOException("retry abort"); }); }
                catch (IOException error) { Assert(error.Message == "retry abort", "Interrupted swap could not recover."); }
                Assert(File.Exists(Path.Combine(program, "old-after-repair.txt")), "Old program was lost after interruption.");
                Assert(File.ReadAllText(Path.Combine(data, "custom-config.txt")) == "keep", "Data was lost after interruption.");
                Assert(File.Exists(Path.Combine(interruptedCode, SetupCore.ProgramMarker)), "Interrupted candidate was not saved aside.");
                Console.WriteLine("PASS retry restores both original folders after an interrupted swap");

                var conflict = new TcpListener(IPAddress.Any, port);
                try
                {
                    conflict.Start();
                    bool rejected = false;
                    try { SetupCore.Plan(options); }
                    catch (IOException error) { rejected = error.Message.Contains(port.ToString()); }
                    Assert(rejected, "Occupied port was not rejected.");
                }
                finally { conflict.Stop(); }
                Console.WriteLine("PASS occupied port rejected without changing files");

                var clean = new InstallOptions { ProgramDirectory = Path.Combine(root, "Чистая установка"),
                    DataDirectory = Path.Combine(root, "Чистые данные"), Port = FreePort() };
                Process instance = null;
                try
                {
                    SetupCore.Install(SetupCore.Plan(clean), Progress, selected => instance = SetupWindows.StartVerifiedProcess(selected, true));
                    Assert(File.Exists(Path.Combine(clean.DataDirectory, "auth.json")), "First launch did not create local credentials.");
                }
                finally
                {
                    if (instance != null)
                    {
                        SetupWindows.StopProcessTree(instance);
                        instance.Dispose();
                    }
                }
                Console.WriteLine("PASS bundled Python boots actual node and responds on isolated HTTP listener");
                return 0;
            }
            catch (Exception error) { Console.Error.WriteLine(error); return 1; }
            finally
            {
                legacyListener.Stop();
                Directory.Delete(root, true);
            }
        }
    }
}
