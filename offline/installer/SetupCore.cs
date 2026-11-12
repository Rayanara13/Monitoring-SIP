using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace IneiSetup
{
    internal sealed class InstallOptions
    {
        public string ProgramDirectory, DataDirectory, PreviousData;
        public int Port = 8000;
        public bool Autostart, Desktop, Firewall, OpenBrowser = true;
    }

    internal sealed class InstallPlan
    {
        public InstallOptions Options;
        public string ProgramBackup, DataBackup;
        public long RequiredBytes;
        public bool ExistingProgram, ExistingData;
    }

    internal static class SetupCore
    {
        public const string ProgramMarker = ".inei-program";
        public const string DataMarker = ".inei-data";
        public const string LicenseReceipt = ".inei-license-accepted";
        private const string Root = "MonitoringSIP/";
        private static readonly Encoding ConfigEncoding = Encoding.GetEncoding(28591);
        private static readonly string[] DataEntries = { ".env", "auth.json", "phones.json", "users_data",
                                                         "ping-trust.json", "connect.json" };

        private static Stream Resource(string name)
        {
            Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(name);
            if (stream == null) throw new InvalidDataException("В установщике нет обязательного файла.");
            return stream;
        }

        public static string License()
        {
            using (var reader = new StreamReader(Resource("Inei.License.txt"), Encoding.UTF8))
                return reader.ReadToEnd();
        }

        public static string ComponentLicenses()
        {
            var text = new StringBuilder();
            using (var archive = new ZipArchive(Resource("Inei.Kit.zip"), ZipArchiveMode.Read))
                foreach (ZipArchiveEntry entry in archive.Entries)
                {
                    if (entry.Length == 0 || entry.Length > 262144 || !Regex.IsMatch(entry.Name, @"^(LICENSE|LICENCE|COPYING|NOTICE)(?:[._-].*)?$", RegexOptions.IgnoreCase))
                        continue;
                    using (var reader = new StreamReader(entry.Open(), Encoding.UTF8))
                        text.AppendLine(entry.FullName).AppendLine(reader.ReadToEnd()).AppendLine();
                }
            return text.ToString();
        }

        public static string PayloadVersion()
        {
            using (var archive = new ZipArchive(Resource("Inei.Kit.zip"), ZipArchiveMode.Read))
            using (var reader = new StreamReader(archive.GetEntry(Root + "VERSION.txt").Open(), Encoding.UTF8))
            {
                Match version = Regex.Match(reader.ReadToEnd(), @"\b[0-9]+\.[0-9]+(?:\.[0-9]+)?\b");
                if (!version.Success) throw new InvalidDataException("Не определена версия комплекта.");
                return version.Value;
            }
        }

        private static bool Below(string path, string directory)
        {
            return path.StartsWith(directory.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar,
                                   StringComparison.OrdinalIgnoreCase);
        }

        public static string FullLocalPath(string value)
        {
            if (String.IsNullOrWhiteSpace(value) || !Regex.IsMatch(value.Trim(), @"^[a-zA-Z]:[\\/]"))
                throw new IOException("Выберите абсолютный путь на локальном диске.");
            string full = Path.GetFullPath(value.Trim()).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            if (full.Length <= 3) throw new IOException("Выберите папку внутри диска.");
            for (string current = full; current != null; current = Path.GetDirectoryName(current))
            {
                if ((Directory.Exists(current) || File.Exists(current)) &&
                    (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                    throw new IOException("Путь установки содержит ссылку или точку подключения. Выберите обычную папку.");
            }
            return full;
        }

        private static bool Same(string left, string right)
        {
            return String.Equals(left, right, StringComparison.OrdinalIgnoreCase);
        }

        private static bool Intersects(string left, string right)
        {
            return Same(left, right) || Below(left, right) || Below(right, left);
        }

        public static string FindData(string folder)
        {
            folder = FullLocalPath(folder);
            foreach (string candidate in new[] { folder, Path.Combine(folder, "app"),
                                                  Path.Combine(folder, "MonitoringSIP", "app") })
            {
                if (File.Exists(Path.Combine(candidate, "victoria-role.json")))
                    throw new IOException("Для переноса Виктории требуется внутренний комплект.");
                if (DataEntries.Any(item => File.Exists(Path.Combine(candidate, item)) ||
                                            Directory.Exists(Path.Combine(candidate, item))))
                    return FullLocalPath(candidate);
            }
            throw new IOException("В выбранной папке не найдены данные Инея.");
        }

        private static bool Occupied(string path)
        {
            if (File.Exists(path)) throw new IOException("Вместо выбранной папки найден файл.");
            return Directory.Exists(path) && Directory.EnumerateFileSystemEntries(path).Any();
        }

        private static string BackupName(string path)
        {
            return path + ".backup-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N").Substring(0, 8);
        }

        private static long ProgramBytes()
        {
            using (var archive = new ZipArchive(Resource("Inei.Kit.zip"), ZipArchiveMode.Read))
                return archive.Entries.Sum(entry => entry.Length);
        }

        public static InstallPlan Plan(InstallOptions options)
        {
            options.ProgramDirectory = FullLocalPath(options.ProgramDirectory);
            options.DataDirectory = FullLocalPath(options.DataDirectory);
            if (Intersects(options.ProgramDirectory, options.DataDirectory))
                throw new IOException("Программа и рабочие данные должны находиться в отдельных папках.");
            if (options.Port < 1 || options.Port > 65535) throw new IOException("Порт должен быть от 1 до 65535.");
            if (Occupied(options.ProgramDirectory) && !File.Exists(Path.Combine(options.ProgramDirectory, ProgramMarker)))
                throw new IOException("В папке программы уже есть файлы. Выберите пустую папку для новой установки.");
            if (Occupied(options.DataDirectory) && !File.Exists(Path.Combine(options.DataDirectory, DataMarker)))
                throw new IOException("В папке данных уже есть файлы. Укажите её как источник переноса и выберите новый каталог данных.");
            bool existingProgram = Occupied(options.ProgramDirectory);
            bool existingData = Occupied(options.DataDirectory);
            if (String.IsNullOrWhiteSpace(options.PreviousData) || Same(options.PreviousData, options.DataDirectory))
                options.PreviousData = existingData ? options.DataDirectory : null;
            else
            {
                options.PreviousData = FindData(options.PreviousData);
                if (Occupied(options.DataDirectory) || Intersects(options.PreviousData, options.ProgramDirectory) ||
                    Intersects(options.PreviousData, options.DataDirectory))
                    throw new IOException("Для переноса укажите пустые отдельные папки и отдельный источник данных.");
            }
            if (options.PreviousData != null && File.Exists(Path.Combine(options.PreviousData, "victoria-role.json")))
                throw new IOException("Для переноса Виктории требуется внутренний комплект.");
            long data = options.PreviousData == null ? 0 : DataFiles(options.PreviousData).Sum(path => new FileInfo(path).Length);
            bool sourceIsDestination = options.PreviousData != null && Same(options.PreviousData, options.DataDirectory);
            long programBytes = ProgramBytes() + 8 * 1024 * 1024;
            long dataBytes = data * (sourceIsDestination ? 1 : 2) + 8 * 1024 * 1024;
            var programDrive = new DriveInfo(Path.GetPathRoot(options.ProgramDirectory));
            var dataDrive = new DriveInfo(Path.GetPathRoot(options.DataDirectory));
            long programNeed = programBytes + (Same(programDrive.Name, dataDrive.Name) ? dataBytes : 0);
            if (programDrive.AvailableFreeSpace < programNeed || dataDrive.AvailableFreeSpace < dataBytes)
                throw new IOException("Недостаточно свободного места для комплекта и резервной копии.");
            CheckPort(options.Port);
            if (options.PreviousData != null && ReadPort(options.PreviousData) != options.Port)
                CheckPort(ReadPort(options.PreviousData));
            return new InstallPlan { Options = options, ExistingProgram = existingProgram, ExistingData = existingData,
                ProgramBackup = existingProgram ? BackupName(options.ProgramDirectory) : null,
                DataBackup = options.PreviousData != null || existingData ? BackupName(options.DataDirectory) : null,
                RequiredBytes = programBytes + dataBytes };
        }

        public static void CheckPort(int port)
        {
            var listener = new TcpListener(IPAddress.Any, port);
            listener.ExclusiveAddressUse = true;
            try { listener.Start(); }
            catch (SocketException) { throw new IOException("TCP-порт " + port + " занят. Остановите старый Иней или выберите другой порт."); }
            finally { listener.Stop(); }
        }

        public static int ReadPort(string folder)
        {
            int port;
            return Int32.TryParse(ConfigLines(folder).Where(line => line.StartsWith("MONITORING_SIP_PORT=")).
                    Select(line => line.Substring("MONITORING_SIP_PORT=".Length)).FirstOrDefault(), out port) &&
                    port >= 1 && port <= 65535 ? port : 8000;
        }

        private static string[] ConfigLines(string folder)
        {
            string path = Path.Combine(folder, ".env");
            if (!File.Exists(path)) return new string[0];
            string text = ConfigEncoding.GetString(File.ReadAllBytes(path));
            if (text.StartsWith("\u00ef\u00bb\u00bf", StringComparison.Ordinal)) text = text.Substring(3);
            return text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
        }

        private static void SetConfig(string folder, int port)
        {
            var lines = ConfigLines(folder).Where(line => !line.StartsWith("MONITORING_SIP_PORT=") &&
                !line.StartsWith("MONITORING_SIP_ROLE=")).ToList();
            lines.Add("MONITORING_SIP_ROLE=node");
            lines.Add("MONITORING_SIP_PORT=" + port);
            File.WriteAllBytes(Path.Combine(folder, ".env"), ConfigEncoding.GetBytes(String.Join("\r\n", lines) + "\r\n"));
        }

        private static IEnumerable<string> DataFiles(string root)
        {
            bool owned = File.Exists(Path.Combine(root, DataMarker));
            foreach (string item in Directory.EnumerateFileSystemEntries(root))
            {
                string name = Path.GetFileName(item);
                if (name == DataMarker || (!owned && !DataEntries.Contains(name, StringComparer.OrdinalIgnoreCase))) continue;
                foreach (string file in Files(item)) yield return file;
            }
        }

        private static IEnumerable<string> Files(string entry)
        {
            FileAttributes attributes = File.GetAttributes(entry);
            if ((attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("В данных найдена файловая ссылка.");
            if ((attributes & FileAttributes.Directory) == 0) { yield return entry; yield break; }
            if (Same(Path.GetFileName(entry), ".managed-release")) yield break;
            foreach (string child in Directory.EnumerateFileSystemEntries(entry))
                foreach (string file in Files(child)) yield return file;
        }

        private static byte[] Hash(Stream input)
        {
            using (var sha = SHA256.Create()) return sha.ComputeHash(input);
        }

        private static void CopyChecked(string source, string destination)
        {
            foreach (string file in DataFiles(source))
            {
                string target = Path.Combine(destination, file.Substring(source.Length + 1));
                Directory.CreateDirectory(Path.GetDirectoryName(target));
                byte[] expected;
                using (var input = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    using (var output = new FileStream(target, FileMode.CreateNew, FileAccess.Write)) input.CopyTo(output);
                    input.Position = 0;
                    expected = Hash(input);
                }
                using (var output = File.OpenRead(target))
                    if (!expected.SequenceEqual(Hash(output))) throw new IOException("Проверка копии рабочих данных не прошла.");
            }
        }

        private static void Extract(string destination)
        {
            using (var archive = new ZipArchive(Resource("Inei.Kit.zip"), ZipArchiveMode.Read))
                foreach (ZipArchiveEntry entry in archive.Entries)
                {
                    if (!entry.FullName.StartsWith(Root, StringComparison.Ordinal) || entry.FullName.Contains("\\"))
                        throw new InvalidDataException("Неверная структура комплекта.");
                    string relative = entry.FullName.Substring(Root.Length).Replace('/', Path.DirectorySeparatorChar);
                    if (relative.Length == 0) continue;
                    if (relative.IndexOf(':') >= 0 || relative.Split(Path.DirectorySeparatorChar).Any(part => part == ".." || part == "."))
                        throw new InvalidDataException("Неверный путь в комплекте.");
                    string path = Path.GetFullPath(Path.Combine(destination, relative));
                    if (!Below(path, destination)) throw new InvalidDataException("Неверный путь в комплекте.");
                    if (entry.Name.Length == 0) { Directory.CreateDirectory(path); continue; }
                    Directory.CreateDirectory(Path.GetDirectoryName(path));
                    using (var input = entry.Open())
                    using (var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write)) input.CopyTo(output);
                }
            if (File.ReadAllText(Path.Combine(destination, "PROFILE.txt")).Trim() != "public_node" ||
                !File.Exists(Path.Combine(destination, "runtime", "windows", "python.exe")) ||
                !File.Exists(Path.Combine(destination, "start_windows.bat")))
                throw new InvalidDataException("Ожидается публичный комплект узла Windows x64.");
        }

        private static string Stage(string destination)
        {
            string stage = destination + ".setup-" + Guid.NewGuid().ToString("N");
            Directory.CreateDirectory(stage);
            return stage;
        }

        private static void DeleteTemporary(string path)
        {
            if (path == null || !Directory.Exists(path)) return;
            try { Directory.Delete(path, true); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }

        private static string RecoveryPath(InstallOptions options) { return options.ProgramDirectory + ".inei-swap"; }

        internal static void RecordSwap(InstallPlan plan, string codeStage, string dataStage)
        {
            string path = RecoveryPath(plan.Options);
            string temporary = path + "-" + Guid.NewGuid().ToString("N");
            try
            {
                using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write))
                using (var record = new BinaryWriter(stream))
                {
                    record.Write(false);
                    record.Write("IneiSwap1");
                    record.Write(plan.Options.DataDirectory);
                    record.Write(plan.Options.Port);
                    record.Write(codeStage);
                    record.Write(dataStage);
                    record.Write(plan.ProgramBackup ?? "");
                    record.Write(plan.DataBackup ?? "");
                    record.Write(plan.ExistingProgram);
                    record.Write(plan.ExistingData);
                    record.Flush();
                    stream.Flush(true);
                }
                File.Move(temporary, path);
            }
            finally { if (File.Exists(temporary)) File.Delete(temporary); }
        }

        private static void CommitSwap(InstallOptions options)
        {
            string path = RecoveryPath(options);
            using (var stream = new FileStream(path, FileMode.Open, FileAccess.Write))
            {
                stream.WriteByte(1);
                stream.Flush(true);
            }
            try { File.Delete(path); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }

        private static string ValidateSwapPath(string value, string destination, string suffix)
        {
            string path = FullLocalPath(value);
            if (!Regex.IsMatch(path, "^" + Regex.Escape(destination) + suffix + "$", RegexOptions.IgnoreCase))
                throw new IOException("Не удалось проверить путь восстановления.");
            return path;
        }

        private static void RestoreFolder(string destination, string staged, string backup, bool existed, string marker)
        {
            bool originalMoved = existed && Directory.Exists(backup);
            bool candidateMoved = !Directory.Exists(staged) && Directory.Exists(destination) && (!existed || originalMoved);
            if (candidateMoved)
            {
                if (!File.Exists(Path.Combine(destination, marker))) throw new IOException("Не удалось проверить папку восстановления.");
                Directory.Move(destination, staged);
            }
            if (originalMoved) Directory.Move(backup, destination);
        }

        private static bool RecoverSwap(InstallOptions options)
        {
            string path = RecoveryPath(options);
            if (!File.Exists(path)) return false;
            using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var record = new BinaryReader(stream))
            {
                if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0 || stream.Length > 32768)
                    throw new IOException("Не удалось проверить журнал восстановления.");
                bool committed = record.ReadBoolean();
                if (record.ReadString() != "IneiSwap1" || !Same(record.ReadString(), options.DataDirectory))
                    throw new IOException("Для восстановления укажите прежний каталог рабочих данных.");
                int port = record.ReadInt32();
                string codeStage = ValidateSwapPath(record.ReadString(), options.ProgramDirectory, @"\.setup-[a-f0-9]{32}");
                string dataStage = ValidateSwapPath(record.ReadString(), options.DataDirectory, @"\.setup-[a-f0-9]{32}");
                string codeBackup = record.ReadString(), dataBackup = record.ReadString();
                bool existedCode = record.ReadBoolean(), existedData = record.ReadBoolean();
                const string backup = @"\.backup-[0-9]{8}-[0-9]{6}-[a-f0-9]{8}";
                if (existedCode) codeBackup = ValidateSwapPath(codeBackup, options.ProgramDirectory, backup);
                if (existedData) dataBackup = ValidateSwapPath(dataBackup, options.DataDirectory, backup);
                if (!committed)
                {
                    CheckPort(port);
                    RestoreFolder(options.DataDirectory, dataStage, dataBackup, existedData, DataMarker);
                    RestoreFolder(options.ProgramDirectory, codeStage, codeBackup, existedCode, ProgramMarker);
                }
            }
            File.Delete(path);
            return true;
        }

        public static void Install(InstallPlan plan, Action<int, string> progress, Action<InstallOptions> boot)
        {
            InstallOptions options = plan.Options;
            if (RecoverSwap(options))
            {
                InstallPlan recovered = Plan(options);
                plan.ProgramBackup = recovered.ProgramBackup;
                plan.DataBackup = recovered.DataBackup;
                plan.ExistingProgram = recovered.ExistingProgram;
                plan.ExistingData = recovered.ExistingData;
            }
            string codeStage = null, dataStage = null, backupStage = null;
            bool oldCodeMoved = false, oldDataMoved = false, codeInstalled = false, dataInstalled = false;
            bool journalRecorded = false, rollbackComplete = false;
            try
            {
                progress(10, "Распаковываем программу");
                codeStage = Stage(options.ProgramDirectory);
                Extract(codeStage);
                File.WriteAllText(Path.Combine(codeStage, ProgramMarker), PayloadVersion());
                progress(35, "Копируем и проверяем рабочие данные");
                dataStage = Stage(options.DataDirectory);
                if (options.PreviousData != null)
                {
                    CopyChecked(options.PreviousData, dataStage);
                    if (!Same(options.PreviousData, options.DataDirectory))
                    {
                        backupStage = Stage(options.DataDirectory);
                        CopyChecked(options.PreviousData, backupStage);
                        // The original source remains untouched even if installation fails.
                        Directory.Move(backupStage, plan.DataBackup);
                    }
                }
                SetConfig(dataStage, options.Port);
                File.WriteAllText(Path.Combine(dataStage, DataMarker), "Inei");
                using (Stream license = Resource("Inei.License.txt"))
                    File.WriteAllText(Path.Combine(dataStage, LicenseReceipt),
                        Convert.ToBase64String(Hash(license)) + "\n" + DateTimeOffset.UtcNow.ToString("O"));
                progress(65, "Переключаем программу на новый комплект");
                CheckPort(options.Port);
                RecordSwap(plan, codeStage, dataStage);
                journalRecorded = true;
                if (plan.ExistingProgram) { Directory.Move(options.ProgramDirectory, plan.ProgramBackup); oldCodeMoved = true; }
                if (plan.ExistingData)
                {
                    Directory.Move(options.DataDirectory, plan.DataBackup);
                    oldDataMoved = true;
                }
                if (!oldCodeMoved && Directory.Exists(options.ProgramDirectory)) Directory.Delete(options.ProgramDirectory);
                if (!oldDataMoved && Directory.Exists(options.DataDirectory)) Directory.Delete(options.DataDirectory);
                Directory.Move(codeStage, options.ProgramDirectory);
                codeInstalled = true;
                Directory.Move(dataStage, options.DataDirectory);
                dataInstalled = true;
                progress(85, "Проверяем запуск Инея");
                boot(options);
                CommitSwap(options);
                progress(100, "Иней готов к работе");
            }
            catch
            {
                progress(85, "Возвращаем прежние файлы");
                if (dataInstalled) Directory.Move(options.DataDirectory, dataStage);
                if (codeInstalled) Directory.Move(options.ProgramDirectory, codeStage);
                if (oldDataMoved) Directory.Move(plan.DataBackup, options.DataDirectory);
                if (oldCodeMoved) Directory.Move(plan.ProgramBackup, options.ProgramDirectory);
                if (journalRecorded) File.Delete(RecoveryPath(options));
                rollbackComplete = true;
                throw;
            }
            finally
            {
                if (rollbackComplete || !File.Exists(RecoveryPath(options)))
                {
                    DeleteTemporary(codeStage);
                    DeleteTemporary(dataStage);
                }
                DeleteTemporary(backupStage);
            }
        }
    }
}
