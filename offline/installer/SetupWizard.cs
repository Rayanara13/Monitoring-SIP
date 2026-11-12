using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Windows.Forms;

namespace IneiSetup
{
    internal static class EntryPoint
    {
        [STAThread]
        private static int Main(string[] args)
        {
            if (args.Length != 0 && (args[0] == "--firewall-add" || args[0] == "--firewall-remove"))
                return SetupWindows.FirewallCommand(args);
            bool acquired;
            using (var mutex = new Mutex(true, @"Local\IneiSetup-" + System.Security.Principal.WindowsIdentity.GetCurrent().User.Value, out acquired))
            {
                if (!acquired) return 1;
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                try { Application.Run(new Wizard(args.Length != 0 && args[0] == "--uninstall")); }
                catch (Exception error) { MessageBox.Show(error.Message, "Иней", MessageBoxButtons.OK, MessageBoxIcon.Error); return 1; }
                return 0;
            }
        }
    }

    internal sealed class Wizard : Form
    {
        private static readonly Color Background = Color.FromArgb(10, 17, 29);
        private static readonly Color Surface = Color.FromArgb(20, 34, 52);
        private static readonly Color TextColor = Color.FromArgb(236, 244, 255);
        private static readonly Color Muted = Color.FromArgb(175, 194, 218);
        private static readonly Color Accent = Color.FromArgb(159, 195, 255);
        private readonly InstallOptions installed, options;
        private readonly string version;
        private readonly Panel body;
        private readonly Label heading, feedback;
        private readonly Button next, back, cancel;
        private TableLayoutPanel column;
        private ComboBox action;
        private TextBox program, data, previous;
        private CheckBox accept, autostart, desktop, firewall, open, removeData;
        private NumericUpDown port;
        private int step;
        private bool accepted, busy, removing, migrate, repair, successful;
        private string report;
        private InstallPlan plan;
        private ProgressBar progress;

        public Wizard(bool uninstall)
        {
            version = SetupCore.PayloadVersion();
            installed = SetupWindows.Installed();
            options = new InstallOptions {
                ProgramDirectory = installed == null ? SetupWindows.DefaultProgram : installed.ProgramDirectory,
                DataDirectory = installed == null ? SetupWindows.DefaultData : installed.DataDirectory,
                Port = installed == null ? 8000 : installed.Port,
                Autostart = installed != null && installed.Autostart,
                Desktop = installed != null && installed.Desktop,
                Firewall = installed != null && installed.Firewall,
            };
            removing = uninstall && installed != null;
            Text = "Установка Инея " + version;
            Icon = System.Drawing.Icon.ExtractAssociatedIcon(Assembly.GetExecutingAssembly().Location);
            BackColor = Background;
            ForeColor = TextColor;
            Font = new Font("Segoe UI", 10);
            StartPosition = FormStartPosition.CenterScreen;
            AutoScaleMode = AutoScaleMode.Dpi;
            ClientSize = new Size(660, 500);
            MinimumSize = new Size(540, 420);

            var layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(24), RowCount = 4, ColumnCount = 1 };
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 70));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 48));
            var header = new Panel { Dock = DockStyle.Fill };
            var badge = new PictureBox { Width = 36, Height = 36, Location = new Point(0, 4), SizeMode = PictureBoxSizeMode.Zoom,
                Image = Icon.ToBitmap(), AccessibleName = "Иней" };
            heading = new Label { AutoSize = true, Font = new Font("Segoe UI", 16, FontStyle.Bold), Location = new Point(48, 0) };
            header.Controls.Add(badge);
            header.Controls.Add(heading);
            header.Controls.Add(new Label { AutoSize = true, Text = "Иней " + version + " by Стёпчик", ForeColor = Muted,
                                           Location = new Point(49, 32) });
            body = new Panel { Dock = DockStyle.Fill, AutoScroll = true };
            feedback = new Label { AutoSize = true, ForeColor = Color.FromArgb(255, 173, 174), MaximumSize = new Size(590, 0) };
            var footer = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.RightToLeft,
                                               WrapContents = false, Padding = new Padding(0, 4, 0, 0) };
            next = ButtonFor("&Далее", true, Advance);
            cancel = ButtonFor("&Отмена", false, Close);
            back = ButtonFor("&Назад", false, Previous);
            footer.Controls.AddRange(new Control[] { next, cancel, back });
            AcceptButton = next;
            CancelButton = cancel;
            layout.Controls.Add(header, 0, 0);
            layout.Controls.Add(body, 0, 1);
            layout.Controls.Add(feedback, 0, 2);
            layout.Controls.Add(footer, 0, 3);
            Controls.Add(layout);
            FormClosing += (sender, eventArgs) => { if (busy) eventArgs.Cancel = true; };
            Render();
        }

        private Button ButtonFor(string text, bool primary, Action run)
        {
            var button = new Button { Text = text, AutoSize = true, MinimumSize = new Size(104, 34), FlatStyle = FlatStyle.Flat,
                ForeColor = primary ? Background : TextColor, BackColor = primary ? Accent : Surface,
                Margin = new Padding(4, 4, 0, 0), UseVisualStyleBackColor = false };
            button.FlatAppearance.BorderColor = Color.FromArgb(58, 82, 115);
            button.Click += (sender, args) => run();
            return button;
        }

        private void ResetPage(string title)
        {
            heading.Text = title;
            feedback.Text = "";
            while (body.Controls.Count > 0) body.Controls[0].Dispose();
            column = new TableLayoutPanel { AutoSize = true, Dock = DockStyle.Top, ColumnCount = 1, RowCount = 0,
                                            Padding = new Padding(0, 0, 8, 0) };
            column.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            body.Controls.Add(column);
            back.Visible = step > 0 && step < 5;
            next.Enabled = true;
            next.Text = "&Далее";
            cancel.Enabled = true;
        }

        private void Add(Control control)
        {
            control.Dock = DockStyle.Top;
            control.Margin = new Padding(0, 0, 0, 8);
            int row = column.RowCount++;
            column.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            column.Controls.Add(control, 0, row);
        }

        private void Paragraph(string text, bool muted = false)
        {
            Add(new Label { Text = text, AutoSize = true, MaximumSize = new Size(570, 0), ForeColor = muted ? Muted : TextColor });
        }

        private CheckBox Choice(string text, bool value)
        {
            var checkbox = new CheckBox { Text = text, Checked = value, AutoSize = true, ForeColor = TextColor };
            Add(checkbox);
            return checkbox;
        }

        private TextBox DirectoryField(string label, string value, bool editable = true)
        {
            Paragraph(label);
            var row = new TableLayoutPanel { ColumnCount = 2, RowCount = 1, AutoSize = true };
            row.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            row.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            var box = new TextBox { Text = value ?? "", AccessibleName = label, Dock = DockStyle.Fill, ReadOnly = !editable,
                                    BackColor = Surface, ForeColor = TextColor, Margin = new Padding(0, 8, 8, 0) };
            row.Controls.Add(box, 0, 0);
            Button browse = ButtonFor("&Обзор…", false, () => {
                using (var chooser = new FolderBrowserDialog { Description = label, ShowNewFolderButton = true })
                {
                    if (Directory.Exists(box.Text)) chooser.SelectedPath = box.Text;
                    if (chooser.ShowDialog(this) == DialogResult.OK) box.Text = chooser.SelectedPath;
                }
            });
            browse.Enabled = editable;
            row.Controls.Add(browse, 1, 0);
            Add(row);
            return box;
        }

        private void Render()
        {
            switch (step)
            {
                case 0:
                    ResetPage("Мастер установки");
                    Paragraph(installed == null ? "Установите узел Инея на этот компьютер." :
                        "Обнаружена установка Инея. Папка программы — " + installed.ProgramDirectory + ".");
                    action = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, AccessibleName = "Действие",
                                            BackColor = Surface, ForeColor = TextColor };
                    if (installed == null)
                    {
                        action.Items.AddRange(new object[] { "Установить", "Установить и перенести данные" });
                        action.SelectedIndex = migrate ? 1 : 0;
                    }
                    else
                    {
                        action.Items.AddRange(new object[] { "Обновить", "Восстановить", "Удалить" });
                        action.SelectedIndex = removing ? 2 : repair ? 1 : 0;
                    }
                    Add(action);
                    Paragraph("Портативный Python и зависимости входят в комплект.", true);
                    break;
                case 1:
                    ResetPage("Лицензия и условия установки");
                    Add(new RichTextBox { Text = SetupCore.License(), ReadOnly = true, Height = 240, BorderStyle = BorderStyle.FixedSingle,
                                          BackColor = Surface, ForeColor = TextColor, AccessibleName = "Текст лицензии" });
                    var licenseButton = ButtonFor("Лицензии компонентов", false, ShowComponentLicenses);
                    Add(licenseButton);
                    accept = Choice("&Принимаю условия лицензии", accepted);
                    next.Enabled = accept.Checked;
                    accept.CheckedChanged += (sender, args) => next.Enabled = accept.Checked;
                    break;
                case 2:
                    ResetPage("Каталоги");
                    program = DirectoryField("Папка программы", options.ProgramDirectory, installed == null);
                    data = DirectoryField("Папка рабочих данных", options.DataDirectory, installed == null);
                    if (installed != null)
                    {
                        Paragraph("При обслуживании используются каталоги обнаруженной установки.", true);
                    }
                    else if (migrate) previous = DirectoryField("Папка прежней установки Rel 1.0 или 1.4.x", options.PreviousData);
                    Paragraph("Папки программы и рабочих данных выбираются отдельно.", true);
                    break;
                case 3:
                    ResetPage("Настройки");
                    autostart = Choice("Запускать Иней при входе в Windows", options.Autostart);
                    desktop = Choice("Создать ярлык на рабочем столе", options.Desktop);
                    firewall = Choice("Разрешить входящие подключения на выбранный порт в частной сети", options.Firewall);
                    open = Choice("Открыть панель после установки", options.OpenBrowser);
                    Paragraph("TCP-порт панели");
                    port = new NumericUpDown { Minimum = 1, Maximum = 65535, Value = options.Port, AccessibleName = "TCP-порт панели",
                                               BackColor = Surface, ForeColor = TextColor };
                    Add(port);
                    var address = new Label { Text = SetupWindows.PanelUrl(options), AutoSize = true, ForeColor = Accent };
                    port.ValueChanged += (sender, args) => address.Text = "http://127.0.0.1:" + port.Value;
                    Add(address);
                    Paragraph("Для изменения правила брандмауэра Windows запросит права администратора.", true);
                    break;
                case 4:
                    ResetPage(removing ? "Удаление Инея" : repair ? "Проверка перед восстановлением" : "Проверка перед установкой");
                    if (removing)
                    {
                        Paragraph("Будет удалена программа из папки " + options.ProgramDirectory + ".");
                        removeData = Choice("Удалить также рабочие данные из папки " + options.DataDirectory, false);
                        Paragraph("При удалении данных будут потеряны настройки, учётные записи и история в этой папке.", true);
                        next.Text = "&Удалить";
                    }
                    else
                    {
                        Paragraph("Версия " + version + " · TCP-порт " + options.Port + " свободен");
                        Paragraph("Программа — " + options.ProgramDirectory);
                        Paragraph("Рабочие данные — " + options.DataDirectory);
                        if (plan.Options.PreviousData != null) Paragraph("Перенос данных из " + plan.Options.PreviousData);
                        if (plan.DataBackup != null) Paragraph("Резервная копия — " + plan.DataBackup);
                        Paragraph("Потребуется примерно " + Math.Ceiling(plan.RequiredBytes / 1048576.0) + " МБ. Свободного места достаточно.", true);
                        Paragraph("Настройки — " + SummaryOptions(), true);
                        next.Text = installed == null ? "&Установить" : repair ? "&Восстановить" : "&Обновить";
                    }
                    break;
                case 5:
                    ResetPage(removing ? "Удаляем Иней" : "Устанавливаем Иней");
                    progress = new ProgressBar { Height = 20, Minimum = 0, Maximum = 100 };
                    Add(progress);
                    next.Enabled = cancel.Enabled = false;
                    break;
                case 6:
                    ResetPage(successful ? "Готово" : "Операция не завершена");
                    Paragraph(report);
                    if (successful && !removing)
                        Add(ButtonFor("Открыть Иней", true, () => SetupWindows.OpenPanel(options)));
                    if (!removing)
                    {
                        Add(ButtonFor("Сохранить отчёт", false, SaveReport));
                        if (File.Exists(Path.Combine(options.ProgramDirectory, "diagnose_windows.bat")))
                            Add(ButtonFor("Запустить диагностику", false, () => Process.Start(new ProcessStartInfo(
                                Path.Combine(options.ProgramDirectory, "diagnose_windows.bat"),
                                "--data-dir \"" + options.DataDirectory + "\"") { UseShellExecute = true, WorkingDirectory = options.ProgramDirectory })));
                    }
                    cancel.Visible = false;
                    next.Text = "&Готово";
                    break;
            }
        }

        private string SummaryOptions()
        {
            var entries = new List<string> { "ярлык в меню «Пуск»" };
            if (options.Autostart) entries.Add("автозапуск при входе");
            if (options.Desktop) entries.Add("ярлык на рабочем столе");
            if (options.Firewall) entries.Add("правило брандмауэра");
            if (options.OpenBrowser) entries.Add("открытие панели");
            return String.Join(", ", entries);
        }

        private void Advance()
        {
            try
            {
                switch (step)
                {
                    case 0:
                        removing = installed != null && action.SelectedIndex == 2;
                        repair = installed != null && action.SelectedIndex == 1;
                        migrate = installed == null && action.SelectedIndex == 1;
                        if (!migrate) options.PreviousData = null;
                        step = removing ? 4 : 1;
                        break;
                    case 1:
                        if (!accept.Checked) return;
                        accepted = true;
                        step = 2;
                        break;
                    case 2:
                        options.ProgramDirectory = SetupCore.FullLocalPath(program.Text);
                        options.DataDirectory = SetupCore.FullLocalPath(data.Text);
                        SetupWindows.ValidateDirectories(options);
                        if (migrate)
                        {
                            options.PreviousData = SetupCore.FindData(previous.Text);
                            options.Port = SetupCore.ReadPort(options.PreviousData);
                        }
                        step = 3;
                        break;
                    case 3:
                        ReadSettings();
                        plan = SetupCore.Plan(options);
                        step = 4;
                        break;
                    case 4:
                        RunOperation();
                        return;
                    case 6:
                        Close();
                        return;
                }
                Render();
            }
            catch (Exception error) { feedback.Text = error.Message; }
        }

        private void ReadSettings()
        {
            options.Port = Decimal.ToInt32(port.Value);
            options.Autostart = autostart.Checked;
            options.Desktop = desktop.Checked;
            options.Firewall = firewall.Checked;
            options.OpenBrowser = open.Checked;
        }

        private void Previous()
        {
            if (step == 1) accepted = accept.Checked;
            if (step == 3) ReadSettings();
            step = removing ? 0 : step - 1;
            Render();
        }

        private void RunOperation()
        {
            bool deleteData = removing && removeData.Checked;
            if (deleteData && MessageBox.Show(this, "Удалить рабочие данные из " + options.DataDirectory + "?", "Иней",
                    MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            busy = true;
            step = 5;
            Render();
            var worker = new BackgroundWorker { WorkerReportsProgress = true };
            worker.ProgressChanged += (sender, args) => { progress.Value = args.ProgressPercentage; feedback.Text = (string)args.UserState; };
            worker.DoWork += (sender, args) =>
            {
                if (removing) SetupWindows.Uninstall(installed, deleteData);
                else
                {
                    SetupCore.Install(plan, (percent, message) => worker.ReportProgress(percent, message), SetupWindows.StartAndVerify);
                    args.Result = SetupWindows.Integrate(options, installed);
                }
            };
            worker.RunWorkerCompleted += (sender, args) =>
            {
                busy = false;
                successful = args.Error == null;
                report = successful ? (removing ? (deleteData ? "Программа и выбранные рабочие данные удалены." :
                    "Программа удалена. Рабочие данные сохранены.") : "Иней запущен. Панель доступна по адресу " + SetupWindows.PanelUrl(options) + ".") :
                    args.Error.Message + "\nПрограмма — " + options.ProgramDirectory + "\nРабочие данные — " + options.DataDirectory;
                if (successful && !removing && args.Result is List<string>)
                {
                    string credentials = Path.Combine(options.DataDirectory, "users_data", "first-start.txt");
                    if (File.Exists(credentials)) report += "\nДанные для первого входа — " + credentials;
                    foreach (string warning in (List<string>)args.Result) report += "\n" + warning;
                    if (options.OpenBrowser)
                        try { SetupWindows.OpenPanel(options); }
                        catch (Exception) { report += "\nОткрыть браузер автоматически не удалось."; }
                }
                if (!successful && !removing)
                {
                    string marker = Path.Combine(options.ProgramDirectory, SetupCore.ProgramMarker);
                    if (File.Exists(marker)) report += "\nВерсия в папке программы — " + File.ReadAllText(marker).Trim() + ".";
                    if (plan.DataBackup != null && Directory.Exists(plan.DataBackup)) report += "\nРезервная копия — " + plan.DataBackup;
                }
                step = 6;
                Render();
                worker.Dispose();
            };
            worker.RunWorkerAsync();
        }

        private void ShowComponentLicenses()
        {
            using (var dialog = new Form { Text = "Лицензии компонентов", StartPosition = FormStartPosition.CenterParent,
                       Size = new Size(620, 430), Font = Font, BackColor = Background, ForeColor = TextColor })
            {
                dialog.Controls.Add(new RichTextBox { Dock = DockStyle.Fill, Text = SetupCore.ComponentLicenses(), ReadOnly = true,
                                                      BackColor = Surface, ForeColor = TextColor });
                dialog.ShowDialog(this);
            }
        }

        private void SaveReport()
        {
            using (var chooser = new SaveFileDialog { FileName = "inei-setup.txt", Filter = "Текстовый отчёт (*.txt)|*.txt" })
                if (chooser.ShowDialog(this) == DialogResult.OK) File.WriteAllText(chooser.FileName, "Иней " + version + "\n" + report);
        }
    }
}
