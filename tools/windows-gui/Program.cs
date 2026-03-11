// ObsidianQ Launcher --- WinForms .NET 8 GUI wrapper
// Calls obsidianq.exe via stdin for password; never passes secrets via CLI args.
// Cyberpunk aesthetic: #050807 bg, #00FF7A neon green accent, monospace console.
// Tabbed layout: [FILE] encrypt/decrypt files  [TEXT] encrypt/decrypt text  [VAULT] mount drive

using System.Diagnostics;
using System.IO.Compression;
using System.IO.Pipes;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32;

[assembly: System.Runtime.Versioning.SupportedOSPlatform("windows")]

namespace ObsidianQ.Launcher;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------
static class Program
{
    private const string SingleInstanceMutexName = @"Local\ObsidianQ.Launcher.SingleInstance";
    private static readonly string SingleInstancePipeName = $"ObsidianQ.Launcher.Pipe.{Environment.UserName}";
    private const string EmbeddedSfxMagic = "OBSQSFX1";
    private const int EmbeddedSfxTrailerSize = 24; // zipLen(8) + cliLen(8) + magic(8)

    private sealed record LaunchIntent(
        bool CreateVaultOnStart,
        string? PreloadPath,
        string? CreateVaultTarget,
        bool CreatePackageOnStart,
        string? CreatePackageTarget,
        bool EncryptFolderOnStart,
        string? EncryptFolderTarget);
    private sealed record EmbeddedSfxInfo(long PackageOffset, long PackageLength, long CliOffset, long CliLength);

    private static void LogStartup(string[] args)
    {
        try
        {
            string dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "ObsidianQ");
            Directory.CreateDirectory(dir);
            string log = Path.Combine(dir, "launcher_startup.log");
            string line = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} | pid={Environment.ProcessId} | exe={Environment.ProcessPath} | args=[{string.Join(" ", args)}]{Environment.NewLine}";
            File.AppendAllText(log, line);
        }
        catch { /* best effort */ }
    }

    [STAThread]
    static void Main(string[] args)
    {
        LogStartup(args);

        string hostExePath = Environment.ProcessPath ?? Application.ExecutablePath;
        if (TryGetEmbeddedSfxInfo(hostExePath, out var sfxInfo))
        {
            Application.SetHighDpiMode(HighDpiMode.SystemAware);
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            RunEmbeddedSfxExtractor(hostExePath, sfxInfo);
            return;
        }

        using var singleInstanceMutex = new Mutex(true, SingleInstanceMutexName, out bool isFirstInstance);
        if (!isFirstInstance)
        {
            TrySignalExistingInstance(args);
            return;
        }

        Application.SetHighDpiMode(HighDpiMode.SystemAware);
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);

        var launch = ParseLaunchIntent(args);
        using var cts = new CancellationTokenSource();
        var form = new MainForm(
            launch.PreloadPath,
            launch.CreateVaultOnStart,
            launch.CreateVaultTarget,
            launch.CreatePackageOnStart,
            launch.CreatePackageTarget,
            launch.EncryptFolderOnStart,
            launch.EncryptFolderTarget);
        _ = RunSingleInstanceServerAsync(form, cts.Token);
        Application.ApplicationExit += (_, _) => cts.Cancel();
        Application.Run(form);
    }

    private static bool TryGetEmbeddedSfxInfo(string hostExePath, out EmbeddedSfxInfo info)
    {
        info = new EmbeddedSfxInfo(0, 0, 0, 0);
        try
        {
            using var fs = new FileStream(hostExePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            if (fs.Length <= EmbeddedSfxTrailerSize) return false;
            fs.Seek(-EmbeddedSfxTrailerSize, SeekOrigin.End);
            byte[] trailer = new byte[EmbeddedSfxTrailerSize];
            int read = fs.Read(trailer, 0, trailer.Length);
            if (read != trailer.Length) return false;

            string magic = Encoding.ASCII.GetString(trailer, 16, 8);
            if (!string.Equals(magic, EmbeddedSfxMagic, StringComparison.Ordinal)) return false;

            long packageLen = BitConverter.ToInt64(trailer, 0);
            long cliLen = BitConverter.ToInt64(trailer, 8);
            if (packageLen <= 0 || cliLen <= 0) return false;

            long payloadStart = fs.Length - EmbeddedSfxTrailerSize - packageLen - cliLen;
            if (payloadStart < 0) return false;
            long cliOffset = payloadStart + packageLen;
            if (cliOffset < 0 || cliOffset + cliLen > fs.Length) return false;

            info = new EmbeddedSfxInfo(payloadStart, packageLen, cliOffset, cliLen);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static void CopyRangeToFile(string sourcePath, long offset, long length, string destinationPath)
    {
        using var src = new FileStream(sourcePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using var dst = new FileStream(destinationPath, FileMode.Create, FileAccess.Write, FileShare.None);
        src.Seek(offset, SeekOrigin.Begin);
        byte[] buffer = new byte[128 * 1024];
        long remaining = length;
        while (remaining > 0)
        {
            int want = (int)Math.Min(buffer.Length, remaining);
            int n = src.Read(buffer, 0, want);
            if (n <= 0) throw new EndOfStreamException("Unexpected end of embedded payload.");
            dst.Write(buffer, 0, n);
            remaining -= n;
        }
    }

    private static string? PromptForPassword()
    {
        using var dlg = new Form
        {
            Text = "Decrypt Package",
            StartPosition = FormStartPosition.CenterScreen,
            FormBorderStyle = FormBorderStyle.FixedDialog,
            MaximizeBox = false,
            MinimizeBox = false,
            ShowInTaskbar = true,
            ClientSize = new Size(460, 130),
            BackColor = Theme.Bg,
            ForeColor = Theme.TextMain,
            Font = Theme.SafeMono(9f),
        };
        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 4, Padding = new Padding(12), BackColor = Theme.Bg };
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 20));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 34));
        var lbl = new Label
        {
            Text = "Enter password to decrypt package:",
            Dock = DockStyle.Fill,
            ForeColor = Theme.TextMain,
            BackColor = Theme.Bg,
            TextAlign = ContentAlignment.MiddleLeft,
        };
        var txt = new TextBox
        {
            Dock = DockStyle.Fill,
            UseSystemPasswordChar = true,
            BackColor = Theme.Surface,
            ForeColor = Theme.Accent,
            BorderStyle = BorderStyle.FixedSingle,
        };
        var actions = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, BackColor = Theme.Bg };
        actions.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        actions.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        var btnCancel = new NeonButton { Text = "CANCEL", Dock = DockStyle.Fill, Margin = new Padding(0, 0, 4, 0) };
        var btnOk = new NeonButton { Text = "DECRYPT", Dock = DockStyle.Fill, Margin = new Padding(4, 0, 0, 0) };
        btnCancel.Click += (_, _) => { dlg.DialogResult = DialogResult.Cancel; dlg.Close(); };
        btnOk.Click += (_, _) =>
        {
            if (string.IsNullOrWhiteSpace(txt.Text))
            {
                MessageBox.Show(dlg, "Password is required.", "Decrypt Package", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            dlg.DialogResult = DialogResult.OK;
            dlg.Close();
        };
        actions.Controls.Add(btnCancel, 0, 0);
        actions.Controls.Add(btnOk, 1, 0);
        root.Controls.Add(lbl, 0, 0);
        root.Controls.Add(txt, 0, 1);
        root.Controls.Add(new Panel { Dock = DockStyle.Fill, BackColor = Theme.Bg }, 0, 2);
        root.Controls.Add(actions, 0, 3);
        dlg.Controls.Add(root);
        return dlg.ShowDialog() == DialogResult.OK ? txt.Text : null;
    }

    private static void RunEmbeddedSfxExtractor(string hostExePath, EmbeddedSfxInfo sfx)
    {
        string? password = PromptForPassword();
        if (password == null) return;
        string tempRoot = Path.Combine(Path.GetTempPath(), $"obsq_sfx_run_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempRoot);
        string pkgPath = Path.Combine(tempRoot, "package.zip");
        string cliPath = Path.Combine(tempRoot, "obsidianq.exe");
        string probeOutDir = Path.Combine(tempRoot, "probe_out");

        try
        {
            CopyRangeToFile(hostExePath, sfx.PackageOffset, sfx.PackageLength, pkgPath);
            CopyRangeToFile(hostExePath, sfx.CliOffset, sfx.CliLength, cliPath);

            var psi = new ProcessStartInfo
            {
                FileName = cliPath,
                Arguments = $"delivery extract \"{pkgPath}\" --out \"{probeOutDir}\" --password-stdin",
                UseShellExecute = false,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            using var proc = Process.Start(psi);
            if (proc == null) throw new InvalidOperationException("Failed to start embedded extractor.");

            proc.StandardInput.WriteLine(password);
            proc.StandardInput.Close();
            string stdout = proc.StandardOutput.ReadToEnd();
            string stderr = proc.StandardError.ReadToEnd();
            proc.WaitForExit();

            if (proc.ExitCode != 0)
            {
                string detail = (string.IsNullOrWhiteSpace(stderr) ? stdout : stderr).Trim();
                bool likelyBadPassword =
                    detail.Contains("PayloadCorrupt", StringComparison.OrdinalIgnoreCase) ||
                    detail.Contains("decrypt payload", StringComparison.OrdinalIgnoreCase) ||
                    detail.Contains("password", StringComparison.OrdinalIgnoreCase);
                string message = likelyBadPassword
                    ? "Incorrect password or corrupted package."
                    : (string.IsNullOrWhiteSpace(detail) ? $"Extractor failed (exit {proc.ExitCode})." : detail);
                MessageBox.Show(message, "ObsidianQ", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            string baseDir = Path.GetDirectoryName(hostExePath) ?? Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
            string stem = Path.GetFileNameWithoutExtension(hostExePath);
            string defaultOutDir = Path.Combine(baseDir, $"{stem}_Extracted");

            var pick = MessageBox.Show(
                "Password Verified.\n\nDecrypt file/files to the same folder?",
                "ObsidianQ",
                MessageBoxButtons.YesNoCancel,
                MessageBoxIcon.Question,
                MessageBoxDefaultButton.Button1);
            if (pick == DialogResult.Cancel) return;

            string outDir = defaultOutDir;
            if (pick == DialogResult.No)
            {
                using var folder = new FolderBrowserDialog
                {
                    Description = "Choose where to extract files",
                    UseDescriptionForTitle = true,
                    ShowNewFolderButton = true,
                    SelectedPath = baseDir,
                };
                if (folder.ShowDialog() != DialogResult.OK || string.IsNullOrWhiteSpace(folder.SelectedPath))
                    return;
                outDir = folder.SelectedPath;
            }

            Directory.CreateDirectory(outDir);
            MoveExtractedContentsSafe(probeOutDir, outDir);
            MessageBox.Show("Decryption complete.", "ObsidianQ", MessageBoxButtons.OK, MessageBoxIcon.Information);
            try { Process.Start(new ProcessStartInfo("explorer.exe", $"\"{outDir}\"") { UseShellExecute = true }); } catch { }
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "ObsidianQ", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        finally
        {
            try { Directory.Delete(tempRoot, recursive: true); } catch { }
        }
    }

    private static void MoveExtractedContentsSafe(string sourceRoot, string targetRoot)
    {
        if (!Directory.Exists(sourceRoot))
            throw new DirectoryNotFoundException($"Extracted source folder not found: {sourceRoot}");
        Directory.CreateDirectory(targetRoot);

        foreach (string dir in Directory.GetDirectories(sourceRoot))
        {
            string name = Path.GetFileName(dir);
            string desired = Path.Combine(targetRoot, name);
            string final = GetUniquePath(desired, isDirectory: true);
            DirectoryCopyRecursive(dir, final);
        }
        foreach (string file in Directory.GetFiles(sourceRoot))
        {
            string name = Path.GetFileName(file);
            string desired = Path.Combine(targetRoot, name);
            string final = GetUniquePath(desired, isDirectory: false);
            File.Copy(file, final, overwrite: false);
        }
    }

    private static void DirectoryCopyRecursive(string sourceDir, string targetDir)
    {
        Directory.CreateDirectory(targetDir);
        foreach (string file in Directory.GetFiles(sourceDir))
        {
            string name = Path.GetFileName(file);
            string desired = Path.Combine(targetDir, name);
            string final = GetUniquePath(desired, isDirectory: false);
            File.Copy(file, final, overwrite: false);
        }
        foreach (string dir in Directory.GetDirectories(sourceDir))
        {
            string name = Path.GetFileName(dir);
            string desired = Path.Combine(targetDir, name);
            string final = GetUniquePath(desired, isDirectory: true);
            DirectoryCopyRecursive(dir, final);
        }
    }

    private static string GetUniquePath(string desiredPath, bool isDirectory)
    {
        if (isDirectory ? !Directory.Exists(desiredPath) : !File.Exists(desiredPath))
            return desiredPath;
        string parent = Path.GetDirectoryName(desiredPath) ?? Environment.CurrentDirectory;
        string name = Path.GetFileNameWithoutExtension(desiredPath);
        string ext = Path.GetExtension(desiredPath);
        for (int i = 1; i < 10_000; i++)
        {
            string candidateName = isDirectory ? $"{name} ({i})" : $"{name} ({i}){ext}";
            string candidate = Path.Combine(parent, candidateName);
            if (isDirectory ? !Directory.Exists(candidate) : !File.Exists(candidate))
                return candidate;
        }
        throw new IOException("Unable to resolve non-conflicting output path.");
    }

    private static LaunchIntent ParseLaunchIntent(string[] args)
    {
        bool createVaultOnStart = args.Any(a => string.Equals(a, "--create-vault", StringComparison.OrdinalIgnoreCase));
        bool createPackageOnStart = args.Any(a => string.Equals(a, "--create-package", StringComparison.OrdinalIgnoreCase));
        bool encryptFolderOnStart = args.Any(a => string.Equals(a, "--encrypt-folder", StringComparison.OrdinalIgnoreCase));
        string? positionalPath = args.FirstOrDefault(a => !a.StartsWith("-"));
        bool positionalExists = positionalPath != null && (File.Exists(positionalPath) || Directory.Exists(positionalPath));
        string? preloadPath = (!createVaultOnStart && !createPackageOnStart && !encryptFolderOnStart && positionalPath != null && File.Exists(positionalPath))
            ? positionalPath
            : null;
        string? createVaultTarget = createVaultOnStart ? positionalPath : null;
        string? createPackageTarget = (createPackageOnStart && positionalExists) ? positionalPath : null;
        string? encryptFolderTarget = (encryptFolderOnStart && positionalPath != null && Directory.Exists(positionalPath)) ? positionalPath : null;
        return new LaunchIntent(
            createVaultOnStart,
            preloadPath,
            createVaultTarget,
            createPackageOnStart,
            createPackageTarget,
            encryptFolderOnStart,
            encryptFolderTarget);
    }

    private static bool TrySignalExistingInstance(string[] args)
    {
        var launch = ParseLaunchIntent(args);
        string payload = Convert.ToBase64String(Encoding.UTF8.GetBytes(
            $"{(launch.CreateVaultOnStart ? "1" : "0")}\t{launch.PreloadPath ?? string.Empty}\t{launch.CreateVaultTarget ?? string.Empty}\t{(launch.CreatePackageOnStart ? "1" : "0")}\t{launch.CreatePackageTarget ?? string.Empty}\t{(launch.EncryptFolderOnStart ? "1" : "0")}\t{launch.EncryptFolderTarget ?? string.Empty}"));
        for (int i = 0; i < 5; i++)
        {
            try
            {
                using var client = new NamedPipeClientStream(".", SingleInstancePipeName, PipeDirection.Out);
                client.Connect(250);
                using var writer = new StreamWriter(client, Encoding.UTF8, 1024, leaveOpen: true) { AutoFlush = true };
                writer.WriteLine(payload);
                return true;
            }
            catch
            {
                Thread.Sleep(120);
            }
        }
        return false;
    }

    private static async Task RunSingleInstanceServerAsync(MainForm form, CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            try
            {
                using var server = new NamedPipeServerStream(
                    SingleInstancePipeName,
                    PipeDirection.In,
                    1,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous);
                await server.WaitForConnectionAsync(token);
                using var reader = new StreamReader(server, Encoding.UTF8, true, 1024, leaveOpen: true);
                string? line = await reader.ReadLineAsync();
                if (string.IsNullOrWhiteSpace(line)) continue;

                string decoded;
                try { decoded = Encoding.UTF8.GetString(Convert.FromBase64String(line)); }
                catch { continue; }
                string[] parts = decoded.Split('\t');
                bool createVaultOnStart = parts.Length > 0 && parts[0] == "1";
                string? preloadPath = parts.Length > 1 && !string.IsNullOrWhiteSpace(parts[1]) ? parts[1] : null;
                string? createVaultTarget = parts.Length > 2 && !string.IsNullOrWhiteSpace(parts[2]) ? parts[2] : null;
                bool createPackageOnStart = parts.Length > 3 && parts[3] == "1";
                string? createPackageTarget = parts.Length > 4 && !string.IsNullOrWhiteSpace(parts[4]) ? parts[4] : null;
                bool encryptFolderOnStart = parts.Length > 5 && parts[5] == "1";
                string? encryptFolderTarget = parts.Length > 6 && !string.IsNullOrWhiteSpace(parts[6]) ? parts[6] : null;
                form.BeginInvoke(new Action(() =>
                    form.HandleExternalLaunch(
                        preloadPath,
                        createVaultOnStart,
                        createVaultTarget,
                        createPackageOnStart,
                        createPackageTarget,
                        encryptFolderOnStart,
                        encryptFolderTarget)));
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch
            {
                await Task.Delay(150, token);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Colour palette & fonts (all centralised)
// ---------------------------------------------------------------------------
static class Theme
{
    public static readonly Color Bg        = Color.FromArgb(0xFF, 0x05, 0x08, 0x07);
    public static readonly Color Surface   = Color.FromArgb(0xFF, 0x0B, 0x12, 0x0F);
    public static readonly Color Border    = Color.FromArgb(0xFF, 0x00, 0x55, 0x30);
    public static readonly Color Accent    = Color.FromArgb(0xFF, 0x00, 0xFF, 0x7A);
    public static readonly Color AccentDim = Color.FromArgb(0xFF, 0x00, 0xAA, 0x50);
    public static readonly Color TextMain  = Color.FromArgb(0xFF, 0xCC, 0xFF, 0xDD);
    public static readonly Color TextDim   = Color.FromArgb(0xFF, 0x44, 0x77, 0x55);
    public static readonly Color Error     = Color.FromArgb(0xFF, 0xFF, 0x33, 0x55);
    public static readonly Color LogBg     = Color.FromArgb(0xFF, 0x02, 0x06, 0x04);

    public static Font Mono(float size) => new("Cascadia Mono", size, FontStyle.Regular, GraphicsUnit.Point);
    public static Font MonoBold(float size) => new("Cascadia Mono", size, FontStyle.Bold, GraphicsUnit.Point);

    // Fallback chain: Cascadia --- Consolas --- Courier New
    public static Font SafeMono(float size)
    {
        foreach (string name in new[] { "Cascadia Mono", "Cascadia Code", "Consolas", "Courier New" })
            if (FontFamily.Families.Any(f => f.Name == name))
                return new Font(name, size, FontStyle.Regular, GraphicsUnit.Point);
        return new Font(FontFamily.GenericMonospace, size, FontStyle.Regular, GraphicsUnit.Point);
    }
}

// ---------------------------------------------------------------------------
// Custom flat button with neon border + hover glow
// ---------------------------------------------------------------------------
class NeonButton : Button
{
    private bool _hovered;
    public NeonButton()
    {
        FlatStyle = FlatStyle.Flat;
        FlatAppearance.BorderSize = 0;
        BackColor = Theme.Bg;
        ForeColor = Theme.Accent;
        Font = Theme.SafeMono(9f);
        Cursor = Cursors.Hand;
        UseVisualStyleBackColor = false;
        SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
    }
    protected override void OnMouseEnter(EventArgs e) { _hovered = true; Invalidate(); base.OnMouseEnter(e); }
    protected override void OnMouseLeave(EventArgs e) { _hovered = false; Invalidate(); base.OnMouseLeave(e); }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.None;
        var rc = ClientRectangle;
        if (rc.Width <= 1 || rc.Height <= 1) return;

        using var bgBrush = new SolidBrush(_hovered ? Theme.Surface : Theme.Bg);
        g.FillRectangle(bgBrush, rc);

        using var pen = new Pen(_hovered ? Theme.Accent : Theme.AccentDim, 1f) { Alignment = System.Drawing.Drawing2D.PenAlignment.Inset };
        g.DrawRectangle(pen, rc.X, rc.Y, rc.Width - 1, rc.Height - 1);

        if (_hovered)
        {
            using var glowPen = new Pen(Color.FromArgb(40, Theme.Accent), 3f);
            g.DrawRectangle(glowPen, rc.X + 1, rc.Y + 1, rc.Width - 3, rc.Height - 3);
        }

        Color textColor = Enabled
            ? (_hovered ? Theme.Accent : Theme.TextMain)
            : Theme.AccentDim;
        TextRenderer.DrawText(
            g,
            Text,
            Font,
            new Rectangle(rc.X, rc.Y, rc.Width, rc.Height),
            textColor,
            TextFormatFlags.HorizontalCenter
            | TextFormatFlags.VerticalCenter
            | TextFormatFlags.EndEllipsis
            | TextFormatFlags.NoPrefix);
    }
}

// ---------------------------------------------------------------------------
// Segmented toggle: two states (PASSWORD | PQC)
// ---------------------------------------------------------------------------
class SegmentedToggle : Control
{
    public enum Segment { Password, Pqc }
    public Segment Selected { get; private set; } = Segment.Password;
    public event EventHandler? SelectionChanged;
    public string LeftLabel { get; set; } = "PASSWORD";
    public string RightLabel { get; set; } = "PQC";

    public SegmentedToggle()
    {
        SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
        Height = 32;
        Cursor = Cursors.Hand;
        Font = Theme.SafeMono(8.5f);
    }

    protected override void OnMouseClick(MouseEventArgs e)
    {
        int half = Width / 2;
        Segment clicked = e.X < half ? Segment.Password : Segment.Pqc;
        SetSelected(clicked);
        base.OnMouseClick(e);
    }

    public void SetSelected(Segment segment)
    {
        if (segment == Selected) return;
        Selected = segment;
        Invalidate();
        SelectionChanged?.Invoke(this, EventArgs.Empty);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.None;
        if (Width <= 1 || Height <= 1) return;
        int half = Width / 2;
        var leftRect = new Rectangle(0, 0, half, Height - 1);
        var rightRect = new Rectangle(half, 0, Width - half, Height - 1);

        using var leftBg = new SolidBrush(Selected == Segment.Password ? Color.FromArgb(30, Theme.Accent) : Theme.Bg);
        using var rightBg = new SolidBrush(Selected == Segment.Pqc ? Color.FromArgb(30, Theme.Accent) : Theme.Bg);
        g.FillRectangle(leftBg, leftRect);
        g.FillRectangle(rightBg, rightRect);

        using var outerBorder = new Pen(Theme.Border, 1f);
        g.DrawRectangle(outerBorder, 0, 0, Width - 1, Height - 1);

        using var splitPen = new Pen(Theme.Border, 1f);
        g.DrawLine(splitPen, half, 0, half, Height - 1);

        using var activeBorder = new Pen(Theme.Accent, 1f);
        var activeRect = Selected == Segment.Password
            ? new Rectangle(0, 0, Math.Max(1, half), Height - 1)
            : new Rectangle(half, 0, Math.Max(1, Width - half), Height - 1);
        g.DrawRectangle(activeBorder, activeRect.X, activeRect.Y, activeRect.Width - 1, activeRect.Height);

        using var sf = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center };
        using var leftTextBrush = new SolidBrush(Selected == Segment.Password ? Theme.Accent : Theme.TextDim);
        using var rightTextBrush = new SolidBrush(Selected == Segment.Pqc ? Theme.Accent : Theme.TextDim);
        g.DrawString(LeftLabel, Font, leftTextBrush, new RectangleF(leftRect.X, leftRect.Y, leftRect.Width, leftRect.Height), sf);
        g.DrawString(RightLabel, Font, rightTextBrush, new RectangleF(rightRect.X, rightRect.Y, rightRect.Width, rightRect.Height), sf);
    }
}

// ---------------------------------------------------------------------------
// Scanline overlay panel --- draws faint horizontal lines over a child control
// ---------------------------------------------------------------------------
class ScanlineOverlay : Panel
{
    public ScanlineOverlay()
    {
        SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint |
                 ControlStyles.SupportsTransparentBackColor, true);
        BackColor = Color.Transparent;
    }

    protected override void OnPaintBackground(PaintEventArgs e) { /* transparent */ }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        using var pen = new Pen(Color.FromArgb(12, 0, 0, 0), 1f);
        for (int y = 0; y < Height; y += 2)
            g.DrawLine(pen, 0, y, Width, y);
    }

    // Let mouse events pass through to children.
    protected override void WndProc(ref Message m)
    {
        const int WM_NCHITTEST = 0x0084;
        const int HTTRANSPARENT = -1;
        if (m.Msg == WM_NCHITTEST) { m.Result = (IntPtr)HTTRANSPARENT; return; }
        base.WndProc(ref m);
    }
}

static class ShellRefresh
{
    [DllImport("shell32.dll")]
    private static extern void SHChangeNotify(int wEventId, uint uFlags, IntPtr dwItem1, IntPtr dwItem2);

    public static void NotifyAssocChanged()
    {
        const int SHCNE_ASSOCCHANGED = 0x08000000;
        const uint SHCNF_IDLIST = 0x0000;
        SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, IntPtr.Zero, IntPtr.Zero);
    }
}

// ---------------------------------------------------------------------------
// Shimmer strip --- animated top-line effect during active operation
// ---------------------------------------------------------------------------
class ShimmerStrip : Control
{
    private float _pos;
    private readonly System.Windows.Forms.Timer _timer;
    public bool Running { get; private set; }

    public ShimmerStrip()
    {
        Height = 3;
        SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
        BackColor = Theme.Bg;
        _timer = new System.Windows.Forms.Timer { Interval = 16 };
        _timer.Tick += (_, _) => { _pos = (_pos + 0.015f) % 1.0f; Invalidate(); };
    }

    public void Start() { _pos = 0f; Running = true; _timer.Start(); Invalidate(); }
    public void Stop()  { Running = false; _timer.Stop(); Invalidate(); }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.Clear(Theme.Bg);
        if (!Running) return;

        float cx = _pos * (Width + 200) - 100;
        using var brush = new System.Drawing.Drawing2D.LinearGradientBrush(
            new PointF(cx - 80, 0), new PointF(cx + 80, 0),
            Color.Transparent, Color.Transparent);
        brush.InterpolationColors = new System.Drawing.Drawing2D.ColorBlend
        {
            Colors = [Color.Transparent, Theme.Accent, Color.White, Theme.Accent, Color.Transparent],
            Positions = [0f, 0.3f, 0.5f, 0.7f, 1f]
        };
        g.FillRectangle(brush, cx - 80, 0, 160, Height);
    }

    protected override void Dispose(bool disposing) { if (disposing) _timer.Dispose(); base.Dispose(disposing); }
}

// ---------------------------------------------------------------------------
// Neon progress bar --- dark background + green 1px border + green fill
// Supports Continuous and Marquee styles used by file tab progress streaming.
// ---------------------------------------------------------------------------
class NeonProgressBar : Control
{
    private int _minimum;
    private int _maximum = 100;
    private int _value;
    private ProgressBarStyle _style = ProgressBarStyle.Continuous;
    private int _marqueeAnimationSpeed = 24;
    private int _marqueeOffset;
    private readonly System.Windows.Forms.Timer _marqueeTimer;

    public int Minimum
    {
        get => _minimum;
        set
        {
            _minimum = Math.Min(value, _maximum);
            if (_value < _minimum) _value = _minimum;
            Invalidate();
        }
    }

    public int Maximum
    {
        get => _maximum;
        set
        {
            _maximum = Math.Max(value, _minimum + 1);
            if (_value > _maximum) _value = _maximum;
            Invalidate();
        }
    }

    public int Value
    {
        get => _value;
        set
        {
            _value = Math.Max(_minimum, Math.Min(_maximum, value));
            Invalidate();
        }
    }

    public ProgressBarStyle Style
    {
        get => _style;
        set
        {
            _style = value;
            UpdateMarqueeTimer();
            Invalidate();
        }
    }

    public int MarqueeAnimationSpeed
    {
        get => _marqueeAnimationSpeed;
        set
        {
            _marqueeAnimationSpeed = Math.Max(0, value);
            UpdateMarqueeTimer();
        }
    }

    public NeonProgressBar()
    {
        SetStyle(
            ControlStyles.UserPaint |
            ControlStyles.AllPaintingInWmPaint |
            ControlStyles.OptimizedDoubleBuffer |
            ControlStyles.ResizeRedraw,
            true);
        BackColor = Theme.LogBg;
        ForeColor = Theme.Accent;
        _marqueeTimer = new System.Windows.Forms.Timer { Interval = 24 };
        _marqueeTimer.Tick += (_, _) =>
        {
            _marqueeOffset += Math.Max(2, Width / 28);
            if (_marqueeOffset > Width + 48) _marqueeOffset = -48;
            Invalidate();
        };
    }

    private void UpdateMarqueeTimer()
    {
        if (_style == ProgressBarStyle.Marquee && _marqueeAnimationSpeed > 0)
        {
            _marqueeTimer.Interval = Math.Max(10, _marqueeAnimationSpeed);
            if (!_marqueeTimer.Enabled) _marqueeTimer.Start();
        }
        else
        {
            _marqueeTimer.Stop();
            _marqueeOffset = -48;
        }
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        var rc = ClientRectangle;
        if (rc.Width <= 1 || rc.Height <= 1) return;

        using var bg = new SolidBrush(Color.FromArgb(0xFF, 0x03, 0x08, 0x05));
        g.FillRectangle(bg, rc);

        var inner = Rectangle.Inflate(rc, -1, -1);
        if (inner.Width > 0 && inner.Height > 0)
        {
            if (_style == ProgressBarStyle.Marquee)
            {
                int blockW = Math.Max(22, inner.Width / 6);
                var block = new Rectangle(inner.X + _marqueeOffset, inner.Y, blockW, inner.Height);
                using var fillMarquee = new SolidBrush(Color.FromArgb(0xFF, 0x00, 0xC7, 0x60));
                g.FillRectangle(fillMarquee, block);
            }
            else
            {
                double range = Math.Max(1, _maximum - _minimum);
                double ratio = (_value - _minimum) / range;
                int fillW = (int)Math.Round(inner.Width * Math.Max(0.0, Math.Min(1.0, ratio)));
                if (fillW > 0)
                {
                    var fill = new Rectangle(inner.X, inner.Y, fillW, inner.Height);
                    using var fillBrush = new SolidBrush(Color.FromArgb(0xFF, 0x00, 0xC7, 0x60));
                    g.FillRectangle(fillBrush, fill);
                }
            }
        }

        using var border = new Pen(Color.FromArgb(0xFF, 0x00, 0x6E, 0x3E), 1f);
        g.DrawRectangle(border, rc.X, rc.Y, rc.Width - 1, rc.Height - 1);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) _marqueeTimer.Dispose();
        base.Dispose(disposing);
    }
}

// ---------------------------------------------------------------------------
// Drop zone panel --- prominent file-drop target with click-to-browse
// ---------------------------------------------------------------------------
class DropZonePanel : Panel
{
    private bool _hovering;
    private bool _dragging;
    private string? _filePath;

    public string? FilePath => _filePath;
    public event EventHandler<string>? FileDropped;

    /// Browse dialog filter (default: neutral, all files first).
    public string Filter { get; set; } = "All files|*.*|ObsidianQ containers|*.obsq";

    public DropZonePanel()
    {
        AllowDrop = true;
        SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
        BackColor = Theme.Surface;
        Cursor    = Cursors.Hand;

        DragEnter += (_, e) =>
        {
            if (e.Data?.GetDataPresent(DataFormats.FileDrop) == true)
            { e.Effect = DragDropEffects.Copy; _dragging = true; Invalidate(); }
        };
        DragOver  += (_, e) =>
        {
            if (e.Data?.GetDataPresent(DataFormats.FileDrop) == true) e.Effect = DragDropEffects.Copy;
        };
        DragDrop  += (_, e) =>
        {
            _dragging = false;
            if (e.Data?.GetData(DataFormats.FileDrop) is string[] { Length: > 0 } files)
                SetFile(files[0]);
        };
        DragLeave += (_, _)  => { _dragging = false; Invalidate(); };
        MouseEnter += (_, _) => { _hovering = true;  Invalidate(); };
        MouseLeave += (_, _) => { _hovering = false; Invalidate(); };
        Click      += (_, _) =>
        {
            using var dlg = new OpenFileDialog { Title = "Select input file", Filter = Filter };
            if (dlg.ShowDialog() == DialogResult.OK) SetFile(dlg.FileName);
        };
    }

    public void SetFile(string path)
    {
        _filePath = path;
        _dragging = false;
        Invalidate();
        FileDropped?.Invoke(this, path);
    }

    public void ClearFile()
    {
        _filePath = null;
        _dragging = false;
        Invalidate();
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g  = e.Graphics;
        g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.None;
        var rc = ClientRectangle;
        if (rc.Width <= 1 || rc.Height <= 1) return;

        using var bgBrush = new SolidBrush(_dragging ? Color.FromArgb(18, Theme.Accent) : Theme.Surface);
        g.FillRectangle(bgBrush, rc);

        var borderColor = _dragging ? Theme.Accent : (_hovering ? Theme.AccentDim : Theme.Border);
        using var borderPen = new Pen(borderColor, _dragging ? 2f : 1f) { Alignment = System.Drawing.Drawing2D.PenAlignment.Inset };
        g.DrawRectangle(borderPen, rc.X, rc.Y, rc.Width - 1, rc.Height - 1);

        if (_dragging)
        {
            using var underPen = new Pen(Theme.Accent, 2f);
            g.DrawLine(underPen, rc.X + 3, rc.Height - 2, rc.Width - 4, rc.Height - 2);
        }

        using var sf = new StringFormat
        { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center };

        if (_filePath == null)
        {
            var hint  = _dragging ? "Release to load" : "Drop a file here    or    [ Browse ]";
            using var hintBrush = new SolidBrush(_dragging ? Theme.Accent : Theme.TextDim);
            using var hintFont  = Theme.SafeMono(9f);
            g.DrawString(hint, hintFont, hintBrush, new RectangleF(rc.X, rc.Y, rc.Width, rc.Height), sf);
        }
        else
        {
            var name = Path.GetFileName(_filePath);
            var dir  = Path.GetDirectoryName(_filePath) ?? "";
            using var nameFont = Theme.SafeMono(9.5f);
            using var dirFont  = Theme.SafeMono(7.5f);
            using var nameBrush = new SolidBrush(Theme.Accent);
            using var dirBrush  = new SolidBrush(Theme.TextDim);

            var nameSize = g.MeasureString(name, nameFont, rc.Width, sf);
            var dirSize  = g.MeasureString(dir,  dirFont,  rc.Width, sf);
            float totalH = nameSize.Height + dirSize.Height + 2f;
            float startY = (rc.Height - totalH) / 2f;

            g.DrawString(name, nameFont, nameBrush,
                new RectangleF(rc.X, startY, rc.Width, nameSize.Height), sf);
            g.DrawString(dir,  dirFont,  dirBrush,
                new RectangleF(rc.X, startY + nameSize.Height + 2f, rc.Width, dirSize.Height), sf);
        }
    }
}

// ---------------------------------------------------------------------------
// Cyberpunk tab control --- fully custom-painted tabs with dark neon theme.
// Uses UserPaint so we own every pixel: the tab strip, the area to the right
// of the last tab, and the border around the content area all stay Theme.Bg.
// ---------------------------------------------------------------------------
class CyberpunkTabControl : TabControl
{
    public CyberpunkTabControl()
    {
        SizeMode  = TabSizeMode.FillToRight;
        ItemSize  = new Size(100, 32);
        Padding   = new Point(12, 4);
        BackColor = Theme.Bg;
        Font      = Theme.SafeMono(9f);
        SetStyle(
            ControlStyles.UserPaint |
            ControlStyles.AllPaintingInWmPaint |
            ControlStyles.OptimizedDoubleBuffer |
            ControlStyles.ResizeRedraw,
            true);
        // Redraw when selected tab changes so the active highlight updates.
        SelectedIndexChanged += (_, _) => Invalidate();
    }

    protected override void OnPaintBackground(PaintEventArgs e) { /* suppressed — OnPaint owns everything */ }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.Clear(Theme.Bg);

        if (TabCount == 0) return;

        // Draw each tab header.
        for (int i = 0; i < TabCount; i++)
        {
            bool active = i == SelectedIndex;
            var rc = GetTabRect(i);

            using var bg = new SolidBrush(active ? Color.FromArgb(30, Theme.Accent) : Theme.Bg);
            g.FillRectangle(bg, rc);

            using var border = new Pen(active ? Theme.Accent : Theme.Border, 1f);
            g.DrawRectangle(border, rc.X, rc.Y, rc.Width - 1, rc.Height - 1);

            using var sf = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center };
            using var tb = new SolidBrush(active ? Theme.Accent : Theme.TextDim);
            g.DrawString(TabPages[i].Text, Font, tb, new RectangleF(rc.X, rc.Y, rc.Width, rc.Height), sf);
        }

        // Draw a single neon border around the tab page content area.
        int contentTop = GetTabRect(0).Bottom;
        using var contentBorder = new Pen(Theme.Border, 1f);
        g.DrawRectangle(contentBorder, 0, contentTop, Width - 1, Height - contentTop - 1);
    }
}

class ShellSetupPromptForm : Form
{
    private readonly CheckBox _dontAsk;
    public bool DontAskAgain => _dontAsk.Checked;

    public ShellSetupPromptForm()
    {
        Text = "ObsidianQ Setup";
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        ShowInTaskbar = false;
        ClientSize = new Size(520, 190);
        BackColor = Theme.Bg;
        ForeColor = Theme.TextMain;
        Font = Theme.SafeMono(9f);

        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 3,
            Padding = new Padding(14),
            BackColor = Theme.Bg,
        };
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 28));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 36));

        var lbl = new Label
        {
            Dock = DockStyle.Fill,
            AutoSize = false,
            ForeColor = Theme.TextMain,
            BackColor = Theme.Bg,
            TextAlign = ContentAlignment.TopLeft,
            Text = "Would you like to install ObsidianQ shell menu entries, .vault/.obsqpub associations, and Explorer New item?\n\n" +
                   "This enables right-click actions, opening .vault files directly, and New > Obsidian Vault.",
        };

        _dontAsk = new CheckBox
        {
            Dock = DockStyle.Fill,
            Text = "Don't ask again",
            ForeColor = Theme.TextDim,
            BackColor = Theme.Bg,
            AutoSize = true,
        };

        var btns = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 1,
            BackColor = Theme.Bg,
        };
        btns.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        btns.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));

        var btnNo = new NeonButton { Text = "NOT NOW", Dock = DockStyle.Fill, Margin = new Padding(0, 0, 4, 0) };
        var btnYes = new NeonButton { Text = "INSTALL", Dock = DockStyle.Fill, Margin = new Padding(4, 0, 0, 0) };
        btnNo.Click += (_, _) => { DialogResult = DialogResult.No; Close(); };
        btnYes.Click += (_, _) => { DialogResult = DialogResult.Yes; Close(); };

        btns.Controls.Add(btnNo, 0, 0);
        btns.Controls.Add(btnYes, 1, 0);

        root.Controls.Add(lbl, 0, 0);
        root.Controls.Add(_dontAsk, 0, 1);
        root.Controls.Add(btns, 0, 2);
        Controls.Add(root);
    }
}

class KeygenRiskPromptForm : Form
{
    private readonly CheckBox _dontAsk;
    public bool DontAskAgain => _dontAsk.Checked;

    public KeygenRiskPromptForm()
    {
        Text = "Generate New Keys";
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        ShowInTaskbar = false;
        ClientSize = new Size(560, 220);
        BackColor = Theme.Bg;
        ForeColor = Theme.TextMain;
        Font = Theme.SafeMono(9f);

        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 3,
            Padding = new Padding(14),
            BackColor = Theme.Bg,
        };
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 28));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 36));

        var lbl = new Label
        {
            Dock = DockStyle.Fill,
            AutoSize = false,
            ForeColor = Theme.TextMain,
            BackColor = Theme.Bg,
            TextAlign = ContentAlignment.TopLeft,
            Text = "Generating a new keypair creates a new identity.\n\n" +
                   "Old encrypted files/vaults/packets may still require older private keys.\n" +
                   "Do not delete old private keys unless you are sure they are no longer needed.",
        };

        _dontAsk = new CheckBox
        {
            Dock = DockStyle.Fill,
            Text = "Don't show this warning again",
            ForeColor = Theme.TextDim,
            BackColor = Theme.Bg,
            AutoSize = true,
        };

        var btns = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 1,
            BackColor = Theme.Bg,
        };
        btns.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        btns.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));

        var btnCancel = new NeonButton { Text = "CANCEL", Dock = DockStyle.Fill, Margin = new Padding(0, 0, 4, 0) };
        var btnContinue = new NeonButton { Text = "CONTINUE", Dock = DockStyle.Fill, Margin = new Padding(4, 0, 0, 0) };
        btnCancel.Click += (_, _) => { DialogResult = DialogResult.Cancel; Close(); };
        btnContinue.Click += (_, _) => { DialogResult = DialogResult.OK; Close(); };

        btns.Controls.Add(btnCancel, 0, 0);
        btns.Controls.Add(btnContinue, 1, 0);

        root.Controls.Add(lbl, 0, 0);
        root.Controls.Add(_dontAsk, 0, 1);
        root.Controls.Add(btns, 0, 2);
        Controls.Add(root);
    }
}

class TextPromptForm : Form
{
    private readonly TextBox _input;
    public string Value => _input.Text.Trim();

    public TextPromptForm(string title, string label, string placeholder = "", bool password = false)
    {
        Text = title;
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        ShowInTaskbar = false;
        ClientSize = new Size(520, 146);
        BackColor = Theme.Bg;
        ForeColor = Theme.TextMain;
        Font = Theme.SafeMono(9f);

        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 3,
            Padding = new Padding(14),
            BackColor = Theme.Bg,
        };
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 22));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 34));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 36));

        var lbl = new Label
        {
            Text = label,
            Dock = DockStyle.Fill,
            ForeColor = Theme.TextDim,
            BackColor = Theme.Bg,
            TextAlign = ContentAlignment.MiddleLeft,
        };
        _input = new TextBox
        {
            Dock = DockStyle.Fill,
            BackColor = Theme.Surface,
            ForeColor = Theme.Accent,
            BorderStyle = BorderStyle.FixedSingle,
            PlaceholderText = placeholder,
            UseSystemPasswordChar = password,
        };
        var btnRow = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, BackColor = Theme.Bg };
        btnRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        btnRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        var btnCancel = new NeonButton { Text = "CANCEL", Dock = DockStyle.Fill, Margin = new Padding(0, 0, 4, 0) };
        var btnOk = new NeonButton { Text = "OK", Dock = DockStyle.Fill, Margin = new Padding(4, 0, 0, 0) };
        btnCancel.Click += (_, _) => { DialogResult = DialogResult.Cancel; Close(); };
        btnOk.Click += (_, _) => { DialogResult = DialogResult.OK; Close(); };
        btnRow.Controls.Add(btnCancel, 0, 0);
        btnRow.Controls.Add(btnOk, 1, 0);

        root.Controls.Add(lbl, 0, 0);
        root.Controls.Add(_input, 0, 1);
        root.Controls.Add(btnRow, 0, 2);
        Controls.Add(root);
    }
}

class VaultAccessModePromptForm : Form
{
    public enum ModeChoice { Cancel, Password, PqcRecipients }
    public ModeChoice Choice { get; private set; } = ModeChoice.Cancel;

    public VaultAccessModePromptForm()
    {
        Text = "Manage Vault Access";
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        ShowInTaskbar = false;
        ClientSize = new Size(560, 180);
        BackColor = Theme.Bg;
        ForeColor = Theme.TextMain;
        Font = Theme.SafeMono(9f);

        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 2,
            Padding = new Padding(14),
            BackColor = Theme.Bg,
        };
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 38));

        var lbl = new Label
        {
            Dock = DockStyle.Fill,
            AutoSize = false,
            ForeColor = Theme.TextMain,
            BackColor = Theme.Bg,
            TextAlign = ContentAlignment.TopLeft,
            Text = "Choose how this vault should be unlocked going forward:",
        };

        var btns = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 3,
            RowCount = 1,
            BackColor = Theme.Bg,
        };
        btns.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.33f));
        btns.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.33f));
        btns.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.34f));

        var btnPassword = new NeonButton { Text = "PASSWORD", Dock = DockStyle.Fill, Margin = new Padding(0, 0, 4, 0) };
        var btnPqc = new NeonButton { Text = "PQC RECIPIENTS", Dock = DockStyle.Fill, Margin = new Padding(4, 0, 4, 0) };
        var btnCancel = new NeonButton { Text = "CANCEL", Dock = DockStyle.Fill, Margin = new Padding(4, 0, 0, 0) };
        btnPassword.Click += (_, _) => { Choice = ModeChoice.Password; DialogResult = DialogResult.OK; Close(); };
        btnPqc.Click += (_, _) => { Choice = ModeChoice.PqcRecipients; DialogResult = DialogResult.OK; Close(); };
        btnCancel.Click += (_, _) => { Choice = ModeChoice.Cancel; DialogResult = DialogResult.Cancel; Close(); };

        btns.Controls.Add(btnPassword, 0, 0);
        btns.Controls.Add(btnPqc, 1, 0);
        btns.Controls.Add(btnCancel, 2, 0);

        root.Controls.Add(lbl, 0, 0);
        root.Controls.Add(btns, 0, 1);
        Controls.Add(root);
    }
}

class VaultProgressForm : Form
{
    private readonly Label _lblStatus;
    private readonly ProgressBar _bar;
    private readonly NeonButton _btnCancel;
    private readonly DateTime _startedUtc;
    public bool CancelRequested { get; private set; }

    public VaultProgressForm(string title, int total)
    {
        Text = title;
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        ShowInTaskbar = false;
        ControlBox = false;
        TopMost = true;
        ClientSize = new Size(560, 148);
        BackColor = Theme.Bg;
        ForeColor = Theme.TextMain;
        Font = Theme.SafeMono(9f);

        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 3,
            Padding = new Padding(14),
            BackColor = Theme.Bg,
        };
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 58));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 28));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 34));

        _lblStatus = new Label
        {
            Dock = DockStyle.Fill,
            AutoSize = false,
            ForeColor = Theme.Accent,
            BackColor = Theme.Bg,
            TextAlign = ContentAlignment.MiddleLeft,
            Text = $"Preparing... (0/{total})",
        };
        _bar = new ProgressBar
        {
            Dock = DockStyle.Fill,
            Minimum = 0,
            Maximum = Math.Max(1, total),
            Value = 0,
            Style = ProgressBarStyle.Continuous,
        };

        _btnCancel = new NeonButton
        {
            Text = "CANCEL",
            Dock = DockStyle.Right,
            Width = 120,
            Margin = new Padding(0, 0, 0, 0),
        };
        _btnCancel.Click += (_, _) =>
        {
            CancelRequested = true;
            _btnCancel.Enabled = false;
            _btnCancel.Text = "CANCELLING...";
        };
        var btnPanel = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Bg };
        btnPanel.Controls.Add(_btnCancel);

        root.Controls.Add(_lblStatus, 0, 0);
        root.Controls.Add(_bar, 0, 1);
        root.Controls.Add(btnPanel, 0, 2);
        Controls.Add(root);
        _startedUtc = DateTime.UtcNow;
    }

    public void UpdateProgress(int completed, int total, string currentPath, long bytesProcessed = 0, long totalBytes = 0, string stage = "processing")
    {
        int safeTotal = Math.Max(1, total);
        bool done = completed >= total && total > 0;
        if (totalBytes > 0)
        {
            _bar.Style = ProgressBarStyle.Continuous;
            const int scale = 1000;
            _bar.Maximum = scale;
            int v = (int)Math.Max(0, Math.Min(scale, (bytesProcessed * scale) / Math.Max(1, totalBytes)));
            if (!done && v >= scale) v = scale - 1;
            _bar.Value = v;
        }
        else if (safeTotal <= 1 && !done)
        {
            // Single long-running item: keep visible motion instead of a stuck 0/1 bar.
            _bar.Style = ProgressBarStyle.Marquee;
            _bar.MarqueeAnimationSpeed = 24;
        }
        else
        {
            _bar.Style = ProgressBarStyle.Continuous;
            _bar.Maximum = safeTotal;
            _bar.Value = Math.Max(0, Math.Min(completed, safeTotal));
        }
        if (done)
        {
            _bar.Style = ProgressBarStyle.Continuous;
            if (_bar.Maximum <= 0) _bar.Maximum = 1;
            _bar.Value = _bar.Maximum;
        }
        double elapsedSec = Math.Max(0.001, (DateTime.UtcNow - _startedUtc).TotalSeconds);
        double mbps = bytesProcessed > 0 ? (bytesProcessed / 1_048_576.0) / elapsedSec : 0.0;
        string etaText = string.Empty;
        if (totalBytes > 0 && bytesProcessed > 0 && bytesProcessed < totalBytes)
        {
            double remainingBytes = Math.Max(0, totalBytes - bytesProcessed);
            double bytesPerSec = bytesProcessed / elapsedSec;
            if (bytesPerSec > 0)
            {
                double etaSec = remainingBytes / bytesPerSec;
                etaText = $" | ETA {FormatEta(etaSec)}";
            }
        }
        else if (total > 0 && completed > 0 && completed < total)
        {
            double itemsPerSec = completed / elapsedSec;
            if (itemsPerSec > 0)
            {
                double etaSec = (total - completed) / itemsPerSec;
                etaText = $" | ETA {FormatEta(etaSec)}";
            }
        }
        string throughput = bytesProcessed > 0
            ? $" | {FormatBytes(bytesProcessed)} @ {mbps:0.##} MB/s"
            : string.Empty;
        string stageText = string.IsNullOrWhiteSpace(stage) ? "processing" : stage;
        _lblStatus.Text = $"{stageText} {completed}/{total}: {currentPath}{throughput}{etaText}";
        Refresh();
    }

    private static string FormatBytes(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB", "PB"];
        double size = bytes < 0 ? 0 : bytes;
        int unit = 0;
        while (size >= 1024 && unit < units.Length - 1)
        {
            size /= 1024;
            unit++;
        }
        return unit == 0 ? $"{bytes} {units[unit]}" : $"{size:0.##} {units[unit]}";
    }

    private static string FormatEta(double seconds)
    {
        int sec = (int)Math.Max(0, Math.Ceiling(seconds));
        int hh = sec / 3600;
        int mm = (sec % 3600) / 60;
        int ss = sec % 60;
        return hh > 0 ? $"{hh:D2}:{mm:D2}:{ss:D2}" : $"{mm:D2}:{ss:D2}";
    }
}

class BusyProgressForm : Form
{
    private readonly Label _lblStatus;
    private readonly ProgressBar _bar;

    public BusyProgressForm(string title, string message)
    {
        Text = title;
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        ShowInTaskbar = false;
        ControlBox = false;
        TopMost = true;
        ClientSize = new Size(520, 118);
        BackColor = Theme.Bg;
        ForeColor = Theme.TextMain;
        Font = Theme.SafeMono(9f);

        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 2,
            Padding = new Padding(14),
            BackColor = Theme.Bg,
        };
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 56));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));

        _lblStatus = new Label
        {
            Dock = DockStyle.Fill,
            AutoSize = false,
            ForeColor = Theme.Accent,
            BackColor = Theme.Bg,
            TextAlign = ContentAlignment.MiddleLeft,
            Text = message,
        };
        _bar = new ProgressBar
        {
            Dock = DockStyle.Fill,
            Style = ProgressBarStyle.Marquee,
            MarqueeAnimationSpeed = 24,
        };

        root.Controls.Add(_lblStatus, 0, 0);
        root.Controls.Add(_bar, 0, 1);
        Controls.Add(root);
    }
}

class VaultPreviewForm : Form
{
    private static readonly HashSet<string> TextExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".txt",".md",".markdown",".json",".xml",".csv",".log",".toml",".yaml",".yml",
        ".ini",".conf",".cfg",".rs",".cs",".py",".js",".ts",".tsx",".jsx",".html",".htm",".css",".sql",".ps1",".bat",".cmd",".sh"
    };
    private static readonly HashSet<string> ImageExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".png",".jpg",".jpeg",".gif",".bmp",".tif",".tiff",".webp",".ico"
    };

    public VaultPreviewForm(string vaultPath, byte[] data)
    {
        Text = $"Preview - {vaultPath}";
        StartPosition = FormStartPosition.CenterParent;
        Size = new Size(860, 620);
        MinimumSize = new Size(620, 420);
        BackColor = Theme.Bg;
        ForeColor = Theme.TextMain;
        Font = Theme.SafeMono(9f);

        string ext = Path.GetExtension(vaultPath);
        if (TryBuildImagePreview(ext, data, out var imagePanel))
        {
            Controls.Add(imagePanel);
            return;
        }

        var text = new RichTextBox
        {
            Dock = DockStyle.Fill,
            ReadOnly = true,
            WordWrap = true,
            BackColor = Theme.LogBg,
            ForeColor = Theme.Accent,
            BorderStyle = BorderStyle.None,
            ScrollBars = RichTextBoxScrollBars.Both,
            Font = Theme.SafeMono(9f),
        };

        const int maxPreviewBytes = 2 * 1024 * 1024;
        byte[] previewBytes = data.Length > maxPreviewBytes ? data[..maxPreviewBytes] : data;
        bool likelyText = IsLikelyText(ext, previewBytes);
        if (likelyText && TryDecodeText(previewBytes, out var decoded))
        {
            text.Text = decoded;
            if (data.Length > maxPreviewBytes) text.AppendText($"\n\n[truncated to {maxPreviewBytes} bytes]");
        }
        else
        {
            var sb = new StringBuilder(previewBytes.Length * 3 + 128);
            sb.AppendLine("[Binary preview: hex]");
            for (int i = 0; i < previewBytes.Length; i++)
            {
                if (i % 16 == 0) sb.Append($"\n{i:X8}: ");
                sb.Append(previewBytes[i].ToString("X2")).Append(' ');
            }
            if (data.Length > maxPreviewBytes) sb.Append($"\n\n[truncated to {maxPreviewBytes} bytes]");
            text.Text = sb.ToString();
        }
        Controls.Add(text);
    }

    private static bool TryBuildImagePreview(string ext, byte[] data, out Control panel)
    {
        panel = null!;
        if (!ImageExtensions.Contains(ext)) return false;
        try
        {
            using var ms = new MemoryStream(data);
            using var img = Image.FromStream(ms, useEmbeddedColorManagement: false, validateImageData: true);
            var bitmap = new Bitmap(img);
            var picture = new PictureBox
            {
                Dock = DockStyle.Fill,
                Image = bitmap,
                SizeMode = PictureBoxSizeMode.Zoom,
                BackColor = Theme.LogBg,
            };
            panel = picture;
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool IsLikelyText(string ext, byte[] bytes)
    {
        if (TextExtensions.Contains(ext)) return true;
        if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF) return true; // UTF-8 BOM
        if (bytes.Length >= 2 && ((bytes[0] == 0xFF && bytes[1] == 0xFE) || (bytes[0] == 0xFE && bytes[1] == 0xFF))) return true; // UTF-16 BOM
        int ctrl = 0;
        int sample = Math.Min(bytes.Length, 4096);
        for (int i = 0; i < sample; i++)
        {
            byte b = bytes[i];
            if (b == 9 || b == 10 || b == 13) continue;
            if (b < 32) ctrl++;
        }
        return sample == 0 || (ctrl * 100 / sample) < 2;
    }

    private static bool TryDecodeText(byte[] bytes, out string decoded)
    {
        try
        {
            if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF)
            {
                decoded = Encoding.UTF8.GetString(bytes);
                return true;
            }
            if (bytes.Length >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE)
            {
                decoded = Encoding.Unicode.GetString(bytes);
                return true;
            }
            if (bytes.Length >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF)
            {
                decoded = Encoding.BigEndianUnicode.GetString(bytes);
                return true;
            }
            decoded = Encoding.UTF8.GetString(bytes);
            return true;
        }
        catch
        {
            decoded = string.Empty;
            return false;
        }
    }
}

class VaultInitForm : Form
{
    private readonly string? _defaultPubkeyPath;
    private string _vaultDirectory;
    private readonly TextBox _txtVaultName;
    private readonly Label _lblPath;
    private readonly SegmentedToggle _toggleMode;
    private readonly Panel _passwordPanel;
    private readonly Panel _pqcPanel;
    private readonly TextBox _txtPassword;
    private readonly TextBox _txtConfirm;
    private readonly TextBox _txtPubkey;
    private readonly Label _lblHint;

    public string VaultPath => Path.Combine(_vaultDirectory, EnsureVaultFilename(_txtVaultName.Text));
    public bool UsePqc => _toggleMode.Selected == SegmentedToggle.Segment.Pqc;
    public string Password => _txtPassword.Text;
    public string PubkeyPath => _txtPubkey.Text.Trim();

    public VaultInitForm(string initialVaultPath, string? defaultPubkeyPath = null)
    {
        _defaultPubkeyPath = defaultPubkeyPath;
        Text = "Initialize Vault";
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        ShowInTaskbar = false;
        ClientSize = new Size(620, 300);
        BackColor = Theme.Bg;
        ForeColor = Theme.TextMain;
        Font = Theme.SafeMono(9f);

        string initialPath = EnsureVaultExtension(initialVaultPath);
        _vaultDirectory = Path.GetDirectoryName(initialPath) ?? Environment.CurrentDirectory;
        if (string.IsNullOrWhiteSpace(_vaultDirectory))
            _vaultDirectory = Environment.CurrentDirectory;
        string initialName = Path.GetFileName(initialPath);
        if (string.IsNullOrWhiteSpace(initialName))
            initialName = "New Vault.vault";

        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 9,
            Padding = new Padding(14),
            BackColor = Theme.Bg,
        };
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 20));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 32));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 22));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 68));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 34));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 8));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 36));

        var lblTitle = new Label
        {
            Dock = DockStyle.Fill,
            AutoSize = false,
            ForeColor = Theme.TextMain,
            Text = "Create new vault",
            TextAlign = ContentAlignment.MiddleLeft,
        };
        var nameRow = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 1,
            BackColor = Theme.Bg,
            Margin = new Padding(0),
        };
        nameRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 120));
        nameRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        var lblName = new Label
        {
            Dock = DockStyle.Fill,
            AutoSize = false,
            ForeColor = Theme.TextDim,
            Text = "Vault Name:",
            TextAlign = ContentAlignment.MiddleLeft,
        };
        _txtVaultName = new TextBox
        {
            Dock = DockStyle.Fill,
            BackColor = Theme.Surface,
            ForeColor = Theme.Accent,
            BorderStyle = BorderStyle.FixedSingle,
            PlaceholderText = "Default.vault",
            Text = initialName,
        };
        _txtVaultName.Leave += (_, _) =>
        {
            _txtVaultName.Text = EnsureVaultFilename(_txtVaultName.Text);
        };
        nameRow.Controls.Add(lblName, 0, 0);
        nameRow.Controls.Add(_txtVaultName, 1, 0);

        _lblPath = new Label
        {
            Dock = DockStyle.Fill,
            AutoSize = false,
            ForeColor = Theme.TextDim,
            TextAlign = ContentAlignment.MiddleLeft,
            Text = $"Location: {_vaultDirectory}",
        };

        var pathRow = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 1,
            BackColor = Theme.Bg,
            Margin = new Padding(0),
        };
        pathRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        pathRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 154));
        var btnPickLocation = new NeonButton
        {
            Text = "CHOOSE LOCATION...",
            Dock = DockStyle.Fill,
            Margin = new Padding(4, 0, 0, 0),
        };
        btnPickLocation.Click += (_, _) =>
        {
            using var dlg = new SaveFileDialog
            {
                Title = "Choose Vault Location",
                Filter = "Vault files (*.vault)|*.vault|All files (*.*)|*.*",
                InitialDirectory = Directory.Exists(_vaultDirectory) ? _vaultDirectory : Environment.CurrentDirectory,
                FileName = EnsureVaultFilename(_txtVaultName.Text),
                AddExtension = true,
                DefaultExt = "vault",
                OverwritePrompt = false,
            };
            if (dlg.ShowDialog(this) != DialogResult.OK) return;
            string selected = EnsureVaultExtension(dlg.FileName);
            string? dir = Path.GetDirectoryName(selected);
            if (!string.IsNullOrWhiteSpace(dir))
                _vaultDirectory = dir;
            _txtVaultName.Text = EnsureVaultFilename(Path.GetFileName(selected));
            _lblPath.Text = $"Location: {_vaultDirectory}";
        };
        pathRow.Controls.Add(_lblPath, 0, 0);
        pathRow.Controls.Add(btnPickLocation, 1, 0);

        _toggleMode = new SegmentedToggle { Dock = DockStyle.Fill, Margin = new Padding(0) };
        _toggleMode.RightLabel = "SECURE CONTACTS - KEY BASED ENCRYPTION";
        _toggleMode.SelectionChanged += (_, _) => UpdateModeUi();

        _lblHint = new Label
        {
            Dock = DockStyle.Fill,
            AutoSize = false,
            ForeColor = Theme.TextDim,
            TextAlign = ContentAlignment.MiddleLeft,
        };

        _passwordPanel = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Bg };
        _txtPassword = new TextBox
        {
            Dock = DockStyle.Fill,
            UseSystemPasswordChar = true,
            BackColor = Theme.Surface,
            ForeColor = Theme.Accent,
            BorderStyle = BorderStyle.FixedSingle,
            PlaceholderText = "Password",
        };
        _txtConfirm = new TextBox
        {
            Dock = DockStyle.Fill,
            UseSystemPasswordChar = true,
            BackColor = Theme.Surface,
            ForeColor = Theme.Accent,
            BorderStyle = BorderStyle.FixedSingle,
            PlaceholderText = "Confirm password",
        };
        var pwLayout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 2,
            BackColor = Theme.Bg,
            Margin = new Padding(0),
        };
        pwLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 50));
        pwLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 50));
        pwLayout.Controls.Add(_txtPassword, 0, 0);
        pwLayout.Controls.Add(_txtConfirm, 0, 1);
        _passwordPanel.Controls.Add(pwLayout);

        _pqcPanel = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Bg, Visible = false };
        _txtPubkey = new TextBox
        {
            Dock = DockStyle.Fill,
            BackColor = Theme.Surface,
            ForeColor = Theme.Accent,
            BorderStyle = BorderStyle.FixedSingle,
            PlaceholderText = "Public key path(s) (.bin/.pem). Separate multiple with ;",
            Text = defaultPubkeyPath ?? string.Empty,
        };
        var pqcRow = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 1,
            BackColor = Theme.Bg,
            Margin = new Padding(0),
        };
        pqcRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        pqcRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 102));
        var btnBrowseKey = new NeonButton { Text = "BROWSE", Dock = DockStyle.Fill, Margin = new Padding(4, 0, 0, 0) };
        btnBrowseKey.Click += (_, _) =>
        {
            using var dlg = new OpenFileDialog
            {
                Title = "Select public key",
                Filter = "Key files|*.bin;*.pem|All files|*.*",
            };
            if (dlg.ShowDialog(this) == DialogResult.OK)
            {
                var keys = ParseRecipientKeyPaths(_txtPubkey.Text);
                keys.Add(dlg.FileName);
                _txtPubkey.Text = string.Join("; ", keys.Distinct(StringComparer.OrdinalIgnoreCase));
            }
        };
        pqcRow.Controls.Add(_txtPubkey, 0, 0);
        pqcRow.Controls.Add(btnBrowseKey, 1, 0);
        _pqcPanel.Controls.Add(pqcRow);

        var btnRow = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, BackColor = Theme.Bg };
        btnRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        btnRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        var btnCancel = new NeonButton { Text = "CANCEL", Dock = DockStyle.Fill, Margin = new Padding(0, 0, 4, 0) };
        var btnInit = new NeonButton { Text = "INITIALIZE", Dock = DockStyle.Fill, Margin = new Padding(4, 0, 0, 0) };
        btnCancel.Click += (_, _) => { DialogResult = DialogResult.Cancel; Close(); };
        btnInit.Click += (_, _) =>
        {
            string vaultPath = VaultPath;
            if (string.IsNullOrWhiteSpace(vaultPath))
            {
                MessageBox.Show(this, "Vault file path is required.", "Initialize vault", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            string name = _txtVaultName.Text.Trim();
            if (name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
            {
                MessageBox.Show(this, "Vault name contains invalid filename characters.", "Initialize vault", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            if (UsePqc)
            {
                string? picked = ShowRecipientsPicker(PubkeyPath);
                if (string.IsNullOrWhiteSpace(picked))
                {
                    MessageBox.Show(this, "Select at least one recipient to continue.", "Initialize vault", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
                var keys = ParseRecipientKeyPaths(picked);
                if (!string.IsNullOrWhiteSpace(_defaultPubkeyPath) && File.Exists(_defaultPubkeyPath))
                    keys.Insert(0, _defaultPubkeyPath);
                if (keys.Count == 0)
                {
                    MessageBox.Show(this, "At least one public key is required for SECURE CONTACTS - KEY BASED ENCRYPTION mode.", "Initialize vault", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
                if (keys.Any(k => !File.Exists(k)))
                {
                    MessageBox.Show(this, "One or more selected public key files were not found.", "Initialize vault", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
                _txtPubkey.Text = string.Join("; ", keys.Distinct(StringComparer.OrdinalIgnoreCase));
            }
            else
            {
                if (string.IsNullOrEmpty(_txtPassword.Text))
                {
                    MessageBox.Show(this, "Password is required.", "Initialize vault", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
                if (_txtPassword.Text != _txtConfirm.Text)
                {
                    MessageBox.Show(this, "Passwords do not match.", "Initialize vault", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
            }
            DialogResult = DialogResult.OK;
            Close();
        };
        btnRow.Controls.Add(btnCancel, 0, 0);
        btnRow.Controls.Add(btnInit, 1, 0);

        root.Controls.Add(lblTitle, 0, 0);
        root.Controls.Add(nameRow, 0, 1);
        root.Controls.Add(pathRow, 0, 2);
        root.Controls.Add(_toggleMode, 0, 3);
        root.Controls.Add(_lblHint, 0, 4);
        root.Controls.Add(_passwordPanel, 0, 5);
        root.Controls.Add(_pqcPanel, 0, 6);
        root.Controls.Add(new Panel { Dock = DockStyle.Fill, BackColor = Theme.Bg }, 0, 7);
        root.Controls.Add(btnRow, 0, 8);
        Controls.Add(root);

        _toggleMode.SetSelected(SegmentedToggle.Segment.Pqc);
        UpdateModeUi();
    }

    private static string EnsureVaultExtension(string path)
    {
        string value = path.Trim();
        if (string.IsNullOrEmpty(value)) return value;
        return Path.HasExtension(value) ? value : value + ".vault";
    }

    private static string EnsureVaultFilename(string name)
    {
        string value = name.Trim();
        if (string.IsNullOrEmpty(value)) value = "Default.vault";
        return value.EndsWith(".vault", StringComparison.OrdinalIgnoreCase) ? value : value + ".vault";
    }

    private void UpdateModeUi()
    {
        bool isPqc = UsePqc;
        _passwordPanel.Visible = !isPqc;
        _pqcPanel.Visible = isPqc;
        _lblHint.Text = isPqc
            ? "SECURE CONTACTS - KEY BASED ENCRYPTION mode: recipient selection is required at Initialize. Your local key is auto-included."
            : "Password mode uses a passphrase to initialize this vault.";
    }

    private static List<string> ParseRecipientKeyPaths(string raw)
    {
        return raw
            .Split(new[] { ';', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries)
            .Select(s => s.Trim().Trim('"'))
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static string SafeRecipientFileStem(string name, int index)
    {
        if (string.IsNullOrWhiteSpace(name)) return $"recipient_{index}";
        var sb = new StringBuilder(name.Length);
        foreach (char ch in name)
            sb.Append(char.IsLetterOrDigit(ch) || ch == '-' || ch == '_' ? ch : '_');
        string safe = sb.ToString().Trim('_');
        if (string.IsNullOrWhiteSpace(safe)) safe = $"recipient_{index}";
        return safe;
    }

    private string? ShowRecipientsPicker(string currentRaw)
    {
        string recipientsPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "ObsidianQ",
            "trusted_recipients_v1.tsv");
        string contactsDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "ObsidianQ",
            "contacts_pubkeys");

        var options = new List<(string Label, string KeyPath)>();
        if (!string.IsNullOrWhiteSpace(_defaultPubkeyPath) && File.Exists(_defaultPubkeyPath))
            options.Add(($"Me (local default)", _defaultPubkeyPath));
        if (File.Exists(recipientsPath))
        {
            Directory.CreateDirectory(contactsDir);
            int idx = 0;
            foreach (string line in File.ReadAllLines(recipientsPath))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                string[] parts = line.Split('\t');
                if (parts.Length < 5) continue;
                string name = parts[0].Trim();
                string fp = parts[1].Trim();
                string b64 = parts[4].Trim();
                if (string.IsNullOrWhiteSpace(b64)) continue;
                try
                {
                    byte[] raw = Convert.FromBase64String(b64);
                    string stem = SafeRecipientFileStem(name, idx++);
                    string keyPath = Path.Combine(contactsDir, $"{stem}_{fp}.bin");
                    File.WriteAllBytes(keyPath, raw);
                    options.Add(($"{name} ({(fp.Length > 8 ? fp[..8] : fp)})", keyPath));
                }
                catch { /* skip invalid recipient rows */ }
            }
        }

        if (options.Count == 0)
        {
            MessageBox.Show(
                this,
                "No recipient keys found.\n\nAdd recipients in Trusted Recipients first.",
                "Select Recipients",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            return null;
        }

        var current = ParseRecipientKeyPaths(currentRaw);
        using var dlg = new Form
        {
            Text = "Select Recipients",
            StartPosition = FormStartPosition.CenterParent,
            FormBorderStyle = FormBorderStyle.FixedDialog,
            MaximizeBox = false,
            MinimizeBox = false,
            ShowInTaskbar = false,
            ClientSize = new Size(560, 420),
            BackColor = Theme.Bg,
            ForeColor = Theme.TextMain,
            Font = Theme.SafeMono(9f),
        };

        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3, Padding = new Padding(12), BackColor = Theme.Bg };
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 28));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 36));

        var lbl = new Label
        {
            Text = "Select recipient public keys:",
            Dock = DockStyle.Fill,
            ForeColor = Theme.TextMain,
            BackColor = Theme.Bg,
            TextAlign = ContentAlignment.MiddleLeft
        };

        var clb = new CheckedListBox
        {
            Dock = DockStyle.Fill,
            BackColor = Theme.Surface,
            ForeColor = Theme.TextMain,
            BorderStyle = BorderStyle.FixedSingle,
            CheckOnClick = true,
            IntegralHeight = false,
        };
        foreach (var item in options)
        {
            int i = clb.Items.Add(item.Label);
            bool shouldCheck = current.Contains(item.KeyPath, StringComparer.OrdinalIgnoreCase)
                || (current.Count == 0
                    && !string.IsNullOrWhiteSpace(_defaultPubkeyPath)
                    && string.Equals(item.KeyPath, _defaultPubkeyPath, StringComparison.OrdinalIgnoreCase));
            if (shouldCheck)
                clb.SetItemChecked(i, true);
        }

        var btnRow = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, BackColor = Theme.Bg };
        btnRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        btnRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        var btnCancel = new NeonButton { Text = "CANCEL", Dock = DockStyle.Fill, Margin = new Padding(0, 0, 4, 0) };
        var btnApply = new NeonButton { Text = "APPLY", Dock = DockStyle.Fill, Margin = new Padding(4, 0, 0, 0) };
        btnCancel.Click += (_, _) => { dlg.DialogResult = DialogResult.Cancel; dlg.Close(); };
        btnApply.Click += (_, _) => { dlg.DialogResult = DialogResult.OK; dlg.Close(); };
        btnRow.Controls.Add(btnCancel, 0, 0);
        btnRow.Controls.Add(btnApply, 1, 0);

        root.Controls.Add(lbl, 0, 0);
        root.Controls.Add(clb, 0, 1);
        root.Controls.Add(btnRow, 0, 2);
        dlg.Controls.Add(root);

        if (dlg.ShowDialog(this) != DialogResult.OK) return null;

        var selected = new List<string>();
        for (int i = 0; i < clb.Items.Count; i++)
            if (clb.GetItemChecked(i))
                selected.Add(options[i].KeyPath);
        return selected.Count == 0 ? null : string.Join("; ", selected);
    }
}

// ---------------------------------------------------------------------------
// Main Form
// ---------------------------------------------------------------------------
class MainForm : Form
{
    private const string LauncherPrefsKey = @"Software\ObsidianQ\Launcher";
    private const string SkipShellPromptValue = "SkipShellSetupPrompt";
    private const string SkipKeygenPromptValue = "SkipKeygenRiskPrompt";
    private const string FirstRunKeypairPromptedValue = "FirstRunKeypairPrompted";
    // -----------------------------------------------------------------------
    // FILE TAB controls
    // -----------------------------------------------------------------------
    private readonly SegmentedToggle _toggle;
    private readonly NeonButton _btnRun, _btnCopyLog, _lnkChangeOut;
    private readonly DropZonePanel _dropZone;
    private readonly Label _lblOutPath;
    private readonly TextBox _txtPassword, _txtConfirm;
    private readonly TextBox _txtPrivkey;
    private readonly NeonButton _btnBrowsePrivkey;
    private readonly NeonButton _btnGenerateKeypair;
    private readonly CheckBox _chkCompress;
    private readonly ComboBox _cmbSuite;
    private readonly RichTextBox _rtbLog;
    private readonly Label _lblStatus;
    private readonly NeonProgressBar _fileProgressBar;
    private readonly NeonButton _btnAdvanced;
    private bool _advancedExpanded;
    private readonly TableLayoutPanel _pwPanel, _pqcPanel;

    // -----------------------------------------------------------------------
    // TEXT TAB controls
    // -----------------------------------------------------------------------
    private readonly SegmentedToggle _toggleText;
    private readonly TableLayoutPanel _pwPanelText, _pqcPanelText;
    private readonly TextBox _txtPasswordText, _txtConfirmText, _txtPrivkeyText;
    private readonly RichTextBox _txtInput, _txtOutput;
    private readonly CheckBox _chkTextForceActions;
    private readonly NeonButton _btnTextEncrypt, _btnTextDecrypt;
    private readonly Label _lblStatusText;

    // -----------------------------------------------------------------------
    // VAULT TAB controls
    // -----------------------------------------------------------------------
    private readonly SegmentedToggle _toggleVault;
    private readonly TableLayoutPanel _pwPanelVault, _pqcPanelVault;
    private readonly TextBox _txtPasswordVault, _txtPrivkeyVault;
    private readonly DropZonePanel _dropZoneVault;
    private readonly TextBox _txtDriveLetter;
    private readonly RichTextBox _rtbLogVault;
    private readonly TreeView _tvVaultContents;
    private readonly Label _lblVaultEmptyHint;
    private readonly Label _lblStatusVault;
    private readonly Label _lblVaultSelection;
    private readonly NeonButton _btnMountVault;
    private readonly NeonButton _btnCreateVault;
    private readonly NeonButton _btnLoadVault;
    private readonly NeonButton _btnRekeyVault;
    private readonly NeonButton _btnUnloadVault;
    private readonly NeonButton _btnAddToVault;
    private readonly NeonButton _btnRemoveVaultItem;
    private readonly NeonButton _btnExtractVaultItem;
    private readonly ContextMenuStrip _vaultTreeMenu;
    private readonly ContextMenuStrip _vaultAddMenu;
    private bool _suppressVaultFileDroppedHandler;
    private bool _suppressTreeCheckEvents;
    private readonly HashSet<string> _externalOpenSessionDirs = new(StringComparer.OrdinalIgnoreCase);
    private sealed class ExternalOpenSession
    {
        public string SessionDir { get; init; } = string.Empty;
        public string VaultPath { get; init; } = string.Empty;
        public string VaultItemPath { get; init; } = string.Empty;
        public string ExtractedPath { get; init; } = string.Empty;
        public string AuthArgs { get; init; } = string.Empty;
        public string? StdinPassword { get; init; }
        public long OriginalLength { get; init; }
        public DateTime OriginalWriteUtc { get; init; }
    }

    // -----------------------------------------------------------------------
    // Shared state
    // -----------------------------------------------------------------------
    private readonly ShimmerStrip _shimmer;
    private Action<string?, bool>? _openAddContactDialog;
    private Action<string>? _openDeliveryWithSource;
    private CancellationTokenSource? _cts;
    private DateTime _fileProgressStartUtc;
    private string _fileProgressStage = "processing";
    private static readonly Regex CliProgressRe = new(
        @"^\[PROGRESS\]\s+op=(?<op>\w+)\s+processed=(?<processed>\d+)\s+total=(?<total>\d+)\s*$",
        RegexOptions.Compiled);
    private static readonly Regex CliProgressStageRe = new(
        @"^\[PROGRESS_STAGE\]\s+op=(?<op>\w+)\s+stage=(?<stage>[a-zA-Z0-9_-]+)\s*$",
        RegexOptions.Compiled);
    private bool _busy;
    private Process? _mountProc;
    private char _mountedDrive;
    private bool _isVaultMount; // true when _mountProc is a `vault mount` process
    private readonly CyberpunkTabControl _tabs;

    private static readonly string ExePath = ResolveExePath();
    private static readonly string ExtractorStubPath = ResolveExtractorStubPath();
    private static readonly string LocalKeysDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "ObsidianQ", "keys");
    private static readonly string BundleKeysDir = Path.Combine(AppContext.BaseDirectory, "keys");
    private static readonly string[] DefaultPubKeyNames  = ["obsidianq_test_pub.bin",  "obsidianq_test_pub.pem",  "obsidianq_pub.bin",  "obsidianq_pub.pem"];
    private static readonly string[] DefaultPrivKeyNames = ["obsidianq_test_priv.bin", "obsidianq_test_priv.pem", "obsidianq_priv.bin", "obsidianq_priv.pem"];

    // -----------------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------------
    public MainForm(
        string? preloadPath,
        bool createVaultOnStart = false,
        string? createVaultTarget = null,
        bool createPackageOnStart = false,
        string? createPackageTarget = null,
        bool encryptFolderOnStart = false,
        string? encryptFolderTarget = null)
    {
        Text = "ObsidianQ - Post-Quantum Encryption";
        Size = new Size(840, 780);
        MinimumSize = new Size(680, 680);
        BackColor = Theme.Bg;
        ForeColor = Theme.TextMain;
        FormBorderStyle = FormBorderStyle.Sizable;
        StartPosition = FormStartPosition.CenterScreen;
        Font = Theme.SafeMono(9f);

        // ------------------------------------------------------------------
        // Shimmer strip
        // ------------------------------------------------------------------
        _shimmer = new ShimmerStrip { Dock = DockStyle.Top };

        // ------------------------------------------------------------------
        // FILE TAB – instantiate controls
        // ------------------------------------------------------------------
        _toggle = new SegmentedToggle { Dock = DockStyle.Fill, Margin = new Padding(0) };
        _toggle.RightLabel = "SECURE CONTACTS - KEY BASED ENCRYPTION";
        _toggle.SelectionChanged += OnToggleChanged;

        _dropZone = new DropZonePanel { Dock = DockStyle.Fill, Margin = new Padding(0, 2, 0, 2) };
        _dropZone.FileDropped += OnFileDropped;

        _lblOutPath = MakeLabel("-", 8f);
        _lblOutPath.Dock = DockStyle.Fill;
        _lblOutPath.TextAlign = ContentAlignment.MiddleLeft;
        _lblOutPath.ForeColor = Theme.AccentDim;

        _lnkChangeOut = new NeonButton { Text = "Change...", Dock = DockStyle.Fill, Margin = new Padding(4, 2, 0, 2) };
        _lnkChangeOut.Click += ChangeOut_Click;

        _txtPassword = MakeTextBox(password: true); _txtPassword.PlaceholderText = "Password...";
        _txtConfirm  = MakeTextBox(password: true); _txtConfirm.PlaceholderText  = "Confirm password...";
        _pwPanel = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1,
            BackColor = Theme.Bg, Margin = new Padding(0),
        };
        _pwPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        _pwPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        _pwPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        _pwPanel.Controls.Add(MakeLabeled("PASSWORD", _txtPassword), 0, 0);
        _pwPanel.Controls.Add(MakeLabeled("CONFIRM",  _txtConfirm),  1, 0);

        _txtPrivkey = MakeTextBox(); _txtPrivkey.PlaceholderText = "Public key path(s) (.bin/.pem). Separate multiple with ;";
        _btnBrowsePrivkey   = new NeonButton { Text = "BROWSE",       Dock = DockStyle.Fill, Margin = new Padding(3, 2, 0, 2) };
        _btnBrowsePrivkey.Click += BrowsePrivkey_Click;
        _btnGenerateKeypair = new NeonButton { Text = "GENERATE KEY", Dock = DockStyle.Fill, Margin = new Padding(3, 2, 0, 2) };
        _btnGenerateKeypair.Click += BtnGenerateKeypair_Click;
        int pqcBrowseWidth = Math.Max(86,  TextRenderer.MeasureText("BROWSE",       Theme.SafeMono(9f)).Width + 16);
        int pqcRecipientsWidth = Math.Max(120, TextRenderer.MeasureText("RECIPIENTS", Theme.SafeMono(9f)).Width + 18);
        var btnPickRecipientsFile = new NeonButton { Text = "RECIPIENTS", Dock = DockStyle.Fill, Margin = new Padding(3, 2, 0, 2) };
        btnPickRecipientsFile.Click += (_, _) =>
        {
            string? picked = ShowRecipientsPicker(_txtPrivkey.Text);
            if (!string.IsNullOrWhiteSpace(picked)) _txtPrivkey.Text = picked;
        };
        _pqcPanel = new TableLayoutPanel
        {
            Dock = DockStyle.Top, ColumnCount = 3, RowCount = 1,
            BackColor = Theme.Bg, Margin = new Padding(0), Visible = false,
        };
        _pqcPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        _pqcPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, pqcBrowseWidth));
        _pqcPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, pqcRecipientsWidth));
        _pqcPanel.RowStyles.Clear();
        _pqcPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 26));
        _pqcPanel.Height = 26; _pqcPanel.MinimumSize = new Size(0, 26); _pqcPanel.MaximumSize = new Size(int.MaxValue, 26);
        _pqcPanel.Controls.Add(_txtPrivkey, 0, 0);
        _pqcPanel.Controls.Add(_btnBrowsePrivkey, 1, 0);
        _pqcPanel.Controls.Add(btnPickRecipientsFile, 2, 0);

        _chkCompress = new CheckBox
        {
            Text = "COMPRESS (zstd)", ForeColor = Theme.TextDim, BackColor = Theme.Bg,
            Checked = false, AutoSize = true, Margin = new Padding(0, 8, 16, 0),
        };
        _cmbSuite = new ComboBox
        {
            DropDownStyle = ComboBoxStyle.DropDownList,
            BackColor = Theme.Surface, ForeColor = Theme.Accent,
            FlatStyle = FlatStyle.Flat, Width = 200, Margin = new Padding(0, 6, 0, 0),
        };
        _cmbSuite.Items.AddRange(["xchacha20 (default)", "aesgcm"]);
        _cmbSuite.SelectedIndex = 0;

        _btnAdvanced = new NeonButton
        {
            Text = "ADVANCED [>]", Dock = DockStyle.Fill,
            Margin = new Padding(0), Font = Theme.SafeMono(7.5f),
        };

        _rtbLog = new RichTextBox
        {
            Dock = DockStyle.Fill, ReadOnly = true, WordWrap = false,
            BackColor = Theme.LogBg, ForeColor = Theme.Accent,
            BorderStyle = BorderStyle.None, ScrollBars = RichTextBoxScrollBars.Both,
            Font = Theme.SafeMono(8.5f),
        };
        _rtbLog.HandleCreated += (_, _) => SetWindowTheme(_rtbLog.Handle, "DarkMode_Explorer", null);

        _lblStatus = MakeLabel("READY", 8.5f);
        _lblStatus.Dock = DockStyle.Fill;
        _lblStatus.TextAlign = ContentAlignment.MiddleLeft;
        _lblStatus.Margin = new Padding(0, 0, 0, 1);
        _fileProgressBar = new NeonProgressBar
        {
            Dock = DockStyle.Fill,
            Minimum = 0,
            Maximum = 100,
            Value = 0,
            Style = ProgressBarStyle.Continuous,
            Margin = new Padding(0, 1, 8, 1),
        };

        _btnCopyLog = new NeonButton { Text = "COPY LOG", Dock = DockStyle.Fill, Margin = new Padding(3, 2, 0, 2) };
        _btnCopyLog.Click += (_, _) => { Clipboard.SetText(_rtbLog.Text); };

        _btnRun = new NeonButton { Text = "RUN", Dock = DockStyle.Fill, Margin = new Padding(3, 2, 0, 2), Font = Theme.SafeMono(10f) };
        _btnRun.ForeColor = Theme.Accent;
        _btnRun.Click += BtnRun_Click;

        // ------------------------------------------------------------------
        // TEXT TAB – instantiate controls
        // ------------------------------------------------------------------
        _toggleText = new SegmentedToggle { Dock = DockStyle.Fill, Margin = new Padding(0) };
        _toggleText.RightLabel = "SECURE CONTACTS - KEY BASED ENCRYPTION";
        _toggleText.SelectionChanged += OnToggleTextChanged;

        _txtPasswordText = MakeTextBox(password: true); _txtPasswordText.PlaceholderText = "Password...";
        _txtConfirmText  = MakeTextBox(password: true); _txtConfirmText.PlaceholderText  = "Confirm...";
        _pwPanelText = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1,
            BackColor = Theme.Bg, Margin = new Padding(0),
        };
        _pwPanelText.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        _pwPanelText.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        _pwPanelText.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        _pwPanelText.Controls.Add(MakeLabeled("PASSWORD", _txtPasswordText), 0, 0);
        _pwPanelText.Controls.Add(MakeLabeled("CONFIRM",  _txtConfirmText),  1, 0);

        _txtPrivkeyText = MakeTextBox(); _txtPrivkeyText.PlaceholderText = "Key file path(s) (.bin/.pem). Separate multiple with ;";
        var btnBrowseText = new NeonButton { Text = "BROWSE",       Dock = DockStyle.Fill, Margin = new Padding(3, 2, 0, 2) };
        btnBrowseText.Click += (_, _) => BrowseKeyFile(_txtPrivkeyText);
        var btnPickRecipientsText = new NeonButton { Text = "RECIPIENTS", Dock = DockStyle.Fill, Margin = new Padding(3, 2, 0, 2) };
        btnPickRecipientsText.Click += (_, _) =>
        {
            string? picked = ShowRecipientsPicker(_txtPrivkeyText.Text);
            if (!string.IsNullOrWhiteSpace(picked)) _txtPrivkeyText.Text = picked;
        };
        _pqcPanelText = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, ColumnCount = 3, RowCount = 1,
            BackColor = Theme.Bg, Margin = new Padding(0), Visible = false,
        };
        _pqcPanelText.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        _pqcPanelText.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, pqcBrowseWidth));
        _pqcPanelText.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, pqcRecipientsWidth));
        _pqcPanelText.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        _pqcPanelText.Controls.Add(_txtPrivkeyText, 0, 0);
        _pqcPanelText.Controls.Add(btnBrowseText,   1, 0);
        _pqcPanelText.Controls.Add(btnPickRecipientsText, 2, 0);

        _txtInput = new RichTextBox
        {
            Dock = DockStyle.Fill, WordWrap = true,
            BackColor = Theme.Surface, ForeColor = Theme.TextMain,
            BorderStyle = BorderStyle.None, ScrollBars = RichTextBoxScrollBars.Vertical,
            Font = Theme.SafeMono(9f),
        };
        _txtOutput = new RichTextBox
        {
            Dock = DockStyle.Fill, ReadOnly = true, WordWrap = true,
            BackColor = Theme.LogBg, ForeColor = Theme.Accent,
            BorderStyle = BorderStyle.None, ScrollBars = RichTextBoxScrollBars.Vertical,
            Font = Theme.SafeMono(9f),
        };
        _txtOutput.HandleCreated += (_, _) => SetWindowTheme(_txtOutput.Handle, "DarkMode_Explorer", null);
        _chkTextForceActions = new CheckBox
        {
            Text = "FORCE ACTIONS",
            ForeColor = Theme.TextDim,
            BackColor = Theme.Bg,
            AutoSize = false,
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleRight,
            Margin = new Padding(4, 2, 0, 2),
        };
        _chkTextForceActions.CheckedChanged += (_, _) => UpdateTextInputActionHints();
        _txtInput.TextChanged += (_, _) => UpdateTextInputActionHints();

        _lblStatusText = MakeLabel("READY", 8.5f);
        _lblStatusText.Dock = DockStyle.Fill;
        _lblStatusText.TextAlign = ContentAlignment.MiddleLeft;

        // ------------------------------------------------------------------
        // VAULT TAB – instantiate controls
        // ------------------------------------------------------------------
        _dropZoneVault = new DropZonePanel
        {
            Dock   = DockStyle.Fill,
            Margin = new Padding(0, 2, 0, 2),
            Filter = "ObsidianQ vaults|*.vault;*.obsqv|All files|*.*",
        };
        _dropZoneVault.FileDropped += async (_, path) =>
        {
            if (_suppressVaultFileDroppedHandler) return;
            await HandleVaultFileSelectedAsync(path, autoLoad: true);
        };

        _txtDriveLetter = new TextBox
        {
            Text = FindFirstAvailableDriveLetter().ToString(), Width = 40, BackColor = Theme.Surface, ForeColor = Theme.Accent,
            BorderStyle = BorderStyle.FixedSingle, TextAlign = HorizontalAlignment.Center,
            MaxLength = 1, CharacterCasing = CharacterCasing.Upper,
            Font = Theme.SafeMono(10f), Margin = new Padding(4, 2, 0, 2),
        };

        _toggleVault = new SegmentedToggle { Dock = DockStyle.Fill, Margin = new Padding(0) };
        _toggleVault.RightLabel = "SECURE CONTACTS - KEY BASED ENCRYPTION";
        _toggleVault.SelectionChanged += OnToggleVaultChanged;

        _txtPasswordVault = MakeTextBox(password: true); _txtPasswordVault.PlaceholderText = "Password...";
        _pwPanelVault = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 1,
            BackColor = Theme.Bg, Margin = new Padding(0),
        };
        _pwPanelVault.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        _pwPanelVault.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        _pwPanelVault.Controls.Add(MakeLabeled("PASSWORD", _txtPasswordVault), 0, 0);

        _txtPrivkeyVault = MakeTextBox(); _txtPrivkeyVault.PlaceholderText = "Private key (.bin/.pem)";
        var btnBrowseVault = new NeonButton { Text = "BROWSE",       Dock = DockStyle.Fill, Margin = new Padding(3, 2, 0, 2) };
        btnBrowseVault.Click += (_, _) => BrowseKeyFile(_txtPrivkeyVault);
        _pqcPanelVault = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1,
            BackColor = Theme.Bg, Margin = new Padding(0), Visible = false,
        };
        _pqcPanelVault.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        _pqcPanelVault.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, pqcBrowseWidth));
        _pqcPanelVault.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        _pqcPanelVault.Controls.Add(_txtPrivkeyVault, 0, 0);
        _pqcPanelVault.Controls.Add(btnBrowseVault,   1, 0);

        _rtbLogVault = new RichTextBox
        {
            Dock = DockStyle.Fill, ReadOnly = true, WordWrap = false,
            BackColor = Theme.LogBg, ForeColor = Theme.Accent,
            BorderStyle = BorderStyle.None, ScrollBars = RichTextBoxScrollBars.Both,
            Font = Theme.SafeMono(8.5f),
        };
        _rtbLogVault.HandleCreated += (_, _) => SetWindowTheme(_rtbLogVault.Handle, "DarkMode_Explorer", null);

        _tvVaultContents = new TreeView
        {
            Dock = DockStyle.Fill,
            HideSelection = false,
            BackColor = Theme.Surface,
            ForeColor = Theme.Accent,
            BorderStyle = BorderStyle.None,
            ShowLines = true,
            ShowRootLines = true,
            ShowPlusMinus = true,
            FullRowSelect = true,
            Indent = 18,
            Font = Theme.SafeMono(9f),
            CheckBoxes = true,
            AllowDrop = true,
        };
        _tvVaultContents.HandleCreated += (_, _) => SetWindowTheme(_tvVaultContents.Handle, "DarkMode_Explorer", null);
        _tvVaultContents.MouseDown += (_, e) =>
        {
            if (e.Button != MouseButtons.Right) return;
            var hit = _tvVaultContents.GetNodeAt(e.Location);
            _tvVaultContents.SelectedNode = hit;
        };
        _tvVaultContents.DragEnter += (_, e) =>
        {
            if (e.Data?.GetDataPresent(DataFormats.FileDrop) == true) e.Effect = DragDropEffects.Copy;
        };
        _tvVaultContents.DragDrop += async (_, e) =>
        {
            if (e.Data?.GetData(DataFormats.FileDrop) is string[] { Length: > 0 } files)
                await AddFilesToVaultAsync(files);
        };
        _tvVaultContents.AfterSelect += (_, _) => UpdateVaultUiState();
        _tvVaultContents.NodeMouseDoubleClick += async (_, e) =>
        {
            if (e.Node?.Tag is ValueTuple<string, bool, long, string> t && !t.Item2)
                await OpenVaultItemExternalAsync(t.Item1);
        };
        _tvVaultContents.AfterCheck += (_, e) =>
        {
            if (_suppressTreeCheckEvents || e.Node == null) return;
            try
            {
                _suppressTreeCheckEvents = true;
                foreach (TreeNode child in e.Node.Nodes)
                    child.Checked = e.Node.Checked;
            }
            finally
            {
                _suppressTreeCheckEvents = false;
            }
            UpdateVaultUiState();
        };

        _lblVaultEmptyHint = new Label
        {
            Dock = DockStyle.Fill,
            AutoSize = false,
            BackColor = Theme.Surface,
            ForeColor = Theme.TextDim,
            TextAlign = ContentAlignment.MiddleCenter,
            Font = Theme.SafeMono(9f),
            Text = "Vault is empty.\n\nDrag and drop files or folders into this area to add them.",
            Visible = false,
            AllowDrop = true,
        };
        _lblVaultEmptyHint.DragEnter += (_, e) =>
        {
            if (e.Data?.GetDataPresent(DataFormats.FileDrop) == true) e.Effect = DragDropEffects.Copy;
        };
        _lblVaultEmptyHint.DragDrop += async (_, e) =>
        {
            if (e.Data?.GetData(DataFormats.FileDrop) is string[] { Length: > 0 } files)
                await AddFilesToVaultAsync(files);
        };

        _lblStatusVault = MakeLabel("READY", 8.5f);
        _lblStatusVault.Dock = DockStyle.Fill;
        _lblStatusVault.TextAlign = ContentAlignment.MiddleLeft;
        _lblVaultSelection = MakeLabel("Checked: 0", 8.5f);
        _lblVaultSelection.Dock = DockStyle.Fill;
        _lblVaultSelection.TextAlign = ContentAlignment.MiddleRight;
        _lblVaultSelection.ForeColor = Theme.AccentDim;

        _btnMountVault  = new NeonButton { Text = "MOUNT",        Dock = DockStyle.Fill, Margin = new Padding(3, 2, 0, 2) };
        _btnCreateVault = new NeonButton { Text = "CREATE VAULT", Dock = DockStyle.Fill, Margin = new Padding(3, 2, 0, 2) };
        _btnLoadVault   = new NeonButton { Text = "LOAD VAULT",   Dock = DockStyle.Fill, Margin = new Padding(3, 2, 0, 2) };
        _btnRekeyVault  = new NeonButton { Text = "MANAGE ACCESS", Dock = DockStyle.Fill, Margin = new Padding(3, 2, 0, 2) };
        _btnUnloadVault = new NeonButton { Text = "UNLOAD",       Dock = DockStyle.Fill, Margin = new Padding(3, 2, 0, 2) };
        _btnAddToVault  = new NeonButton { Text = "ADD",          Dock = DockStyle.Fill, Margin = new Padding(3, 2, 0, 2) };
        _btnRemoveVaultItem = new NeonButton { Text = "DELETE",   Dock = DockStyle.Fill, Margin = new Padding(3, 2, 0, 2) };
        _btnExtractVaultItem = new NeonButton { Text = "EXTRACT", Dock = DockStyle.Fill, Margin = new Padding(3, 2, 0, 2) };
        _btnMountVault.Click  += BtnMountVault_Click;
        _btnCreateVault.Click += BtnCreateVault_Click;
        _btnLoadVault.Click += async (_, _) => await RefreshVaultContentsAsync();
        _btnRekeyVault.Click += BtnRekeyVault_Click;
        _btnUnloadVault.Click += BtnUnloadVault_Click;
        _btnAddToVault.Click += (_, _) => _vaultAddMenu?.Show(_btnAddToVault, 0, _btnAddToVault.Height);
        _btnRemoveVaultItem.Click += BtnRemoveVaultItem_Click;
        _btnExtractVaultItem.Click += BtnExtractVaultItem_Click;
        _txtPasswordVault.KeyDown += async (_, e) =>
        {
            if (e.KeyCode == Keys.Enter)
            {
                e.SuppressKeyPress = true;
                await RefreshVaultContentsAsync();
            }
        };

        _vaultTreeMenu = new ContextMenuStrip
        {
            BackColor = Theme.Surface,
            ForeColor = Theme.Accent,
            Font = Theme.SafeMono(9f),
            ShowImageMargin = false,
        };
        var miOpen = new ToolStripMenuItem("Open");
        var miOpenPreview = new ToolStripMenuItem("Open (Secure Preview)");
        var miAddFiles = new ToolStripMenuItem("Add File(s)...");
        var miAddFolder = new ToolStripMenuItem("Add Folder...");
        var miRemoveSelected = new ToolStripMenuItem("Delete Selected");
        var miExtractSelected = new ToolStripMenuItem("Extract Selected...");
        var miRemoveByPath = new ToolStripMenuItem("Delete File by Path...");
        miOpen.Click += async (_, _) =>
        {
            if (_tvVaultContents.SelectedNode?.Tag is ValueTuple<string, bool, long, string> t && !t.Item2)
                await OpenVaultItemExternalAsync(t.Item1);
        };
        miOpenPreview.Click += async (_, _) =>
        {
            if (_tvVaultContents.SelectedNode?.Tag is ValueTuple<string, bool, long, string> t && !t.Item2)
                await OpenVaultItemSecureAsync(t.Item1);
        };
        miAddFiles.Click += BtnAddFiles_Click;
        miAddFolder.Click += BtnAddFolder_Click;
        miRemoveSelected.Click += BtnRemoveVaultItem_Click;
        miExtractSelected.Click += BtnExtractVaultItem_Click;
        miRemoveByPath.Click += async (_, _) =>
        {
            using var prompt = new TextPromptForm("Remove File", "Vault path to remove:", "/path/to/file.txt");
            if (prompt.ShowDialog(this) != DialogResult.OK) return;
            if (string.IsNullOrWhiteSpace(prompt.Value)) return;
            await RemoveVaultPathAsync(prompt.Value, isDir: false);
        };
        _vaultTreeMenu.Items.Add(miOpen);
        _vaultTreeMenu.Items.Add(miOpenPreview);
        _vaultTreeMenu.Items.Add(new ToolStripSeparator());
        _vaultTreeMenu.Items.Add(miAddFiles);
        _vaultTreeMenu.Items.Add(miAddFolder);
        _vaultTreeMenu.Items.Add(new ToolStripSeparator());
        _vaultTreeMenu.Items.Add(miRemoveSelected);
        _vaultTreeMenu.Items.Add(miExtractSelected);
        _vaultTreeMenu.Items.Add(miRemoveByPath);
        _vaultTreeMenu.Opening += (_, _) =>
        {
            bool hasItems = GetCheckedOrSelectedVaultItems().Count > 0;
            miRemoveSelected.Enabled = hasItems;
            miExtractSelected.Enabled = hasItems;
            miOpen.Enabled = _tvVaultContents.SelectedNode?.Tag is ValueTuple<string, bool, long, string> t && !t.Item2;
            miOpenPreview.Enabled = miOpen.Enabled;
        };
        _tvVaultContents.ContextMenuStrip = _vaultTreeMenu;

        _vaultAddMenu = new ContextMenuStrip
        {
            BackColor = Theme.Surface,
            ForeColor = Theme.Accent,
            Font = Theme.SafeMono(9f),
            ShowImageMargin = false,
        };
        var miBarAddFiles = new ToolStripMenuItem("Add File(s)...");
        var miBarAddFolder = new ToolStripMenuItem("Add Folder...");
        miBarAddFiles.Click += BtnAddFiles_Click;
        miBarAddFolder.Click += BtnAddFolder_Click;
        _vaultAddMenu.Items.Add(miBarAddFiles);
        _vaultAddMenu.Items.Add(miBarAddFolder);
        _txtPrivkeyVault.KeyDown += async (_, e) =>
        {
            if (e.KeyCode == Keys.Enter)
            {
                e.SuppressKeyPress = true;
                await RefreshVaultContentsAsync();
            }
        };

        // ==================================================================
        // FILE TAB – layout
        // ==================================================================
        var outerFile = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 9,
            Padding = new Padding(16), BackColor = Theme.Bg,
        };
        outerFile.RowStyles.Add(new RowStyle(SizeType.Absolute, 52));  // 0: header
        outerFile.RowStyles.Add(new RowStyle(SizeType.Absolute, 38));  // 1: toggle
        outerFile.RowStyles.Add(new RowStyle(SizeType.Absolute, 92));  // 2: drop zone
        outerFile.RowStyles.Add(new RowStyle(SizeType.Absolute, 26));  // 3: output path
        outerFile.RowStyles.Add(new RowStyle(SizeType.Absolute, 44));  // 4: mode panel
        outerFile.RowStyles.Add(new RowStyle(SizeType.Absolute, 22));  // 5: advanced toggle
        outerFile.RowStyles.Add(new RowStyle(SizeType.Absolute, 0));   // 6: options (collapsed)
        outerFile.RowStyles.Add(new RowStyle(SizeType.Percent, 100));  // 7: log
        outerFile.RowStyles.Add(new RowStyle(SizeType.Absolute, 44));  // 8: status bar

        outerFile.Controls.Add(MakeTabHeader(
            "FILE ENCRYPTION",
            "Encrypt and decrypt files using password or recipient keys."), 0, 0);

        outerFile.Controls.Add(_toggle, 0, 1);
        outerFile.Controls.Add(_dropZone, 0, 2);

        var outRow = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, ColumnCount = 3, RowCount = 1,
            BackColor = Theme.Bg, Margin = new Padding(0),
        };
        outRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 36));
        outRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        outRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 84));
        outRow.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        var lblOutPrefix = MakeLabel("OUT:", 8f);
        lblOutPrefix.Dock = DockStyle.Fill;
        lblOutPrefix.TextAlign = ContentAlignment.MiddleLeft;
        outRow.Controls.Add(lblOutPrefix, 0, 0);
        outRow.Controls.Add(_lblOutPath,  1, 0);
        outRow.Controls.Add(_lnkChangeOut, 2, 0);
        outerFile.Controls.Add(outRow, 0, 3);

        var modeContainerFile = new Panel { Dock = DockStyle.Fill };
        _pwPanel.Dock = DockStyle.Fill;
        _pqcPanel.Dock = DockStyle.Top;
        modeContainerFile.Controls.Add(_pwPanel);
        modeContainerFile.Controls.Add(_pqcPanel);
        outerFile.Controls.Add(modeContainerFile, 0, 4);

        _btnAdvanced.Click += (_, _) =>
        {
            _advancedExpanded = !_advancedExpanded;
            outerFile.RowStyles[6] = new RowStyle(SizeType.Absolute, _advancedExpanded ? 44 : 0);
            _btnAdvanced.Text = _advancedExpanded ? "ADVANCED [v]" : "ADVANCED [>]";
        };
        outerFile.Controls.Add(_btnAdvanced, 0, 5);

        var optRow = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill, FlowDirection = FlowDirection.LeftToRight,
            BackColor = Theme.Bg, WrapContents = false,
        };
        optRow.Controls.Add(MakeLabel("SUITE:", 8.5f));
        optRow.Controls.Add(_cmbSuite);
        optRow.Controls.Add(_chkCompress);
        outerFile.Controls.Add(optRow, 0, 6);

        var logContainerFile = new Panel { Dock = DockStyle.Fill, BackColor = Theme.LogBg };
        logContainerFile.Controls.Add(_rtbLog);
        logContainerFile.Paint += (_, pe) =>
        {
            using var pen = new Pen(Theme.Border, 1f);
            pe.Graphics.DrawRectangle(pen, 0, 0, logContainerFile.Width - 1, logContainerFile.Height - 1);
        };
        outerFile.Controls.Add(logContainerFile, 0, 7);

        var fileBar = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, ColumnCount = 3, RowCount = 2,
            BackColor = Theme.Bg, Margin = new Padding(0),
        };
        fileBar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        fileBar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 94));
        fileBar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 90));
        fileBar.RowStyles.Add(new RowStyle(SizeType.Absolute, 18));  // status text row
        fileBar.RowStyles.Add(new RowStyle(SizeType.Percent, 100));  // action/progress row
        fileBar.Controls.Add(_lblStatus, 0, 0);
        fileBar.Controls.Add(_fileProgressBar, 0, 1);
        fileBar.Controls.Add(_btnCopyLog, 1, 1);
        fileBar.Controls.Add(_btnRun,     2, 1);
        outerFile.Controls.Add(fileBar, 0, 8);

        // ==================================================================
        // TEXT TAB – layout
        // ==================================================================
        var outerText = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 7,
            Padding = new Padding(16), BackColor = Theme.Bg,
        };
        outerText.RowStyles.Add(new RowStyle(SizeType.Absolute, 52));      // 0: header
        outerText.RowStyles.Add(new RowStyle(SizeType.Absolute, 32));      // 1: toggle
        outerText.RowStyles.Add(new RowStyle(SizeType.Absolute, 44));      // 2: mode panel
        outerText.RowStyles.Add(new RowStyle(SizeType.Percent, 50));       // 3: input
        outerText.RowStyles.Add(new RowStyle(SizeType.Absolute, 36));      // 4: buttons
        outerText.RowStyles.Add(new RowStyle(SizeType.Percent, 50));       // 5: output
        outerText.RowStyles.Add(new RowStyle(SizeType.Absolute, 28));      // 6: status

        outerText.Controls.Add(MakeTabHeader(
            "TEXT PROTECTION",
            "Encrypt and decrypt short text, notes, and ciphertext blocks."), 0, 0);
        outerText.Controls.Add(_toggleText, 0, 1);

        var modeContainerText = new Panel { Dock = DockStyle.Fill };
        _pwPanelText.Dock = DockStyle.Fill;
        _pqcPanelText.Dock = DockStyle.Fill;
        modeContainerText.Controls.Add(_pwPanelText);
        modeContainerText.Controls.Add(_pqcPanelText);
        outerText.Controls.Add(modeContainerText, 0, 2);

        var inputContainer = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Bg };
        var lblInput = MakeLabel("PLAINTEXT / CIPHERTEXT", 7.5f);
        lblInput.Dock = DockStyle.Top; lblInput.Height = 16;
        var inputBox = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Surface };
        inputBox.Controls.Add(_txtInput);
        inputBox.Paint += (_, pe) =>
        {
            using var pen = new Pen(Theme.Border, 1f);
            pe.Graphics.DrawRectangle(pen, 0, 0, inputBox.Width - 1, inputBox.Height - 1);
        };
        inputContainer.Controls.Add(inputBox);
        inputContainer.Controls.Add(lblInput);
        outerText.Controls.Add(inputContainer, 0, 3);

        var btnRowText = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, ColumnCount = 4, RowCount = 1,
            BackColor = Theme.Bg, Margin = new Padding(0),
        };
        btnRowText.ColumnCount = 5;
        for (int i = 0; i < 4; i++) btnRowText.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 25));
        btnRowText.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 130));
        btnRowText.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        var btnPaste = new NeonButton { Text = "PASTE",       Dock = DockStyle.Fill, Margin = new Padding(0, 2, 3, 2) };
        _btnTextEncrypt = new NeonButton { Text = "ENCRYPT",  Dock = DockStyle.Fill, Margin = new Padding(0, 2, 3, 2) };
        _btnTextDecrypt = new NeonButton { Text = "DECRYPT",  Dock = DockStyle.Fill, Margin = new Padding(0, 2, 3, 2) };
        var btnCopy  = new NeonButton { Text = "COPY OUTPUT", Dock = DockStyle.Fill, Margin = new Padding(0, 2, 0, 2) };
        btnPaste.Click += (_, _) => { _txtInput.Text = Clipboard.GetText(); };
        _btnTextEncrypt.Click += BtnTextEncrypt_Click;
        _btnTextDecrypt.Click += BtnTextDecrypt_Click;
        btnCopy.Click  += (_, _) => { if (!string.IsNullOrEmpty(_txtOutput.Text)) Clipboard.SetText(_txtOutput.Text); };
        btnRowText.Controls.Add(btnPaste, 0, 0);
        btnRowText.Controls.Add(_btnTextEncrypt, 1, 0);
        btnRowText.Controls.Add(_btnTextDecrypt, 2, 0);
        btnRowText.Controls.Add(btnCopy,  3, 0);
        btnRowText.Controls.Add(_chkTextForceActions, 4, 0);
        outerText.Controls.Add(btnRowText, 0, 4);

        var outputContainer = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Bg };
        var lblOutput = MakeLabel("OUTPUT", 7.5f);
        lblOutput.Dock = DockStyle.Top; lblOutput.Height = 16;
        var outputBox = new Panel { Dock = DockStyle.Fill, BackColor = Theme.LogBg };
        outputBox.Controls.Add(_txtOutput);
        outputBox.Paint += (_, pe) =>
        {
            using var pen = new Pen(Theme.Border, 1f);
            pe.Graphics.DrawRectangle(pen, 0, 0, outputBox.Width - 1, outputBox.Height - 1);
        };
        outputContainer.Controls.Add(outputBox);
        outputContainer.Controls.Add(lblOutput);
        outerText.Controls.Add(outputContainer, 0, 5);

        outerText.Controls.Add(_lblStatusText, 0, 6);

        // ==================================================================
        // VAULT TAB – layout
        // ==================================================================
        var outerVault = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 9,
            Padding = new Padding(16), BackColor = Theme.Bg,
        };
        outerVault.RowStyles.Add(new RowStyle(SizeType.Absolute, 52));    // 0: header
        outerVault.RowStyles.Add(new RowStyle(SizeType.Absolute, 68));    // 1: drop zone
        outerVault.RowStyles.Add(new RowStyle(SizeType.Absolute, 0));     // 2: drive letter (hidden)
        outerVault.RowStyles.Add(new RowStyle(SizeType.Absolute, 32));    // 3: toggle
        outerVault.RowStyles.Add(new RowStyle(SizeType.Absolute, 44));    // 4: mode panel
        outerVault.RowStyles.Add(new RowStyle(SizeType.Absolute, 32));    // 5: load vault
        outerVault.RowStyles.Add(new RowStyle(SizeType.Percent, 62));     // 6: vault explorer
        outerVault.RowStyles.Add(new RowStyle(SizeType.Percent, 38));     // 7: log
        outerVault.RowStyles.Add(new RowStyle(SizeType.Absolute, 36));    // 8: status + buttons

        outerVault.Controls.Add(MakeTabHeader(
            "VAULT",
            "Create, open, and manage encrypted vault containers."), 0, 0);
        outerVault.Controls.Add(_dropZoneVault, 0, 1);

        var driveRow = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, ColumnCount = 3, RowCount = 1,
            BackColor = Theme.Bg, Margin = new Padding(0),
        };
        driveRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 80));
        driveRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 56));
        driveRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        driveRow.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        var lblDrive = MakeLabel("DRIVE:", 8.5f);
        lblDrive.Dock = DockStyle.Fill;
        lblDrive.TextAlign = ContentAlignment.MiddleLeft;
        driveRow.Controls.Add(lblDrive, 0, 0);
        driveRow.Controls.Add(_txtDriveLetter, 1, 0);
        driveRow.Controls.Add(new Panel { Dock = DockStyle.Fill, BackColor = Theme.Bg }, 2, 0);
        // Mount/drive controls intentionally hidden in current UI.

        outerVault.Controls.Add(_toggleVault, 0, 3);

        var modeContainerVault = new Panel { Dock = DockStyle.Fill };
        _pwPanelVault.Dock = DockStyle.Fill;
        _pqcPanelVault.Dock = DockStyle.Fill;
        modeContainerVault.Controls.Add(_pwPanelVault);
        modeContainerVault.Controls.Add(_pqcPanelVault);
        outerVault.Controls.Add(modeContainerVault, 0, 4);

        var loadRow = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 5,
            RowCount = 1,
            BackColor = Theme.Bg,
            Margin = new Padding(0),
        };
        loadRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        loadRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 118));
        loadRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 110));
        loadRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 136));
        loadRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 90));
        loadRow.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        var lblStepLoad = MakeLabel("Step 3: Load vault", 8.5f);
        lblStepLoad.Dock = DockStyle.Fill;
        lblStepLoad.TextAlign = ContentAlignment.MiddleLeft;
        loadRow.Controls.Add(lblStepLoad, 0, 0);
        loadRow.Controls.Add(_btnCreateVault, 1, 0);
        loadRow.Controls.Add(_btnLoadVault, 2, 0);
        loadRow.Controls.Add(_btnRekeyVault, 3, 0);
        loadRow.Controls.Add(_btnUnloadVault, 4, 0);
        outerVault.Controls.Add(loadRow, 0, 5);

        var listContainerVault = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Surface };
        listContainerVault.Controls.Add(_tvVaultContents);
        listContainerVault.Controls.Add(_lblVaultEmptyHint);
        listContainerVault.Paint += (_, pe) =>
        {
            using var pen = new Pen(Theme.Border, 1f);
            pe.Graphics.DrawRectangle(pen, 0, 0, listContainerVault.Width - 1, listContainerVault.Height - 1);
        };
        outerVault.Controls.Add(listContainerVault, 0, 6);

        var logContainerVault = new Panel { Dock = DockStyle.Fill, BackColor = Theme.LogBg };
        logContainerVault.Controls.Add(_rtbLogVault);
        logContainerVault.Paint += (_, pe) =>
        {
            using var pen = new Pen(Theme.Border, 1f);
            pe.Graphics.DrawRectangle(pen, 0, 0, logContainerVault.Width - 1, logContainerVault.Height - 1);
        };
        outerVault.Controls.Add(logContainerVault, 0, 7);

        var vaultBar = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, ColumnCount = 5, RowCount = 1,
            BackColor = Theme.Bg, Margin = new Padding(0),
        };
        vaultBar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        vaultBar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 170));
        vaultBar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 92));
        vaultBar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 92));
        vaultBar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 90));
        vaultBar.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        vaultBar.Controls.Add(_lblStatusVault, 0, 0);
        vaultBar.Controls.Add(_lblVaultSelection, 1, 0);
        vaultBar.Controls.Add(_btnAddToVault,  2, 0);
        vaultBar.Controls.Add(_btnExtractVaultItem, 3, 0);
        vaultBar.Controls.Add(_btnRemoveVaultItem, 4, 0);
        outerVault.Controls.Add(vaultBar, 0, 8);        // ==================================================================
        // EXCHANGE TAB - layout
        // ==================================================================
        var txtMyPubPath = MakeTextBox(); txtMyPubPath.ReadOnly = true; txtMyPubPath.PlaceholderText = "My public key path (.bin/.pem)";
        var txtMyPub = MakeTextBox(); txtMyPub.ReadOnly = true; txtMyPub.Multiline = true; txtMyPub.ScrollBars = ScrollBars.Vertical; txtMyPub.PlaceholderText = "My public key (base64)";
        var txtMyPubRecv = MakeTextBox(); txtMyPubRecv.ReadOnly = true; txtMyPubRecv.Multiline = true; txtMyPubRecv.ScrollBars = ScrollBars.Vertical; txtMyPubRecv.PlaceholderText = "Share this public key text with sender";
        var txtMyPriv = MakeTextBox(); txtMyPriv.ReadOnly = true; txtMyPriv.PlaceholderText = "My private key path";
        var txtExRecipientPub = MakeTextBox(); txtExRecipientPub.Multiline = true; txtExRecipientPub.ScrollBars = ScrollBars.Vertical; txtExRecipientPub.PlaceholderText = "Paste recipient public key text (base64 or PEM)";
        txtMyPub.Margin = new Padding(0, 4, 0, 4);
        txtMyPubRecv.Margin = new Padding(0, 4, 0, 4);
        txtExRecipientPub.Margin = new Padding(0, 4, 0, 4);
        var txtExIn = MakeTextBox(); txtExIn.PlaceholderText = "File to send";
        var txtExOut = MakeTextBox(); txtExOut.PlaceholderText = "Output package (.obsq)";
        var txtExPktIn = MakeTextBox(); txtExPktIn.PlaceholderText = "Received package (.obsq)";
        var txtExOutDir = MakeTextBox(); txtExOutDir.PlaceholderText = "Output folder for decrypted file";
        var lstExItems = new ListBox
        {
            Dock = DockStyle.Fill,
            BackColor = Theme.Surface,
            ForeColor = Theme.TextMain,
            BorderStyle = BorderStyle.FixedSingle,
            Font = Theme.SafeMono(8.5f),
            IntegralHeight = false,
            HorizontalScrollbar = true,
        };
        lstExItems.HandleCreated += (_, _) => SetWindowTheme(lstExItems.Handle, "DarkMode_Explorer", null);
        var cmbExRecipient = new ComboBox
        {
            DropDownStyle = ComboBoxStyle.DropDownList,
            BackColor = Theme.Surface,
            ForeColor = Theme.Accent,
            FlatStyle = FlatStyle.Flat,
            Dock = DockStyle.Fill,
        };
        string exRecipientsPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "ObsidianQ",
            "trusted_recipients_v1.tsv");
        var exRecipientMap = new Dictionary<string, string>(StringComparer.Ordinal);
        string ExShortFingerprint(string full)
        {
            if (string.IsNullOrWhiteSpace(full)) return "????????????";
            string t = full.Trim();
            return t.Length <= 8 ? t : t[..8];
        }
        void ReloadExchangeRecipients()
        {
            string selected = cmbExRecipient.SelectedItem as string ?? string.Empty;
            cmbExRecipient.Items.Clear();
            exRecipientMap.Clear();
            cmbExRecipient.Items.Add("Manual key paste");
            if (File.Exists(exRecipientsPath))
            {
                foreach (string line in File.ReadAllLines(exRecipientsPath))
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    string[] parts = line.Split('\t');
                    if (parts.Length < 5) continue;
                    string name = parts[0].Trim();
                    string fp = parts[1].Trim();
                    string b64 = parts[4].Trim();
                    if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(b64)) continue;
                    string label = $"{name} ({ExShortFingerprint(fp)})";
                    exRecipientMap[label] = b64;
                    cmbExRecipient.Items.Add(label);
                }
            }
            int idx = Math.Max(0, cmbExRecipient.Items.IndexOf(selected));
            cmbExRecipient.SelectedIndex = idx;
        }
        cmbExRecipient.DropDown += (_, _) => ReloadExchangeRecipients();
        cmbExRecipient.SelectedIndexChanged += (_, _) =>
        {
            string key = cmbExRecipient.SelectedItem as string ?? string.Empty;
            if (exRecipientMap.TryGetValue(key, out var b64))
                txtExRecipientPub.Text = b64;
        };
        ReloadExchangeRecipients();
        var cmbExSuite = new ComboBox
        {
            DropDownStyle = ComboBoxStyle.DropDownList,
            BackColor = Theme.Surface,
            ForeColor = Theme.Accent,
            FlatStyle = FlatStyle.Flat,
            Dock = DockStyle.Fill,
        };
        cmbExSuite.Items.AddRange(["xchacha20", "aesgcm"]);
        cmbExSuite.SelectedIndex = 0;
        var exModeToggle = new SegmentedToggle { Dock = DockStyle.Fill, Height = 28, Margin = new Padding(0) };
        exModeToggle.LeftLabel = "SEND FILE";
        exModeToggle.RightLabel = "RECEIVE FILE";
        exModeToggle.SetSelected(SegmentedToggle.Segment.Password);

        var rtbExLog = new RichTextBox
        {
            Dock = DockStyle.Fill, ReadOnly = true, WordWrap = false,
            BackColor = Theme.LogBg, ForeColor = Theme.Accent,
            BorderStyle = BorderStyle.None, ScrollBars = RichTextBoxScrollBars.Both,
            Font = Theme.SafeMono(8.5f),
        };
        rtbExLog.HandleCreated += (_, _) => SetWindowTheme(rtbExLog.Handle, "DarkMode_Explorer", null);
        var lblExStatus = MakeLabel("READY", 8.5f);
        lblExStatus.Dock = DockStyle.Fill;
        lblExStatus.TextAlign = ContentAlignment.MiddleLeft;
        Label lblHint = null!;
        TableLayoutPanel? sendIdentityPanel = null;
        TableLayoutPanel? recvIdentityPanel = null;
        TableLayoutPanel? outerExchangeRef = null;

        string? FindDefaultKey(string[] names)
        {
            bool wantPublic = names.Contains("obsidianq_test_pub.bin", StringComparer.OrdinalIgnoreCase)
                || names.Contains("obsidianq_pub.bin", StringComparer.OrdinalIgnoreCase);
            string? latest = FindLatestKeyPath(wantPublic, LocalKeysDir, BundleKeysDir);
            if (!string.IsNullOrWhiteSpace(latest)) return latest;

            foreach (string dir in new[] { BundleKeysDir, LocalKeysDir })
                foreach (string name in names)
                {
                    string candidate = Path.Combine(dir, name);
                    if (File.Exists(candidate)) return candidate;
                }
            return null;
        }

        void ExLog(string text, Color color)
        {
            rtbExLog.SelectionStart = rtbExLog.TextLength;
            rtbExLog.SelectionLength = 0;
            rtbExLog.SelectionColor = color;
            rtbExLog.AppendText(text + "\n");
            rtbExLog.ScrollToCaret();
        }

        void ExStatus(string message, bool error = false)
        {
            lblExStatus.ForeColor = error ? Theme.Error : Theme.Accent;
            lblExStatus.Text = message;
            ExLog((error ? "[ERR] " : "[OK] ") + message, error ? Theme.Error : Theme.Accent);
        }

        async Task<(int ExitCode, string Stdout, string Stderr)> RunExchangeCliAsync(string args)
        {
            var psi = new ProcessStartInfo
            {
                FileName = ExePath,
                Arguments = args,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var proc = new Process { StartInfo = psi };
            proc.Start();
            string stdout = await proc.StandardOutput.ReadToEndAsync();
            string stderr = await proc.StandardError.ReadToEndAsync();
            await proc.WaitForExitAsync();
            return (proc.ExitCode, stdout, stderr);
        }

        async Task ShowFingerprintAsync(string keyPath, string label)
        {
            if (string.IsNullOrWhiteSpace(keyPath) || !File.Exists(keyPath)) { ExStatus($"Select a valid {label} key first.", true); return; }
            var (code, stdout, stderr) = await RunWithBusyDialogAsync(
                "Exchange",
                $"Calculating fingerprint for {label}...",
                () => RunExchangeCliAsync($"exchange fingerprint --key \"{keyPath}\""));
            if (!string.IsNullOrWhiteSpace(stderr)) ExLog(stderr.TrimEnd(), Theme.Error);
            if (!string.IsNullOrWhiteSpace(stdout)) ExLog($"{label} fingerprint: {stdout.Trim()}", Theme.AccentDim);
            if (code != 0) ExStatus($"Fingerprint failed (exit {code}).", true);
        }

        string NormalizeKeyText(string text)
        {
            if (string.IsNullOrWhiteSpace(text)) return string.Empty;
            var sb = new StringBuilder();
            foreach (var rawLine in text.Replace("\r", "").Split('\n'))
            {
                string line = rawLine.Trim();
                if (line.StartsWith("-----BEGIN ", StringComparison.Ordinal) || line.StartsWith("-----END ", StringComparison.Ordinal))
                    continue;
                sb.Append(line);
            }
            return sb.ToString().Trim();
        }

        void RefreshMyPublicKeyText()
        {
            if (string.IsNullOrWhiteSpace(txtMyPubPath.Text) || !File.Exists(txtMyPubPath.Text))
            {
                txtMyPub.Text = string.Empty;
                txtMyPubRecv.Text = string.Empty;
                return;
            }

            try
            {
                byte[] raw = File.ReadAllBytes(txtMyPubPath.Text);
                string b64 = Convert.ToBase64String(raw, Base64FormattingOptions.InsertLineBreaks);
                txtMyPub.Text = b64;
                txtMyPubRecv.Text = b64;
            }
            catch (Exception ex)
            {
                txtMyPub.Text = string.Empty;
                txtMyPubRecv.Text = string.Empty;
                ExStatus($"Failed to render public key text: {ex.Message}", true);
            }
        }

        bool TryWriteRecipientKeyTempFile(out string tempPath)
        {
            tempPath = string.Empty;
            string normalized = NormalizeKeyText(txtExRecipientPub.Text);
            if (string.IsNullOrWhiteSpace(normalized)) return false;
            try
            {
                byte[] raw = Convert.FromBase64String(normalized);
                tempPath = Path.Combine(Path.GetTempPath(), $"obsidianq_recipient_{Guid.NewGuid():N}.bin");
                File.WriteAllBytes(tempPath, raw);
                return true;
            }
            catch
            {
                return false;
            }
        }

        bool TryLoadRecipientPublicKeyFromFile(string keyPath)
        {
            try
            {
                byte[] raw = File.ReadAllBytes(keyPath);
                txtExRecipientPub.Text = Convert.ToBase64String(raw, Base64FormattingOptions.InsertLineBreaks);
                ExStatus("Loaded recipient public key text.");
                return true;
            }
            catch (Exception ex)
            {
                ExStatus($"Unable to load recipient key: {ex.Message}", true);
                return false;
            }
        }

        void WireFileDrop(Control target, Action<string[]> onDropFiles)
        {
            target.AllowDrop = true;
            target.DragEnter += (_, e) =>
            {
                if (e.Data?.GetDataPresent(DataFormats.FileDrop) == true) e.Effect = DragDropEffects.Copy;
            };
            target.DragDrop += (_, e) =>
            {
                if (e.Data?.GetData(DataFormats.FileDrop) is string[] files && files.Length > 0)
                    onDropFiles(files);
            };
        }

        void LoadIdentityDefaults(bool force = false)
        {
            string? pub = FindDefaultKey(DefaultPubKeyNames);
            string? priv = FindDefaultKey(DefaultPrivKeyNames);
            if (force || string.IsNullOrWhiteSpace(txtMyPubPath.Text) || !File.Exists(txtMyPubPath.Text)) txtMyPubPath.Text = pub ?? string.Empty;
            if (force || string.IsNullOrWhiteSpace(txtMyPriv.Text) || !File.Exists(txtMyPriv.Text)) txtMyPriv.Text = priv ?? string.Empty;
            RefreshMyPublicKeyText();
        }

        void ExLoadKeys()
        {
            LoadIdentityDefaults(force: true);
            ExStatus("Loaded default key paths.");
        }

        var btnExLoadKeysSend = new NeonButton { Text = "AUTO-LOAD", Dock = DockStyle.Fill, Margin = new Padding(3, 2, 0, 2) };
        btnExLoadKeysSend.Click += (_, _) => ExLoadKeys();
        var btnExLoadKeysRecv = new NeonButton { Text = "AUTO-LOAD", Dock = DockStyle.Fill, Margin = new Padding(3, 2, 0, 2) };
        btnExLoadKeysRecv.Click += (_, _) => ExLoadKeys();
        var btnExCopyPub = new NeonButton { Text = "COPY PUB KEY", Dock = DockStyle.Fill, Margin = new Padding(3, 2, 0, 2) };
        btnExCopyPub.Click += (_, _) =>
        {
            if (string.IsNullOrWhiteSpace(txtMyPub.Text)) { ExStatus("No public key text to copy.", true); return; }
            Clipboard.SetText(txtMyPub.Text);
            ExStatus("Copied public key text.");
        };
        var btnExCopyPubRecv = new NeonButton
        {
            Text = "COPY TO CLIPBOARD",
            Dock = DockStyle.Fill,
            Margin = new Padding(0),
            MinimumSize = new Size(190, 30),
            Font = Theme.SafeMono(8.5f),
        };
        btnExCopyPubRecv.Click += (_, _) =>
        {
            if (string.IsNullOrWhiteSpace(txtMyPubRecv.Text)) { ExStatus("No public key text to copy.", true); return; }
            Clipboard.SetText(txtMyPubRecv.Text);
            ExStatus("Copied public key text.");
        };
        var btnExExportPub = new NeonButton { Text = "EXPORT PUB", Dock = DockStyle.Fill, Margin = new Padding(3, 2, 0, 2) };
        btnExExportPub.Click += (_, _) =>
        {
            if (string.IsNullOrWhiteSpace(txtMyPubPath.Text) || !File.Exists(txtMyPubPath.Text)) { ExStatus("No valid public key to export.", true); return; }
            using var dlg = new SaveFileDialog
            {
                Title = "Export public key",
                Filter = "Public key|*.bin;*.pem|All files|*.*",
                FileName = Path.GetFileName(txtMyPubPath.Text),
            };
            if (dlg.ShowDialog(this) != DialogResult.OK) return;
            File.Copy(txtMyPubPath.Text, dlg.FileName, true);
            ExStatus($"Exported public key to {dlg.FileName}");
        };
        var btnExFpMine = new NeonButton { Text = "MY FINGERPRINT", Dock = DockStyle.Fill, Margin = new Padding(3, 2, 0, 2) };
        btnExFpMine.Click += async (_, _) => await ShowFingerprintAsync(txtMyPubPath.Text, "My public key");
        var btnExPickPriv = new NeonButton { Text = "BROWSE KEY", Dock = DockStyle.Fill, Margin = new Padding(3, 2, 0, 2) };
        btnExPickPriv.Click += (_, _) => BrowseKeyFile(txtMyPriv);

        var btnExPickRecipient = new NeonButton { Text = "LOAD FILE", Dock = DockStyle.Fill, Margin = new Padding(3, 2, 0, 2) };
        btnExPickRecipient.Click += (_, _) =>
        {
            using var dlg = new OpenFileDialog
            {
                Title = "Select recipient public key",
                Filter = "Key files|*.bin;*.pem|BIN files|*.bin|PEM files|*.pem|All files|*.*",
            };
            if (dlg.ShowDialog(this) != DialogResult.OK) return;
            TryLoadRecipientPublicKeyFromFile(dlg.FileName);
        };
        var btnExFpRecipient = new NeonButton { Text = "FINGERPRINT", Dock = DockStyle.Fill, Margin = new Padding(3, 2, 0, 2) };
        btnExFpRecipient.Click += async (_, _) =>
        {
            if (!TryWriteRecipientKeyTempFile(out var tempPath))
            {
                ExStatus("Paste a valid recipient public key text first.", true);
                return;
            }
            try
            {
                await ShowFingerprintAsync(tempPath, "Recipient public key");
            }
            finally
            {
                try { if (File.Exists(tempPath)) File.Delete(tempPath); } catch { }
            }
        };
        var btnExPickIn = new NeonButton { Text = "BROWSE", Dock = DockStyle.Fill, Margin = new Padding(3, 2, 0, 2) };
        btnExPickIn.Click += (_, _) =>
        {
            using var dlg = new OpenFileDialog { Title = "Select file to send", Filter = "All files|*.*" };
            if (dlg.ShowDialog(this) != DialogResult.OK) return;
            txtExIn.Text = dlg.FileName;
            if (string.IsNullOrWhiteSpace(txtExOut.Text)) txtExOut.Text = Path.ChangeExtension(dlg.FileName, ".obsq");
        };
        var btnExPickOut = new NeonButton { Text = "BROWSE", Dock = DockStyle.Fill, Margin = new Padding(3, 2, 0, 2) };
        btnExPickOut.Click += (_, _) =>
        {
            using var dlg = new SaveFileDialog
            {
                Title = "Save exchange packet",
                Filter = "ObsidianQ package|*.obsq;*.obsqx|All files|*.*",
                DefaultExt = "obsq",
                FileName = string.IsNullOrWhiteSpace(txtExOut.Text) ? "package.obsq" : Path.GetFileName(txtExOut.Text),
            };
            if (dlg.ShowDialog(this) == DialogResult.OK) txtExOut.Text = dlg.FileName;
        };
        var btnExPickPkt = new NeonButton { Text = "BROWSE", Dock = DockStyle.Fill, Margin = new Padding(3, 2, 0, 2) };
        btnExPickPkt.Click += (_, _) =>
        {
            using var dlg = new OpenFileDialog { Title = "Select package", Filter = "ObsidianQ package|*.obsq;*.obsqx|All files|*.*" };
            if (dlg.ShowDialog(this) != DialogResult.OK) return;
            txtExPktIn.Text = dlg.FileName;
            if (string.IsNullOrWhiteSpace(txtExOutDir.Text)) txtExOutDir.Text = Path.GetDirectoryName(dlg.FileName) ?? string.Empty;
        };
        var btnExPickOutDir = new NeonButton { Text = "BROWSE", Dock = DockStyle.Fill, Margin = new Padding(3, 2, 0, 2) };
        btnExPickOutDir.Click += (_, _) =>
        {
            using var dlg = new FolderBrowserDialog
            {
                Description = "Select output folder for decrypted file",
                UseDescriptionForTitle = true,
                ShowNewFolderButton = true,
            };
            if (dlg.ShowDialog(this) == DialogResult.OK) txtExOutDir.Text = dlg.SelectedPath;
        };

        // Exchange drag-and-drop targets (send + receive)
        WireFileDrop(txtExRecipientPub, files =>
        {
            string first = files[0];
            if (Directory.Exists(first)) { ExStatus("Drop a public key file (.bin/.pem), not a folder.", true); return; }
            TryLoadRecipientPublicKeyFromFile(first);
        });
        WireFileDrop(txtExIn, files =>
        {
            string first = files[0];
            if (Directory.Exists(first)) { ExStatus("Drop a file to send, not a folder.", true); return; }
            txtExIn.Text = first;
            if (string.IsNullOrWhiteSpace(txtExOut.Text)) txtExOut.Text = Path.ChangeExtension(first, ".obsq");
            ExStatus("Loaded input file from drop.");
        });
        WireFileDrop(txtExOut, files =>
        {
            string first = files[0];
            if (Directory.Exists(first))
            {
                string baseName = !string.IsNullOrWhiteSpace(txtExIn.Text)
                    ? Path.GetFileNameWithoutExtension(txtExIn.Text)
                    : "packet";
                txtExOut.Text = Path.Combine(first, baseName + ".obsq");
            }
            else
            {
                txtExOut.Text = (first.EndsWith(".obsq", StringComparison.OrdinalIgnoreCase) || first.EndsWith(".obsqx", StringComparison.OrdinalIgnoreCase))
                    ? first
                    : Path.ChangeExtension(first, ".obsq");
            }
            ExStatus("Loaded output packet path from drop.");
        });
        WireFileDrop(txtMyPriv, files =>
        {
            string first = files[0];
            if (Directory.Exists(first)) { ExStatus("Drop a private key file (.bin/.pem), not a folder.", true); return; }
            txtMyPriv.Text = first;
            ExStatus("Loaded private key from drop.");
        });
        WireFileDrop(txtExPktIn, files =>
        {
            string first = files[0];
            if (Directory.Exists(first)) { ExStatus("Drop a package file (.obsq), not a folder.", true); return; }
            txtExPktIn.Text = first;
            if (string.IsNullOrWhiteSpace(txtExOutDir.Text)) txtExOutDir.Text = Path.GetDirectoryName(first) ?? string.Empty;
            ExStatus("Loaded incoming packet from drop.");
        });
        WireFileDrop(txtExOutDir, files =>
        {
            string first = files[0];
            txtExOutDir.Text = Directory.Exists(first) ? first : (Path.GetDirectoryName(first) ?? string.Empty);
            ExStatus("Loaded output folder from drop.");
        });
        WireFileDrop(lstExItems, files =>
        {
            foreach (var f in files)
            {
                if (File.Exists(f) || Directory.Exists(f))
                    lstExItems.Items.Add(f);
            }
            if (lstExItems.Items.Count > 0 && string.IsNullOrWhiteSpace(txtExOut.Text))
            {
                string first = lstExItems.Items[0].ToString() ?? "package";
                string stem = Directory.Exists(first) ? Path.GetFileName(first) : Path.GetFileNameWithoutExtension(first);
                txtExOut.Text = Path.Combine(Path.GetDirectoryName(first) ?? Environment.CurrentDirectory, $"{stem}_package.obsq");
            }
            ExStatus("Added dropped items.");
        });

        void AddDirectoryTreeToZip(ZipArchive archive, string folderPath, string prefix)
        {
            foreach (string file in Directory.GetFiles(folderPath))
            {
                string entryName = string.IsNullOrEmpty(prefix)
                    ? Path.GetFileName(file)
                    : $"{prefix}/{Path.GetFileName(file)}";
                archive.CreateEntryFromFile(file, entryName, CompressionLevel.Optimal);
            }
            foreach (string dir in Directory.GetDirectories(folderPath))
            {
                string nextPrefix = string.IsNullOrEmpty(prefix)
                    ? Path.GetFileName(dir)
                    : $"{prefix}/{Path.GetFileName(dir)}";
                AddDirectoryTreeToZip(archive, dir, nextPrefix);
            }
        }

        NeonButton btnExAddFile = new() { Text = "ADD FILE", Dock = DockStyle.Fill, Margin = new Padding(0, 2, 3, 2) };
        NeonButton btnExAddFolder = new() { Text = "ADD FOLDER", Dock = DockStyle.Fill, Margin = new Padding(3, 2, 3, 2) };
        NeonButton btnExRemoveItem = new() { Text = "REMOVE", Dock = DockStyle.Fill, Margin = new Padding(3, 2, 0, 2) };
        var btnExPrimary = new NeonButton { Text = "SEND PACKET", Dock = DockStyle.Fill, Margin = new Padding(0, 2, 0, 2), Font = Theme.SafeMono(10f) };

        var sendPanel = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 9, BackColor = Theme.Bg, Margin = new Padding(0), };
        sendPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 20));  // recipient label
        sendPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 34));  // recipient combo
        sendPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 20));  // files label
        sendPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 36));  // add/remove row
        sendPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 96));  // file list
        sendPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 20));  // recipient key label
        sendPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 64));  // recipient key text
        sendPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 20));  // output label
        sendPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 38));  // output path row
        var lblRecipient = MakeLabel("RECIPIENT", 8f, bold: true); lblRecipient.Dock = DockStyle.Fill; lblRecipient.TextAlign = ContentAlignment.MiddleLeft;
        var lblFiles = MakeLabel("FILES TO ENCRYPT", 8f, bold: true); lblFiles.Dock = DockStyle.Fill; lblFiles.TextAlign = ContentAlignment.MiddleLeft;
        var lblRecipientKey = MakeLabel("RECIPIENT KEY (AUTO-FILLED OR PASTE MANUALLY)", 8f); lblRecipientKey.Dock = DockStyle.Fill; lblRecipientKey.TextAlign = ContentAlignment.MiddleLeft;
        var lblSendOutput = MakeLabel("OUTPUT PACKAGE (.obsq)", 8f); lblSendOutput.Dock = DockStyle.Fill; lblSendOutput.TextAlign = ContentAlignment.MiddleLeft;
        var recipientRow = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, RowCount = 1, BackColor = Theme.Bg };
        recipientRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        recipientRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 92));
        recipientRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 120));
        recipientRow.Controls.Add(cmbExRecipient, 0, 0);
        recipientRow.Controls.Add(btnExPickRecipient, 1, 0);
        recipientRow.Controls.Add(btnExFpRecipient, 2, 0);
        var filesButtons = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, RowCount = 1, BackColor = Theme.Bg };
        filesButtons.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.333f));
        filesButtons.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.333f));
        filesButtons.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.333f));
        filesButtons.Controls.Add(btnExAddFile, 0, 0);
        filesButtons.Controls.Add(btnExAddFolder, 1, 0);
        filesButtons.Controls.Add(btnExRemoveItem, 2, 0);
        var outputRow = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, RowCount = 1, BackColor = Theme.Bg };
        outputRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        outputRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 92));
        outputRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 140));
        outputRow.Controls.Add(txtExOut, 0, 0); outputRow.Controls.Add(btnExPickOut, 1, 0); outputRow.Controls.Add(cmbExSuite, 2, 0);
        sendPanel.Controls.Add(lblRecipient, 0, 0);
        sendPanel.Controls.Add(recipientRow, 0, 1);
        sendPanel.Controls.Add(lblFiles, 0, 2);
        sendPanel.Controls.Add(filesButtons, 0, 3);
        sendPanel.Controls.Add(lstExItems, 0, 4);
        sendPanel.Controls.Add(lblRecipientKey, 0, 5);
        sendPanel.Controls.Add(txtExRecipientPub, 0, 6);
        sendPanel.Controls.Add(lblSendOutput, 0, 7);
        sendPanel.Controls.Add(outputRow, 0, 8);

        var recvPanel = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 7, BackColor = Theme.Bg, Margin = new Padding(0), Visible = false, };
        recvPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 20));
        recvPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 38));
        recvPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 20));
        recvPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 58));
        recvPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 20));
        recvPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 38));
        recvPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        var lblRecvPacket = MakeLabel("ENCRYPTED PACKAGE (.obsq)", 8f); lblRecvPacket.Dock = DockStyle.Fill; lblRecvPacket.TextAlign = ContentAlignment.MiddleLeft;
        var lblSenderInfo = MakeLabel("SENDER INFORMATION", 8f); lblSenderInfo.Dock = DockStyle.Fill; lblSenderInfo.TextAlign = ContentAlignment.MiddleLeft;
        var lblRecvOut = MakeLabel("DECRYPTION OUTPUT FOLDER", 8f); lblRecvOut.Dock = DockStyle.Fill; lblRecvOut.TextAlign = ContentAlignment.MiddleLeft;
        var r1 = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, BackColor = Theme.Bg };
        r1.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        r1.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 92));
        r1.Controls.Add(txtExPktIn, 0, 0); r1.Controls.Add(btnExPickPkt, 1, 0);
        var lblSenderMeta = MakeLabel("Contact: Unknown   |   Fingerprint: Unknown   |   Status: Unknown", 8f);
        lblSenderMeta.Dock = DockStyle.Fill;
        lblSenderMeta.TextAlign = ContentAlignment.MiddleLeft;
        var r2 = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, BackColor = Theme.Bg };
        r2.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        r2.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 92));
        r2.Controls.Add(txtExOutDir, 0, 0); r2.Controls.Add(btnExPickOutDir, 1, 0);
        recvPanel.Controls.Add(lblRecvPacket, 0, 0);
        recvPanel.Controls.Add(r1, 0, 1);
        recvPanel.Controls.Add(lblSenderInfo, 0, 2);
        recvPanel.Controls.Add(lblSenderMeta, 0, 3);
        recvPanel.Controls.Add(lblRecvOut, 0, 4);
        recvPanel.Controls.Add(r2, 0, 5);
        recvPanel.Controls.Add(new Panel { Dock = DockStyle.Fill, BackColor = Theme.Bg }, 0, 6);

        void UpdateExchangeModeUi()
        {
            bool sendMode = exModeToggle.Selected == SegmentedToggle.Segment.Password;
            sendPanel.Visible = sendMode;
            recvPanel.Visible = !sendMode;
            if (sendIdentityPanel != null) sendIdentityPanel.Visible = false;
            if (recvIdentityPanel != null) recvIdentityPanel.Visible = !sendMode;
            if (outerExchangeRef != null)
            {
                outerExchangeRef.RowStyles[1].Height = sendMode ? 8 : 240;
                outerExchangeRef.RowStyles[2].Height = sendMode ? 360 : 220;
            }
            btnExPrimary.Text = sendMode ? "ENCRYPT & PACKAGE FILES" : "INSPECT PACKAGE";
            lblHint.Text = sendMode
                ? "1) Choose recipient. 2) Add files/folders. 3) Pick output package and encrypt."
                : "1) Select encrypted package. 2) Choose output folder. 3) Decrypt.";
        }
        exModeToggle.SelectionChanged += (_, _) => UpdateExchangeModeUi();

        btnExPrimary.Click += async (_, _) =>
        {
            if (!File.Exists(ExePath)) { ExStatus("obsidianq.exe not found.", true); return; }
            bool sendMode = exModeToggle.Selected == SegmentedToggle.Segment.Password;
            btnExPrimary.Enabled = false;
            try
            {
                if (sendMode)
                {
                    if (!TryWriteRecipientKeyTempFile(out var recipientTempPath)) { ExStatus("Paste a valid recipient public key text.", true); return; }
                    var sendItems = lstExItems.Items.Cast<object>().Select(o => o?.ToString() ?? string.Empty).Where(s => !string.IsNullOrWhiteSpace(s)).ToList();
                    if (sendItems.Count == 0) { ExStatus("Add at least one file or folder to send.", true); return; }
                    if (string.IsNullOrWhiteSpace(txtExOut.Text)) { ExStatus("Select output packet path.", true); return; }
                    string suite = cmbExSuite.SelectedIndex == 1 ? "aesgcm" : "xchacha20";
                    long inputBytes = 0;
                    string sendInputPath = string.Empty;
                    string? tempBundlePath = null;
                    try
                    {
                        if (sendItems.Count == 1 && File.Exists(sendItems[0]))
                        {
                            sendInputPath = sendItems[0];
                            try { inputBytes = new FileInfo(sendInputPath).Length; } catch { }
                        }
                        else
                        {
                            tempBundlePath = Path.Combine(Path.GetTempPath(), $"obsidianq_send_bundle_{Guid.NewGuid():N}.zip");
                            using (var zip = ZipFile.Open(tempBundlePath, ZipArchiveMode.Create))
                            {
                                foreach (string item in sendItems)
                                {
                                    if (File.Exists(item))
                                    {
                                        string entryName = Path.GetFileName(item);
                                        zip.CreateEntryFromFile(item, entryName, CompressionLevel.Optimal);
                                    }
                                    else if (Directory.Exists(item))
                                    {
                                        string root = Path.GetFileName(item.TrimEnd('\\', '/'));
                                        AddDirectoryTreeToZip(zip, item, root);
                                    }
                                }
                            }
                            sendInputPath = tempBundlePath;
                            try { inputBytes = new FileInfo(sendInputPath).Length; } catch { }
                            ExLog($"[INFO] Created package staging archive: {sendInputPath}", Theme.AccentDim);
                        }

                        var sw = Stopwatch.StartNew();
                        string args = $"exchange send --in \"{sendInputPath}\" --out \"{txtExOut.Text}\" --pubkey \"{recipientTempPath}\" --suite {suite}";
                        if (!string.IsNullOrWhiteSpace(txtMyPubPath.Text) && File.Exists(txtMyPubPath.Text))
                            args += $" --sender-pubkey \"{txtMyPubPath.Text}\"";
                        ExLog($"[CMD] obsidianq {args}", Theme.TextDim);
                        var (code, stdout, stderr) = await RunWithBusyDialogAsync(
                            "File Send / Receive",
                            "Encrypting and packaging files...",
                            () => RunExchangeCliAsync(args));
                        sw.Stop();
                        if (!string.IsNullOrWhiteSpace(stdout)) ExLog(stdout.TrimEnd(), Theme.Accent);
                        if (!string.IsNullOrWhiteSpace(stderr)) ExLog(stderr.TrimEnd(), Theme.Error);
                        if (code == 0)
                        {
                            double sec = Math.Max(0.001, sw.Elapsed.TotalSeconds);
                            double mbps = inputBytes > 0 ? (inputBytes / 1_048_576.0) / sec : 0.0;
                            ExStatus($"Encrypted package created: {txtExOut.Text}");
                            if (inputBytes > 0) ExLog($"[THROUGHPUT] Send avg {mbps:0.##} MB/s ({FormatBytes(inputBytes)} in {sec:0.##}s)", Theme.AccentDim);
                            ShowSendCompleteDialog(txtExOut.Text);
                        }
                        else ExStatus($"Send failed (exit {code}).", true);
                    }
                    finally
                    {
                        if (!string.IsNullOrWhiteSpace(tempBundlePath))
                        {
                            try { if (File.Exists(tempBundlePath)) File.Delete(tempBundlePath); } catch { }
                        }
                        try { if (File.Exists(recipientTempPath)) File.Delete(recipientTempPath); } catch { }
                    }
                }
                else
                {
                    if (string.IsNullOrWhiteSpace(txtMyPriv.Text) || !File.Exists(txtMyPriv.Text)) { ExStatus("No private key loaded. Use AUTO-LOAD or generate in Settings.", true); return; }
                    if (string.IsNullOrWhiteSpace(txtExPktIn.Text) || !File.Exists(txtExPktIn.Text)) { ExStatus("Select a valid package (.obsq/.obsqx).", true); return; }
                    if (string.IsNullOrWhiteSpace(txtExOutDir.Text)) { ExStatus("Select output directory.", true); return; }
                    string senderFp = "Unknown";
                    string matchedContact = "Unknown";
                    string trustStatus = "Unknown";
                    var packageContents = new List<string>();
                    var (icode, istdout, istderr) = await RunExchangeCliAsync($"exchange inspect --in \"{txtExPktIn.Text}\"");
                    if (!string.IsNullOrWhiteSpace(istderr)) ExLog(istderr.TrimEnd(), Theme.Error);
                    if (icode == 0)
                    {
                        foreach (string line in (istdout ?? string.Empty).Split('\n'))
                        {
                            int eq = line.IndexOf('=');
                            if (eq <= 0) continue;
                            string k = line[..eq].Trim();
                            string v = line[(eq + 1)..].Trim();
                            if (k.Equals("filename", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(v))
                                packageContents.Add(v);
                            else if (k.Equals("sender_fingerprint", StringComparison.OrdinalIgnoreCase))
                                senderFp = string.IsNullOrWhiteSpace(v) ? "Unknown" : v;
                        }
                    }
                    if (!string.Equals(senderFp, "Unknown", StringComparison.OrdinalIgnoreCase) && File.Exists(exRecipientsPath))
                    {
                        foreach (string line in File.ReadAllLines(exRecipientsPath))
                        {
                            if (string.IsNullOrWhiteSpace(line)) continue;
                            string[] parts = line.Split('\t');
                            if (parts.Length < 2) continue;
                            string name = parts[0].Trim();
                            string fp = parts[1].Trim();
                            if (string.Equals(fp, senderFp, StringComparison.Ordinal))
                            {
                                matchedContact = name;
                                trustStatus = "Trusted Key";
                                break;
                            }
                        }
                        if (trustStatus == "Unknown") trustStatus = "Unknown Key";
                    }
                    else if (string.Equals(senderFp, "Unknown", StringComparison.OrdinalIgnoreCase))
                    {
                        trustStatus = "Sender key not included";
                    }
                    if (packageContents.Count == 0) packageContents.Add("Contents preview unavailable before decrypt.");

                    string outDir = txtExOutDir.Text;
                    if (!ShowReceiveInspectDialog(txtExPktIn.Text, ref outDir, senderFp, matchedContact, trustStatus, packageContents))
                    {
                        ExStatus("Inspection canceled.");
                        return;
                    }
                    txtExOutDir.Text = outDir;
                    long packetBytes = 0;
                    try { packetBytes = new FileInfo(txtExPktIn.Text).Length; } catch { }
                    string args = $"exchange recv --in \"{txtExPktIn.Text}\" --privkey \"{txtMyPriv.Text}\" --out-dir \"{txtExOutDir.Text}\"";
                    ExLog($"[CMD] obsidianq {args}", Theme.TextDim);
                    var sw = Stopwatch.StartNew();
                    var (code, stdout, stderr) = await RunWithBusyDialogAsync(
                        "File Send / Receive",
                        "Decrypting package...",
                        () => RunExchangeCliAsync(args));
                    sw.Stop();
                    if (!string.IsNullOrWhiteSpace(stdout)) ExLog(stdout.TrimEnd(), Theme.Accent);
                    if (!string.IsNullOrWhiteSpace(stderr)) ExLog(stderr.TrimEnd(), Theme.Error);
                    if (code == 0)
                    {
                        double sec = Math.Max(0.001, sw.Elapsed.TotalSeconds);
                        double mbps = packetBytes > 0 ? (packetBytes / 1_048_576.0) / sec : 0.0;
                        ExStatus($"Packet decrypted into: {txtExOutDir.Text}");
                        if (packetBytes > 0) ExLog($"[THROUGHPUT] Receive avg {mbps:0.##} MB/s ({FormatBytes(packetBytes)} in {sec:0.##}s)", Theme.AccentDim);
                        ShowDecryptCompleteDialog(txtExOutDir.Text);
                    }
                    else ExStatus($"Receive failed (exit {code}).", true);
                }
            }
            finally
            {
                btnExPrimary.Enabled = true;
            }
        };

        var outerExchange = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 6, Padding = new Padding(16), BackColor = Theme.Bg,
        };
        outerExchangeRef = outerExchange;
        outerExchange.RowStyles.Add(new RowStyle(SizeType.Absolute, 56));
        outerExchange.RowStyles.Add(new RowStyle(SizeType.Absolute, 190));
        outerExchange.RowStyles.Add(new RowStyle(SizeType.Absolute, 260));
        outerExchange.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));
        outerExchange.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        outerExchange.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));

        var modePanel = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 2, BackColor = Theme.Bg, Margin = new Padding(0, 0, 0, 8) };
        modePanel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 120));
        modePanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        modePanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 26));
        modePanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 26));
        var lblMode = MakeLabel("WORKFLOW", 8.5f, bold: true); lblMode.Dock = DockStyle.Fill; lblMode.TextAlign = ContentAlignment.MiddleLeft;
        lblHint = MakeLabel("Send mode packages files for a selected recipient. Receive mode decrypts a package into your chosen folder.", 8f); lblHint.Dock = DockStyle.Fill; lblHint.TextAlign = ContentAlignment.MiddleLeft;
        modePanel.Controls.Add(lblMode, 0, 0); modePanel.Controls.Add(exModeToggle, 1, 0);
        modePanel.Controls.Add(new Panel { Dock = DockStyle.Fill, BackColor = Theme.Bg }, 0, 1); modePanel.Controls.Add(lblHint, 1, 1);
        outerExchange.Controls.Add(modePanel, 0, 0);

        var identityHost = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Bg };

        sendIdentityPanel = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3, BackColor = Theme.Bg, Margin = new Padding(0, 0, 0, 8) };
        sendIdentityPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 20));
        sendIdentityPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 38));
        sendIdentityPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        var lblSendIdentity = MakeLabel("YOUR PUBLIC KEY (SHARE THIS TEXT)", 8f, bold: true); lblSendIdentity.Dock = DockStyle.Fill; lblSendIdentity.TextAlign = ContentAlignment.MiddleLeft;
        sendIdentityPanel.Controls.Add(lblSendIdentity, 0, 0);
        var sendButtons = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 4, RowCount = 1, BackColor = Theme.Bg };
        sendButtons.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 34));
        sendButtons.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33));
        sendButtons.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33));
        sendButtons.Controls.Add(btnExLoadKeysSend, 0, 0);
        sendButtons.Controls.Add(btnExCopyPub, 1, 0);
        sendButtons.Controls.Add(btnExFpMine, 2, 0);
        sendIdentityPanel.Controls.Add(sendButtons, 0, 1);
        sendIdentityPanel.Controls.Add(txtMyPub, 0, 2);

        recvIdentityPanel = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 6, BackColor = Theme.Bg, Margin = new Padding(0, 0, 0, 8), Visible = false };
        recvIdentityPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 20));
        recvIdentityPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 38));
        recvIdentityPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 32));
        recvIdentityPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 20));
        recvIdentityPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 120));
        recvIdentityPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 38));
        var lblRecvIdentity = MakeLabel("YOUR PRIVATE KEY", 8f, bold: true); lblRecvIdentity.Dock = DockStyle.Fill; lblRecvIdentity.TextAlign = ContentAlignment.MiddleLeft;
        var lblRecvShare = MakeLabel("SHARE THIS PUBLIC KEY WITH SENDER", 8f, bold: true); lblRecvShare.Dock = DockStyle.Fill; lblRecvShare.TextAlign = ContentAlignment.MiddleLeft;
        recvIdentityPanel.Controls.Add(lblRecvIdentity, 0, 0);
        var recvButtons = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, RowCount = 1, BackColor = Theme.Bg };
        recvButtons.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        recvButtons.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        recvButtons.Controls.Add(btnExLoadKeysRecv, 0, 0);
        recvButtons.Controls.Add(btnExPickPriv, 1, 0);
        recvIdentityPanel.Controls.Add(recvButtons, 0, 1);
        recvIdentityPanel.Controls.Add(txtMyPriv, 0, 2);
        recvIdentityPanel.Controls.Add(lblRecvShare, 0, 3);
        recvIdentityPanel.Controls.Add(txtMyPubRecv, 0, 4);
        var recvShareButtons = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, BackColor = Theme.Bg };
        recvShareButtons.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        recvShareButtons.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 210));
        recvShareButtons.Controls.Add(new Panel { Dock = DockStyle.Fill, BackColor = Theme.Bg }, 0, 0);
        btnExCopyPubRecv.Margin = new Padding(0, 2, 0, 2);
        recvShareButtons.Controls.Add(btnExCopyPubRecv, 1, 0);
        recvIdentityPanel.Controls.Add(recvShareButtons, 0, 5);

        identityHost.Controls.Add(sendIdentityPanel);
        identityHost.Controls.Add(recvIdentityPanel);
        outerExchange.Controls.Add(identityHost, 0, 1);

        var flowContainer = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Bg };
        flowContainer.Controls.Add(sendPanel);
        flowContainer.Controls.Add(recvPanel);
        outerExchange.Controls.Add(flowContainer, 0, 2);
        outerExchange.Controls.Add(btnExPrimary, 0, 3);

        var exLogContainer = new Panel { Dock = DockStyle.Fill, BackColor = Theme.LogBg };
        exLogContainer.Controls.Add(rtbExLog);
        exLogContainer.Paint += (_, pe) =>
        {
            using var pen = new Pen(Theme.Border, 1f);
            pe.Graphics.DrawRectangle(pen, 0, 0, exLogContainer.Width - 1, exLogContainer.Height - 1);
        };
        outerExchange.Controls.Add(exLogContainer, 0, 4);
        outerExchange.Controls.Add(lblExStatus, 0, 5);

        LoadIdentityDefaults(force: true);
        UpdateExchangeModeUi();
        // ==================================================================
        // SECURE CONTACTS TAB - simplified share/import contacts flow
        // ==================================================================
        string keyExchange2StorePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "ObsidianQ",
            "trusted_recipients_v1.tsv");
        string kx2IdentityProfilePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "ObsidianQ",
            "identity_profile_v1.tsv");
        string kx2MyPubRaw = string.Empty;
        string kx2MyFingerprintRaw = string.Empty;

        var txtKx2MyPub = MakeTextBox();
        txtKx2MyPub.ReadOnly = true;
        txtKx2MyPub.Multiline = true;
        txtKx2MyPub.ScrollBars = ScrollBars.Both;
        txtKx2MyPub.WordWrap = false;
        txtKx2MyPub.PlaceholderText = "Your public identity key";

        var rtbKx2Log = new RichTextBox
        {
            Dock = DockStyle.Fill,
            ReadOnly = true,
            WordWrap = true,
            BackColor = Theme.LogBg,
            ForeColor = Theme.Accent,
            BorderStyle = BorderStyle.None,
            ScrollBars = RichTextBoxScrollBars.Vertical,
            Font = Theme.SafeMono(8.5f),
        };
        rtbKx2Log.HandleCreated += (_, _) => SetWindowTheme(rtbKx2Log.Handle, "DarkMode_Explorer", null);

        var lblKx2Status = MakeLabel("Ready", 8.5f);
        lblKx2Status.Dock = DockStyle.Fill;
        lblKx2Status.TextAlign = ContentAlignment.MiddleLeft;

        var lblKx2MyFingerprint = MakeLabel("-", 10f, bold: true);
        lblKx2MyFingerprint.Dock = DockStyle.Fill;
        lblKx2MyFingerprint.TextAlign = ContentAlignment.MiddleLeft;
        lblKx2MyFingerprint.ForeColor = Theme.Accent;

        string defaultDomain = Environment.GetEnvironmentVariable("USERDNSDOMAIN")?.Trim() ?? "local";
        if (string.IsNullOrWhiteSpace(defaultDomain)) defaultDomain = "local";
        var txtKx2IdentityName = MakeTextBox();
        txtKx2IdentityName.PlaceholderText = "Name";
        txtKx2IdentityName.Text = Environment.UserName;
        var txtKx2IdentityEmail = MakeTextBox();
        txtKx2IdentityEmail.PlaceholderText = "Email";
        txtKx2IdentityEmail.Text = $"{Environment.UserName}@{defaultDomain.ToLowerInvariant()}";
        var txtKx2IdentityDevice = MakeTextBox();
        txtKx2IdentityDevice.PlaceholderText = "Device";
        txtKx2IdentityDevice.Text = Environment.MachineName;

        var lblKx2ContactNameVal = MakeLabel("-", 8.5f);
        lblKx2ContactNameVal.Dock = DockStyle.Fill;
        lblKx2ContactNameVal.TextAlign = ContentAlignment.MiddleLeft;

        var lblKx2ContactFpVal = MakeLabel("-", 8.5f);
        lblKx2ContactFpVal.Dock = DockStyle.Fill;
        lblKx2ContactFpVal.TextAlign = ContentAlignment.MiddleLeft;

        var lblKx2ContactDateVal = MakeLabel("-", 8.5f);
        lblKx2ContactDateVal.Dock = DockStyle.Fill;
        lblKx2ContactDateVal.TextAlign = ContentAlignment.MiddleLeft;

        var lblKx2ContactEmailVal = MakeLabel("-", 8.5f);
        lblKx2ContactEmailVal.Dock = DockStyle.Fill;
        lblKx2ContactEmailVal.TextAlign = ContentAlignment.MiddleLeft;

        var lblKx2ContactDeviceVal = MakeLabel("-", 8.5f);
        lblKx2ContactDeviceVal.Dock = DockStyle.Fill;
        lblKx2ContactDeviceVal.TextAlign = ContentAlignment.MiddleLeft;

        var lblKx2ContactCreatedVal = MakeLabel("-", 8.5f);
        lblKx2ContactCreatedVal.Dock = DockStyle.Fill;
        lblKx2ContactCreatedVal.TextAlign = ContentAlignment.MiddleLeft;

        var lblKx2ContactAlgoVal = MakeLabel("-", 8.5f);
        lblKx2ContactAlgoVal.Dock = DockStyle.Fill;
        lblKx2ContactAlgoVal.TextAlign = ContentAlignment.MiddleLeft;

        var lblKx2ContactTypeVal = MakeLabel("-", 8.5f);
        lblKx2ContactTypeVal.Dock = DockStyle.Fill;
        lblKx2ContactTypeVal.TextAlign = ContentAlignment.MiddleLeft;

        var lvKx2Recipients = new ListView
        {
            Dock = DockStyle.Fill,
            FullRowSelect = true,
            MultiSelect = false,
            HideSelection = false,
            View = View.Details,
            HeaderStyle = ColumnHeaderStyle.Nonclickable,
            BackColor = Theme.Surface,
            ForeColor = Theme.TextMain,
            BorderStyle = BorderStyle.FixedSingle,
            Font = Theme.SafeMono(8.5f),
        };
        lvKx2Recipients.OwnerDraw = true;
        lvKx2Recipients.DrawColumnHeader += (_, e) =>
        {
            using var back = new SolidBrush(Theme.Surface);
            using var border = new Pen(Theme.Border, 1f);
            using var text = new SolidBrush(Theme.Accent);
            e.Graphics.FillRectangle(back, e.Bounds);
            e.Graphics.DrawRectangle(border, e.Bounds.X, e.Bounds.Y, e.Bounds.Width - 1, e.Bounds.Height - 1);
            var sf = new StringFormat
            {
                LineAlignment = StringAlignment.Center,
                Alignment = StringAlignment.Near,
                FormatFlags = StringFormatFlags.NoWrap,
                Trimming = StringTrimming.EllipsisCharacter,
            };
            var textRect = new RectangleF(e.Bounds.X + 6, e.Bounds.Y, e.Bounds.Width - 8, e.Bounds.Height);
            e.Graphics.DrawString(e.Header?.Text ?? string.Empty, Theme.SafeMono(8.5f), text, textRect, sf);
        };
        lvKx2Recipients.DrawItem += (_, e) =>
        {
            bool selected = (e.State & ListViewItemStates.Selected) != 0;
            Color bg = selected ? Color.FromArgb(30, Theme.Accent) : Theme.Surface;
            using var back = new SolidBrush(bg);
            var fullRow = new Rectangle(0, e.Bounds.Y, lvKx2Recipients.ClientSize.Width, e.Bounds.Height);
            e.Graphics.FillRectangle(back, fullRow);
        };
        lvKx2Recipients.DrawSubItem += (_, e) =>
        {
            bool selected = (e.ItemState & ListViewItemStates.Selected) != 0;
            Color bg = selected ? Color.FromArgb(30, Theme.Accent) : Theme.Surface;
            Color fg = selected ? Theme.Accent : Theme.TextMain;
            using var back = new SolidBrush(bg);
            using var pen = new Pen(Theme.Border, 1f);
            using var text = new SolidBrush(fg);
            e.Graphics.FillRectangle(back, e.Bounds);
            e.Graphics.DrawRectangle(pen, e.Bounds.X, e.Bounds.Y, e.Bounds.Width - 1, e.Bounds.Height - 1);
            var sf = new StringFormat
            {
                LineAlignment = StringAlignment.Center,
                Alignment = StringAlignment.Near,
                FormatFlags = StringFormatFlags.NoWrap,
                Trimming = StringTrimming.EllipsisCharacter,
            };
            var textRect = new RectangleF(e.Bounds.X + 6, e.Bounds.Y, e.Bounds.Width - 8, e.Bounds.Height);
            string display = e.SubItem?.Text ?? string.Empty;
            if (e.ColumnIndex == 1)
                display = Kx2FormatFingerprint(display);
            if (e.ColumnIndex == 3)
                display = Kx2FormatDateDisplay(display);
            e.Graphics.DrawString(display, Theme.SafeMono(8.5f), text, textRect, sf);
        };
        lvKx2Recipients.Columns.Add("Contact", 90, HorizontalAlignment.Left);
        lvKx2Recipients.Columns.Add("Fingerprint", 120, HorizontalAlignment.Left);
        lvKx2Recipients.Columns.Add("Added", 110, HorizontalAlignment.Left);
        lvKx2Recipients.Columns.Add("Key Type", 0, HorizontalAlignment.Left);
        lvKx2Recipients.Columns.Add("Email", 0, HorizontalAlignment.Left);
        lvKx2Recipients.Columns.Add("Device", 0, HorizontalAlignment.Left);
        lvKx2Recipients.Columns.Add("IdentityCreated", 0, HorizontalAlignment.Left);
        lvKx2Recipients.Columns.Add("IdentityAlgorithm", 0, HorizontalAlignment.Left);
        lvKx2Recipients.Paint += (_, e) =>
        {
            int used = 0;
            for (int i = 0; i < Math.Min(3, lvKx2Recipients.Columns.Count); i++)
                used += Math.Max(0, lvKx2Recipients.Columns[i].Width);
            if (used < lvKx2Recipients.ClientSize.Width)
            {
                var strip = new Rectangle(used, 0, lvKx2Recipients.ClientSize.Width - used, lvKx2Recipients.ClientSize.Height);
                using var bg = new SolidBrush(Theme.Surface);
                e.Graphics.FillRectangle(bg, strip);
            }
        };
        lvKx2Recipients.HandleCreated += (_, _) => SetWindowTheme(lvKx2Recipients.Handle, "DarkMode_Explorer", null);

        void Kx2AdjustRecipientColumns()
        {
            if (lvKx2Recipients.Columns.Count < 8) return;
            int available = Math.Max(0, lvKx2Recipients.ClientSize.Width);
            if (available <= 0) return;
            int minName = 96, minFp = 130, minDate = 96;
            int nameW = Math.Max(minName, (int)(available * 0.24));
            int fpW = Math.Max(minFp, (int)(available * 0.52));
            int dateW = Math.Max(minDate, available - nameW - fpW);

            int overflow = (nameW + fpW + dateW) - available;
            if (overflow > 0)
            {
                int cut = Math.Min(overflow, Math.Max(0, fpW - minFp));
                fpW -= cut; overflow -= cut;
            }
            if (overflow > 0)
            {
                int cut = Math.Min(overflow, Math.Max(0, nameW - minName));
                nameW -= cut; overflow -= cut;
            }
            if (overflow > 0)
            {
                int cut = Math.Min(overflow, Math.Max(0, dateW - minDate));
                dateW -= cut; overflow -= cut;
            }
            if (overflow > 0)
            {
                int baseW = Math.Max(64, available / 3);
                nameW = baseW;
                fpW = baseW;
                dateW = Math.Max(64, available - nameW - fpW);
            }
            // Hard-fit to full client width to avoid any unpainted sliver at right edge.
            dateW = Math.Max(0, available - nameW - fpW);

            lvKx2Recipients.Columns[0].Width = nameW;
            lvKx2Recipients.Columns[1].Width = fpW;
            lvKx2Recipients.Columns[2].Width = dateW;
            lvKx2Recipients.Columns[3].Width = 0;
            lvKx2Recipients.Columns[4].Width = 0;
            lvKx2Recipients.Columns[5].Width = 0;
            lvKx2Recipients.Columns[6].Width = 0;
            lvKx2Recipients.Columns[7].Width = 0;
        }
        lvKx2Recipients.Resize += (_, _) => Kx2AdjustRecipientColumns();

        void Kx2Log(string text, Color color)
        {
            rtbKx2Log.SelectionStart = rtbKx2Log.TextLength;
            rtbKx2Log.SelectionLength = 0;
            rtbKx2Log.SelectionColor = color;
            rtbKx2Log.AppendText(text + Environment.NewLine);
            rtbKx2Log.ScrollToCaret();
        }

        static string Kx2FormatFingerprint(string full)
        {
            if (string.IsNullOrWhiteSpace(full)) return "-";
            string compact = new string(full.Trim().Where(char.IsLetterOrDigit).ToArray()).ToUpperInvariant();
            if (compact.Length < 8) return full.Trim();
            var sb = new StringBuilder(compact.Length + (compact.Length / 4));
            for (int i = 0; i < compact.Length; i += 4)
            {
                if (i > 0) sb.Append(' ');
                sb.Append(compact, i, Math.Min(4, compact.Length - i));
            }
            return sb.ToString();
        }

        static string Kx2FormatDateDisplay(string dateRaw)
        {
            if (DateTime.TryParse(dateRaw, out var dt))
                return dt.ToString("MMM d yyyy");
            return dateRaw;
        }

        static string Kx2FormatBase64ForDisplay(byte[] raw, int lineLen = 64)
        {
            string b64 = Convert.ToBase64String(raw);
            if (lineLen <= 0 || b64.Length <= lineLen) return b64;
            var sb = new StringBuilder(b64.Length + (b64.Length / lineLen) + 8);
            for (int i = 0; i < b64.Length; i += lineLen)
            {
                int take = Math.Min(lineLen, b64.Length - i);
                sb.Append(b64, i, take);
                if (i + take < b64.Length) sb.AppendLine();
            }
            return sb.ToString();
        }

        static string Kx2NormalizeFingerprint(string value)
        {
            if (string.IsNullOrWhiteSpace(value)) return string.Empty;
            return new string(value.Where(char.IsLetterOrDigit).ToArray()).ToUpperInvariant();
        }

        static string Kx2BuildPublicIdentityDocument(
            string keyBase64,
            string fingerprint,
            string? name = null,
            string? email = null,
            string? device = null,
            string? created = null)
        {
            var sb = new StringBuilder();
            sb.AppendLine("-----BEGIN OBSIDIANQ PUBLIC IDENTITY-----");
            sb.AppendLine("version:1");
            if (!string.IsNullOrWhiteSpace(name)) sb.AppendLine($"name:{name.Trim()}");
            if (!string.IsNullOrWhiteSpace(email)) sb.AppendLine($"email:{email.Trim()}");
            if (!string.IsNullOrWhiteSpace(device)) sb.AppendLine($"device:{device.Trim()}");
            if (!string.IsNullOrWhiteSpace(created)) sb.AppendLine($"created:{created.Trim()}");
            sb.AppendLine("algorithm:ML-KEM-768");
            sb.AppendLine($"fingerprint:{fingerprint.Trim()}");
            sb.AppendLine();
            sb.AppendLine("key:");
            sb.AppendLine(Kx2FormatBase64ForDisplay(Convert.FromBase64String(keyBase64), 64));
            sb.AppendLine("-----END OBSIDIANQ PUBLIC IDENTITY-----");
            return sb.ToString();
        }

        bool TryParsePublicIdentityBlock(
            string text,
            out string keyNormalized,
            out string? name,
            out string? email,
            out string? device,
            out string? created,
            out string? algorithm,
            out string? fingerprint,
            out string error)
        {
            keyNormalized = string.Empty;
            name = null; email = null; device = null; created = null; algorithm = null; fingerprint = null;
            error = string.Empty;
            const string begin = "-----BEGIN OBSIDIANQ PUBLIC IDENTITY-----";
            const string end = "-----END OBSIDIANQ PUBLIC IDENTITY-----";
            if (!text.Contains(begin, StringComparison.Ordinal))
                return false;

            int s = text.IndexOf(begin, StringComparison.Ordinal);
            int e = text.IndexOf(end, StringComparison.Ordinal);
            if (s < 0 || e <= s) { error = "Identity block markers are invalid."; return false; }
            string body = text[(s + begin.Length)..e];
            bool inKey = false;
            var keyLines = new List<string>();
            foreach (string raw in body.Split(['\r', '\n'], StringSplitOptions.None))
            {
                string line = raw.Trim();
                if (string.IsNullOrWhiteSpace(line)) continue;
                if (inKey)
                {
                    keyLines.Add(line);
                    continue;
                }
                if (line.Equals("key:", StringComparison.OrdinalIgnoreCase))
                {
                    inKey = true;
                    continue;
                }
                int idx = line.IndexOf(':');
                if (idx <= 0) continue;
                string k = line[..idx].Trim().ToLowerInvariant();
                string v = line[(idx + 1)..].Trim();
                switch (k)
                {
                    case "name": name = v; break;
                    case "email": email = v; break;
                    case "device": device = v; break;
                    case "created": created = v; break;
                    case "algorithm": algorithm = v; break;
                    case "fingerprint": fingerprint = v; break;
                }
            }

            if (keyLines.Count == 0) { error = "Identity block is missing key data."; return false; }
            keyNormalized = NormalizeKeyText(string.Concat(keyLines));
            if (string.IsNullOrWhiteSpace(keyNormalized)) { error = "Identity key data is empty."; return false; }
            try
            {
                _ = Convert.FromBase64String(keyNormalized);
            }
            catch
            {
                error = "Identity key data is not valid Base64.";
                return false;
            }
            if (string.IsNullOrWhiteSpace(algorithm)) { error = "Identity block is missing algorithm."; return false; }
            if (string.IsNullOrWhiteSpace(fingerprint)) { error = "Identity block is missing fingerprint."; return false; }
            return true;
        }

        void Kx2Status(string text, bool isError = false)
        {
            lblKx2Status.ForeColor = isError ? Theme.Error : Theme.Accent;
            lblKx2Status.Text = text;
            Kx2Log((isError ? "[ERR] " : "[OK] ") + text, isError ? Theme.Error : Theme.Accent);
        }

        bool TryDecodePubKey(string text, out byte[] raw, out string normalized)
        {
            raw = [];
            normalized = NormalizeKeyText(text);
            if (string.IsNullOrWhiteSpace(normalized)) return false;
            try
            {
                raw = Convert.FromBase64String(normalized);
                return raw.Length > 0;
            }
            catch
            {
                return false;
            }
        }

        async Task<string?> ComputeFingerprintAsync(byte[] keyBytes)
        {
            string tempPath = Path.Combine(Path.GetTempPath(), $"obsidianq_kx2_{Guid.NewGuid():N}.bin");
            try
            {
                await File.WriteAllBytesAsync(tempPath, keyBytes);
                var (code, stdout, stderr) = await RunExchangeCliAsync($"exchange fingerprint --key \"{tempPath}\"");
                if (!string.IsNullOrWhiteSpace(stderr)) Kx2Log(stderr.TrimEnd(), Theme.Error);
                if (code != 0) return null;
                return stdout.Trim();
            }
            finally
            {
                try { if (File.Exists(tempPath)) File.Delete(tempPath); } catch { }
            }
        }

        async Task Kx2RefreshMyPublicKeyAsync()
        {
            string? pubPath = FindDefaultKey(DefaultPubKeyNames);
            if (string.IsNullOrWhiteSpace(pubPath) || !File.Exists(pubPath))
            {
                txtKx2MyPub.Text = string.Empty;
                kx2MyPubRaw = string.Empty;
                kx2MyFingerprintRaw = string.Empty;
                lblKx2MyFingerprint.Text = "-";
                Kx2Status("No public key found. Generate one in Settings.", true);
                return;
            }
            try
            {
                byte[] raw = await File.ReadAllBytesAsync(pubPath);
                kx2MyPubRaw = Convert.ToBase64String(raw);
                txtKx2MyPub.Text = Kx2FormatBase64ForDisplay(raw, 64);
                string? fp = await ComputeFingerprintAsync(raw);
                kx2MyFingerprintRaw = fp ?? string.Empty;
                lblKx2MyFingerprint.Text = Kx2FormatFingerprint(fp ?? string.Empty);
                if (!string.IsNullOrWhiteSpace(fp))
                    Kx2Log($"My fingerprint: {fp}", Theme.AccentDim);
                Kx2Status("Loaded your identity.");
            }
            catch (Exception ex)
            {
                Kx2Status($"Failed to load public key: {ex.Message}", true);
            }
        }

        void Kx2SaveRecipients()
        {
            try
            {
                string dir = Path.GetDirectoryName(keyExchange2StorePath) ?? LocalKeysDir;
                Directory.CreateDirectory(dir);
                using var sw = new StreamWriter(keyExchange2StorePath, false, Encoding.UTF8);
                foreach (ListViewItem item in lvKx2Recipients.Items)
                {
                    string name = item.SubItems[0].Text.Replace('\t', ' ').Trim();
                    string fp = item.SubItems[1].Text.Trim();
                    string dateAdded = item.SubItems[2].Text.Trim();
                    string keyType = item.SubItems[3].Text.Trim();
                    string email = item.SubItems.Count > 4 ? item.SubItems[4].Text.Replace('\t', ' ').Trim() : string.Empty;
                    string device = item.SubItems.Count > 5 ? item.SubItems[5].Text.Replace('\t', ' ').Trim() : string.Empty;
                    string identityCreated = item.SubItems.Count > 6 ? item.SubItems[6].Text.Replace('\t', ' ').Trim() : string.Empty;
                    string identityAlgorithm = item.SubItems.Count > 7 ? item.SubItems[7].Text.Replace('\t', ' ').Trim() : string.Empty;
                    string b64 = (item.Tag as string ?? string.Empty).Replace("\r", "").Replace("\n", "").Trim();
                    if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(fp) || string.IsNullOrWhiteSpace(b64)) continue;
                    sw.WriteLine($"{name}\t{fp}\t{keyType}\t{dateAdded}\t{b64}\t{email}\t{device}\t{identityCreated}\t{identityAlgorithm}");
                }
            }
            catch (Exception ex)
            {
                Kx2Log($"[WARN] Failed to save contacts: {ex.Message}", Theme.Error);
            }
        }

        void Kx2LoadRecipients()
        {
            lvKx2Recipients.Items.Clear();
            if (!File.Exists(keyExchange2StorePath)) return;
            try
            {
                foreach (string line in File.ReadAllLines(keyExchange2StorePath))
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    string[] parts = line.Split('\t');
                    if (parts.Length < 5) continue;
                    var item = new ListViewItem(parts[0].Trim());
                    item.SubItems.Add(parts[1].Trim());
                    item.SubItems.Add(parts[3].Trim());
                    item.SubItems.Add(string.IsNullOrWhiteSpace(parts[2]) ? "PQC" : parts[2].Trim());
                    item.SubItems.Add(parts.Length > 5 ? parts[5].Trim() : string.Empty); // email
                    item.SubItems.Add(parts.Length > 6 ? parts[6].Trim() : string.Empty); // device
                    item.SubItems.Add(parts.Length > 7 ? parts[7].Trim() : string.Empty); // identity created
                    item.SubItems.Add(parts.Length > 8 ? parts[8].Trim() : string.Empty); // identity algorithm
                    item.Tag = parts[4].Trim();
                    lvKx2Recipients.Items.Add(item);
                }
                Kx2AdjustRecipientColumns();
            }
            catch (Exception ex)
            {
                Kx2Log($"[WARN] Failed to load contacts: {ex.Message}", Theme.Error);
            }
        }

        void Kx2LoadIdentityProfile()
        {
            try
            {
                if (!File.Exists(kx2IdentityProfilePath)) return;
                string[] parts = File.ReadAllText(kx2IdentityProfilePath, Encoding.UTF8).Split('\t');
                if (parts.Length > 0 && !string.IsNullOrWhiteSpace(parts[0])) txtKx2IdentityName.Text = parts[0].Trim();
                if (parts.Length > 1 && !string.IsNullOrWhiteSpace(parts[1])) txtKx2IdentityEmail.Text = parts[1].Trim();
                if (parts.Length > 2 && !string.IsNullOrWhiteSpace(parts[2])) txtKx2IdentityDevice.Text = parts[2].Trim();
            }
            catch (Exception ex)
            {
                Kx2Log($"[WARN] Failed to load identity profile: {ex.Message}", Theme.Error);
            }
        }

        void Kx2SaveIdentityProfile()
        {
            try
            {
                string dir = Path.GetDirectoryName(kx2IdentityProfilePath) ?? LocalKeysDir;
                Directory.CreateDirectory(dir);
                string content = $"{txtKx2IdentityName.Text.Trim()}\t{txtKx2IdentityEmail.Text.Trim()}\t{txtKx2IdentityDevice.Text.Trim()}";
                File.WriteAllText(kx2IdentityProfilePath, content, Encoding.UTF8);
            }
            catch (Exception ex)
            {
                Kx2Log($"[WARN] Failed to save identity profile: {ex.Message}", Theme.Error);
            }
        }

        var btnKx2CopyMyPub = new NeonButton { Text = "COPY PUBLIC IDENTITY", Dock = DockStyle.Fill, Margin = new Padding(0, 2, 3, 2) };
        var btnKx2ExportMyPub = new NeonButton { Text = "EXPORT PUBLIC IDENTITY", Dock = DockStyle.Fill, Margin = new Padding(3, 2, 0, 2) };
        var btnKx2ToggleFullKey = new NeonButton { Text = "VIEW RAW KEY", Dock = DockStyle.Fill, Margin = new Padding(0, 2, 0, 2), MinimumSize = new Size(0, 30), MaximumSize = new Size(int.MaxValue, 30) };
        var btnKx2FocusAdd = new NeonButton { Text = "+ ADD CONTACT", Dock = DockStyle.Fill, Margin = new Padding(0, 2, 0, 2) };
        btnKx2CopyMyPub.Click += (_, _) =>
        {
            if (string.IsNullOrWhiteSpace(kx2MyPubRaw) || string.IsNullOrWhiteSpace(kx2MyFingerprintRaw))
            {
                Kx2Status("No public identity available to copy.", true);
                return;
            }
            string doc = Kx2BuildPublicIdentityDocument(
                kx2MyPubRaw,
                kx2MyFingerprintRaw,
                txtKx2IdentityName.Text,
                txtKx2IdentityEmail.Text,
                txtKx2IdentityDevice.Text,
                DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"));
            Clipboard.SetText(doc);
            Kx2Status("Public identity copied to clipboard.");
        };
        btnKx2ExportMyPub.Click += (_, _) =>
        {
            if (string.IsNullOrWhiteSpace(kx2MyPubRaw) || string.IsNullOrWhiteSpace(kx2MyFingerprintRaw))
            {
                Kx2Status("No public identity available.", true);
                return;
            }
            try
            {
                string baseName = txtKx2IdentityName.Text.Trim();
                if (string.IsNullOrWhiteSpace(baseName)) baseName = "identity";
                string safeName = string.Concat(baseName.Select(ch => Path.GetInvalidFileNameChars().Contains(ch) ? '_' : ch));
                if (string.IsNullOrWhiteSpace(safeName)) safeName = "identity";
                string doc = Kx2BuildPublicIdentityDocument(
                    kx2MyPubRaw,
                    kx2MyFingerprintRaw,
                    txtKx2IdentityName.Text,
                    txtKx2IdentityEmail.Text,
                    txtKx2IdentityDevice.Text,
                    DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"));
                using var dlg = new SaveFileDialog
                {
                    Title = "Export Public Identity",
                    Filter = "ObsidianQ Public Identity (*.obsqpub)|*.obsqpub|Text files (*.txt)|*.txt|All files|*.*",
                    FileName = $"{safeName}.obsqpub",
                    AddExtension = true,
                };
                if (dlg.ShowDialog(this) != DialogResult.OK) return;
                File.WriteAllText(dlg.FileName, doc, Encoding.UTF8);
                Kx2Status("Public identity exported.");
            }
            catch (Exception ex)
            {
                Kx2Status($"Failed to export public identity: {ex.Message}", true);
            }
        };
        var btnKx2CopyFp = new NeonButton { Text = "COPY FINGERPRINT", Dock = DockStyle.Fill, Margin = new Padding(0, 2, 3, 2) };
        var btnKx2ExportContact = new NeonButton { Text = "EXPORT PUBLIC IDENTITY", Dock = DockStyle.Fill, Margin = new Padding(0, 2, 3, 2) };
        var btnKx2Delete = new NeonButton { Text = "REMOVE CONTACT", Dock = DockStyle.Fill, Margin = new Padding(0, 2, 0, 2) };
        var kx2ContactMenu = new ContextMenuStrip { BackColor = Theme.Surface, ForeColor = Theme.TextMain };
        var kx2MenuRemove = new ToolStripMenuItem("Remove Contact");
        kx2ContactMenu.Items.Add(kx2MenuRemove);
        lvKx2Recipients.ContextMenuStrip = kx2ContactMenu;
        var kx2Tips = new ToolTip { AutoPopDelay = 6000, InitialDelay = 200, ReshowDelay = 120 };
        kx2Tips.SetToolTip(btnKx2CopyMyPub, "Copy your full public identity document.");
        kx2Tips.SetToolTip(btnKx2ExportMyPub, "Export your public identity to an .obsqpub file.");
        kx2Tips.SetToolTip(btnKx2Delete, "Remove this contact from your secure contacts.");
        kx2Tips.SetToolTip(btnKx2ExportContact, "Export selected contact as an .obsqpub identity.");
        txtKx2IdentityName.TextChanged += (_, _) => Kx2SaveIdentityProfile();
        txtKx2IdentityEmail.TextChanged += (_, _) => Kx2SaveIdentityProfile();
        txtKx2IdentityDevice.TextChanged += (_, _) => Kx2SaveIdentityProfile();

        bool Kx2UpsertContact(
            string contactName,
            string normalizedKey,
            string fingerprint,
            string email = "",
            string device = "",
            string identityCreated = "",
            string identityAlgorithm = "ML-KEM-768")
        {
            ListViewItem? existing = null;
            foreach (ListViewItem row in lvKx2Recipients.Items)
            {
                if (string.Equals(row.SubItems[1].Text, fingerprint, StringComparison.OrdinalIgnoreCase))
                {
                    existing = row;
                    break;
                }
            }

            if (existing == null)
            {
                var item = new ListViewItem(contactName);
                item.SubItems.Add(fingerprint);
                item.SubItems.Add(DateTime.Now.ToString("MM-dd-yyyy"));
                item.SubItems.Add("PQC");
                item.SubItems.Add(email.Trim());
                item.SubItems.Add(device.Trim());
                item.SubItems.Add(identityCreated.Trim());
                item.SubItems.Add(identityAlgorithm.Trim());
                item.Tag = normalizedKey;
                lvKx2Recipients.Items.Add(item);
            }
            else
            {
                existing.SubItems[0].Text = contactName;
                existing.SubItems[2].Text = DateTime.Now.ToString("MM-dd-yyyy");
                existing.SubItems[3].Text = "PQC";
                existing.SubItems[4].Text = email.Trim();
                existing.SubItems[5].Text = device.Trim();
                existing.SubItems[6].Text = identityCreated.Trim();
                existing.SubItems[7].Text = identityAlgorithm.Trim();
                existing.Tag = normalizedKey;
            }

            Kx2SaveRecipients();
            Kx2AdjustRecipientColumns();
            Kx2Status($"Contact '{contactName}' added.");
            return true;
        }

        void ShowAddContactDialog(string? initialIdentityText = null, bool autoValidate = false)
        {
            using var dlg = new Form
            {
                Text = "Add A New Contact",
                StartPosition = FormStartPosition.CenterParent,
                FormBorderStyle = FormBorderStyle.FixedDialog,
                MaximizeBox = false,
                MinimizeBox = false,
                ShowInTaskbar = false,
                ClientSize = new Size(760, 520),
                BackColor = Theme.Bg,
                ForeColor = Theme.TextMain,
                Font = Theme.SafeMono(9f),
            };

            var txtKey = MakeTextBox();
            txtKey.Multiline = true;
            txtKey.ScrollBars = ScrollBars.Vertical;
            txtKey.PlaceholderText = "Paste Public Identity block or raw Base64 public key";
            var txtName = MakeTextBox();
            txtName.PlaceholderText = "Contact name (required)";
            var txtEmail = MakeTextBox();
            txtEmail.PlaceholderText = "Email (optional)";
            var txtDevice = MakeTextBox();
            txtDevice.PlaceholderText = "Device (optional)";
            var lblInfo = MakeLabel("Paste a public identity or raw public key, then validate.", 8.5f);
            lblInfo.Dock = DockStyle.Fill;
            lblInfo.TextAlign = ContentAlignment.MiddleLeft;
            lblInfo.AutoSize = false;
            lblInfo.AutoEllipsis = true;
            var btnValidate = new NeonButton { Text = "VALIDATE KEY", Dock = DockStyle.Fill, Margin = new Padding(0, 2, 3, 2) };
            var btnAccept = new NeonButton { Text = "ACCEPT CONTACT", Dock = DockStyle.Fill, Margin = new Padding(3, 2, 0, 2), Enabled = false };
            var btnCancel = new NeonButton { Text = "CANCEL", Dock = DockStyle.Fill, Margin = new Padding(0, 2, 0, 2) };

            string normalized = string.Empty;
            string fingerprint = string.Empty;
            string detectedEmail = string.Empty;
            string detectedDevice = string.Empty;
            string detectedCreated = string.Empty;
            string detectedAlgorithm = "ML-KEM-768";
            bool validating = false;

            var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 8, Padding = new Padding(12), BackColor = Theme.Bg };
            root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 24));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 290));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 24));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 36));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 36));
            var lblTitle = MakeLabel("ADD A NEW CONTACT", 9f, bold: true); lblTitle.ForeColor = Theme.Accent; lblTitle.Dock = DockStyle.Fill; lblTitle.TextAlign = ContentAlignment.MiddleLeft;
            var rowBtns = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, BackColor = Theme.Bg };
            rowBtns.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            rowBtns.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            rowBtns.Controls.Add(btnValidate, 0, 0);
            rowBtns.Controls.Add(btnAccept, 1, 0);
            root.Controls.Add(lblTitle, 0, 0);
            root.Controls.Add(txtKey, 0, 1);
            root.Controls.Add(txtName, 0, 2);
            root.Controls.Add(txtEmail, 0, 3);
            root.Controls.Add(txtDevice, 0, 4);
            root.Controls.Add(lblInfo, 0, 5);
            root.Controls.Add(rowBtns, 0, 6);
            root.Controls.Add(btnCancel, 0, 7);
            dlg.Controls.Add(root);

            if (!string.IsNullOrWhiteSpace(initialIdentityText))
                txtKey.Text = initialIdentityText;

            btnCancel.Click += (_, _) => dlg.Close();
            void RefreshAcceptEnabled()
            {
                btnAccept.Enabled =
                    !string.IsNullOrWhiteSpace(normalized) &&
                    !string.IsNullOrWhiteSpace(fingerprint) &&
                    !string.IsNullOrWhiteSpace(txtName.Text.Trim());
            }

            async Task ValidateContactInputAsync(bool autoTriggered)
            {
                if (validating) return;
                validating = true;
                normalized = string.Empty;
                fingerprint = string.Empty;
                btnAccept.Enabled = false;

                string localName = txtName.Text.Trim();
                string localNormalized = string.Empty;
                byte[] raw = [];
                string localEmail = string.Empty;
                string localDevice = string.Empty;

                bool fromIdentity = TryParsePublicIdentityBlock(
                    txtKey.Text,
                    out localNormalized,
                    out var parsedName,
                    out var parsedEmail,
                    out var parsedDevice,
                    out var parsedCreated,
                    out var parsedAlgorithm,
                    out var parsedFp,
                    out var identityError);

                if (fromIdentity)
                {
                    if (!string.Equals(parsedAlgorithm, "ML-KEM-768", StringComparison.OrdinalIgnoreCase))
                    {
                        lblInfo.Text = autoTriggered ? "Identity detected but algorithm is unsupported." : $"Unsupported identity algorithm: {parsedAlgorithm}";
                        lblInfo.ForeColor = Theme.Error;
                        validating = false;
                        return;
                    }
                    raw = Convert.FromBase64String(localNormalized);
                    if (!string.IsNullOrWhiteSpace(parsedName))
                    {
                        localName = parsedName.Trim();
                        txtName.Text = localName;
                    }
                    localEmail = parsedEmail?.Trim() ?? string.Empty;
                    localDevice = parsedDevice?.Trim() ?? string.Empty;
                    if (!string.IsNullOrWhiteSpace(localEmail)) txtEmail.Text = localEmail;
                    if (!string.IsNullOrWhiteSpace(localDevice)) txtDevice.Text = localDevice;
                    detectedCreated = parsedCreated?.Trim() ?? string.Empty;
                    detectedAlgorithm = string.IsNullOrWhiteSpace(parsedAlgorithm) ? "ML-KEM-768" : parsedAlgorithm.Trim();

                    string? computedFp = await ComputeFingerprintAsync(raw);
                    if (string.IsNullOrWhiteSpace(computedFp))
                    {
                        lblInfo.Text = autoTriggered ? "Detected key could not be validated yet." : "Unable to calculate fingerprint for this key.";
                        lblInfo.ForeColor = Theme.Error;
                        validating = false;
                        return;
                    }
                    if (!string.IsNullOrWhiteSpace(parsedFp) &&
                        !string.Equals(Kx2NormalizeFingerprint(computedFp), Kx2NormalizeFingerprint(parsedFp), StringComparison.Ordinal))
                    {
                        lblInfo.Text = "Identity fingerprint does not match the public key.";
                        lblInfo.ForeColor = Theme.Error;
                        validating = false;
                        return;
                    }
                    fingerprint = computedFp;
                }
                else
                {
                    if (!TryDecodePubKey(txtKey.Text, out raw, out localNormalized))
                    {
                        if (!autoTriggered)
                        {
                            lblInfo.Text = txtKey.Text.Contains("BEGIN OBSIDIANQ PUBLIC IDENTITY", StringComparison.Ordinal)
                                ? $"Identity parse failed: {identityError}"
                                : "Paste a valid contact public key first.";
                            lblInfo.ForeColor = Theme.Error;
                        }
                        validating = false;
                        return;
                    }
                    string? computedFp = await ComputeFingerprintAsync(raw);
                    if (string.IsNullOrWhiteSpace(computedFp))
                    {
                        if (!autoTriggered)
                        {
                            lblInfo.Text = "Unable to calculate fingerprint for this key.";
                            lblInfo.ForeColor = Theme.Error;
                        }
                        validating = false;
                        return;
                    }
                    fingerprint = computedFp;
                    localEmail = txtEmail.Text.Trim();
                    localDevice = txtDevice.Text.Trim();
                }

                if (string.IsNullOrWhiteSpace(localName))
                {
                    if (!autoTriggered)
                    {
                        lblInfo.Text = "Enter a contact name first.";
                        lblInfo.ForeColor = Theme.Error;
                    }
                    validating = false;
                    return;
                }

                normalized = localNormalized;
                detectedEmail = txtEmail.Text.Trim();
                if (string.IsNullOrWhiteSpace(detectedEmail)) detectedEmail = localEmail;
                detectedDevice = txtDevice.Text.Trim();
                if (string.IsNullOrWhiteSpace(detectedDevice)) detectedDevice = localDevice;
                var details = new List<string>
                {
                    $"Fingerprint: {Kx2FormatFingerprint(fingerprint)}"
                };
                if (!string.IsNullOrWhiteSpace(detectedEmail)) details.Add($"Email: {detectedEmail}");
                if (!string.IsNullOrWhiteSpace(detectedDevice)) details.Add($"Device: {detectedDevice}");
                if (!string.IsNullOrWhiteSpace(detectedCreated)) details.Add($"Created: {detectedCreated}");
                if (!string.IsNullOrWhiteSpace(detectedAlgorithm)) details.Add($"Algorithm: {detectedAlgorithm}");
                lblInfo.Text = string.Join(" | ", details);
                lblInfo.ForeColor = Theme.Accent;
                RefreshAcceptEnabled();
                Kx2Status("Key validation successful.");
                validating = false;
            }

            btnValidate.Click += async (_, _) => await ValidateContactInputAsync(autoTriggered: false);
            txtName.TextChanged += (_, _) => RefreshAcceptEnabled();
            txtEmail.TextChanged += (_, _) => RefreshAcceptEnabled();
            txtDevice.TextChanged += (_, _) => RefreshAcceptEnabled();
            txtKey.TextChanged += (_, _) =>
            {
                btnAccept.Enabled = false;
                bool looksLikeIdentity = txtKey.Text.Contains("BEGIN OBSIDIANQ PUBLIC IDENTITY", StringComparison.Ordinal);
                bool looksLikeRaw = !looksLikeIdentity && TryDecodePubKey(txtKey.Text, out _, out _);
                if (looksLikeIdentity || looksLikeRaw)
                    _ = ValidateContactInputAsync(autoTriggered: true);
            };

            btnAccept.Click += (_, _) =>
            {
                string contactName = txtName.Text.Trim();
                if (string.IsNullOrWhiteSpace(contactName))
                {
                    lblInfo.Text = "Enter a contact name first.";
                    lblInfo.ForeColor = Theme.Error;
                    return;
                }
                if (string.IsNullOrWhiteSpace(normalized) || string.IsNullOrWhiteSpace(fingerprint))
                {
                    lblInfo.Text = "Validate the key before accepting.";
                    lblInfo.ForeColor = Theme.Error;
                    return;
                }
                string finalEmail = txtEmail.Text.Trim();
                string finalDevice = txtDevice.Text.Trim();

                string confirmMessage = $"Add secure contact?\n\nName: {contactName}\nFingerprint: {Kx2FormatFingerprint(fingerprint)}";
                if (!string.IsNullOrWhiteSpace(finalEmail)) confirmMessage += $"\nEmail: {finalEmail}";
                if (!string.IsNullOrWhiteSpace(finalDevice)) confirmMessage += $"\nDevice: {finalDevice}";
                if (!string.IsNullOrWhiteSpace(detectedCreated)) confirmMessage += $"\nCreated: {detectedCreated}";
                if (!string.IsNullOrWhiteSpace(detectedAlgorithm)) confirmMessage += $"\nAlgorithm: {detectedAlgorithm}";
                if (MessageBox.Show(this, confirmMessage, "Confirm Contact", MessageBoxButtons.OKCancel, MessageBoxIcon.Question) != DialogResult.OK)
                    return;

                Kx2UpsertContact(contactName, normalized, fingerprint, finalEmail, finalDevice, detectedCreated, detectedAlgorithm);
                dlg.Close();
            };

            if (autoValidate && !string.IsNullOrWhiteSpace(initialIdentityText))
                dlg.Shown += (_, _) => btnValidate.PerformClick();

            dlg.ShowDialog(this);
        }
        _openAddContactDialog = ShowAddContactDialog;

        btnKx2FocusAdd.Click += (_, _) => ShowAddContactDialog();

        btnKx2CopyFp.Click += (_, _) =>
        {
            if (lvKx2Recipients.SelectedItems.Count == 0) { Kx2Status("Select a contact first.", true); return; }
            string fp = lvKx2Recipients.SelectedItems[0].SubItems[1].Text;
            Clipboard.SetText(fp);
            Kx2Status("Fingerprint copied to clipboard.");
        };

        btnKx2ExportContact.Click += (_, _) =>
        {
            if (lvKx2Recipients.SelectedItems.Count == 0) { Kx2Status("Select a contact first.", true); return; }
            string keyB64 = lvKx2Recipients.SelectedItems[0].Tag as string ?? string.Empty;
            if (string.IsNullOrWhiteSpace(keyB64)) { Kx2Status("Contact key is unavailable.", true); return; }
            try
            {
                string baseName = lvKx2Recipients.SelectedItems[0].SubItems[0].Text.Trim();
                if (string.IsNullOrWhiteSpace(baseName)) baseName = "contact";
                string safeName = string.Concat(baseName.Select(ch => Path.GetInvalidFileNameChars().Contains(ch) ? '_' : ch));
                string fp = lvKx2Recipients.SelectedItems[0].SubItems[1].Text.Trim();
                string email = lvKx2Recipients.SelectedItems[0].SubItems.Count > 4 ? lvKx2Recipients.SelectedItems[0].SubItems[4].Text.Trim() : string.Empty;
                string device = lvKx2Recipients.SelectedItems[0].SubItems.Count > 5 ? lvKx2Recipients.SelectedItems[0].SubItems[5].Text.Trim() : string.Empty;
                string identityCreated = lvKx2Recipients.SelectedItems[0].SubItems.Count > 6 ? lvKx2Recipients.SelectedItems[0].SubItems[6].Text.Trim() : string.Empty;
                string doc = Kx2BuildPublicIdentityDocument(
                    keyB64,
                    fp,
                    baseName,
                    email,
                    device,
                    string.IsNullOrWhiteSpace(identityCreated) ? DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") : identityCreated);
                using var dlg = new SaveFileDialog
                {
                    Title = "Export Contact Public Identity",
                    Filter = "ObsidianQ Public Identity (*.obsqpub)|*.obsqpub|Text files (*.txt)|*.txt|All files|*.*",
                    FileName = $"{safeName}.obsqpub",
                    AddExtension = true,
                };
                if (dlg.ShowDialog(this) != DialogResult.OK) return;
                File.WriteAllText(dlg.FileName, doc, Encoding.UTF8);
                Kx2Status("Contact public identity exported.");
            }
            catch (Exception ex)
            {
                Kx2Status($"Failed to export contact identity: {ex.Message}", true);
            }
        };

        btnKx2Delete.Click += (_, _) =>
        {
            if (lvKx2Recipients.SelectedItems.Count == 0) { Kx2Status("Select a contact first.", true); return; }
            string name = lvKx2Recipients.SelectedItems[0].SubItems[0].Text;
            lvKx2Recipients.Items.Remove(lvKx2Recipients.SelectedItems[0]);
            Kx2SaveRecipients();
            lblKx2ContactNameVal.Text = "-";
            lblKx2ContactFpVal.Text = "-";
            lblKx2ContactDateVal.Text = "-";
            lblKx2ContactEmailVal.Text = "-";
            lblKx2ContactDeviceVal.Text = "-";
            lblKx2ContactCreatedVal.Text = "-";
            lblKx2ContactAlgoVal.Text = "-";
            lblKx2ContactTypeVal.Text = "-";
            Kx2AdjustRecipientColumns();
            Kx2Status($"Removed contact '{name}'.");
        };
        kx2MenuRemove.Click += (_, _) => btnKx2Delete.PerformClick();
        lvKx2Recipients.KeyDown += (_, e) =>
        {
            if (e.KeyCode == Keys.Delete)
            {
                btnKx2Delete.PerformClick();
                e.Handled = true;
            }
        };

        lvKx2Recipients.SelectedIndexChanged += (_, _) =>
        {
            if (lvKx2Recipients.SelectedItems.Count == 0)
            {
                lblKx2ContactNameVal.Text = "-";
                lblKx2ContactFpVal.Text = "-";
                lblKx2ContactDateVal.Text = "-";
                lblKx2ContactEmailVal.Text = "-";
                lblKx2ContactDeviceVal.Text = "-";
                lblKx2ContactCreatedVal.Text = "-";
                lblKx2ContactAlgoVal.Text = "-";
                lblKx2ContactTypeVal.Text = "-";
                return;
            }
            var row = lvKx2Recipients.SelectedItems[0];
            lblKx2ContactNameVal.Text = row.SubItems[0].Text;
            lblKx2ContactFpVal.Text = Kx2FormatFingerprint(row.SubItems[1].Text);
            lblKx2ContactDateVal.Text = Kx2FormatDateDisplay(row.SubItems[2].Text);
            lblKx2ContactTypeVal.Text = row.SubItems.Count > 3 && !string.IsNullOrWhiteSpace(row.SubItems[3].Text) ? row.SubItems[3].Text : "-";
            lblKx2ContactEmailVal.Text = row.SubItems.Count > 4 && !string.IsNullOrWhiteSpace(row.SubItems[4].Text) ? row.SubItems[4].Text : "-";
            lblKx2ContactDeviceVal.Text = row.SubItems.Count > 5 && !string.IsNullOrWhiteSpace(row.SubItems[5].Text) ? row.SubItems[5].Text : "-";
            lblKx2ContactCreatedVal.Text = row.SubItems.Count > 6 && !string.IsNullOrWhiteSpace(row.SubItems[6].Text) ? row.SubItems[6].Text : "-";
            lblKx2ContactAlgoVal.Text = row.SubItems.Count > 7 && !string.IsNullOrWhiteSpace(row.SubItems[7].Text) ? row.SubItems[7].Text : "-";
        };

        var outerKx2 = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 5,
            Padding = new Padding(16),
            BackColor = Theme.Bg,
        };
        outerKx2.RowStyles.Add(new RowStyle(SizeType.Absolute, 52));
        outerKx2.RowStyles.Add(new RowStyle(SizeType.Percent, 60));
        outerKx2.RowStyles.Add(new RowStyle(SizeType.Absolute, 196));
        outerKx2.RowStyles.Add(new RowStyle(SizeType.Percent, 40));
        outerKx2.RowStyles.Add(new RowStyle(SizeType.Absolute, 28));
        outerKx2.Controls.Add(MakeTabHeader(
            "SECURE CONTACTS",
            "Manage your identity and trusted recipient keys for secure exchange."), 0, 0);

        var topGrid = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, BackColor = Theme.Bg };
        topGrid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        topGrid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));

        var myKeyCard = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 5, BackColor = Theme.Surface, Margin = new Padding(0, 0, 8, 0), Padding = new Padding(8, 6, 8, 6) };
        myKeyCard.RowStyles.Add(new RowStyle(SizeType.Absolute, 22));
        myKeyCard.RowStyles.Add(new RowStyle(SizeType.Absolute, 48));
        myKeyCard.RowStyles.Add(new RowStyle(SizeType.Absolute, 72));
        myKeyCard.RowStyles.Add(new RowStyle(SizeType.Absolute, 32));
        myKeyCard.RowStyles.Add(new RowStyle(SizeType.Absolute, 32));
        var lblMyKey = MakeLabel("YOUR IDENTITY", 9f, bold: true); lblMyKey.Dock = DockStyle.Fill; lblMyKey.TextAlign = ContentAlignment.MiddleLeft; lblMyKey.ForeColor = Theme.Accent;
        var myFingerprintPanel = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, BackColor = Theme.Surface };
        myFingerprintPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 16));
        myFingerprintPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        var lblMyFpTitle = MakeLabel("Fingerprint", 8f, bold: true); lblMyFpTitle.Dock = DockStyle.Fill; lblMyFpTitle.ForeColor = Theme.TextDim; lblMyFpTitle.TextAlign = ContentAlignment.MiddleLeft;
        myFingerprintPanel.Controls.Add(lblMyFpTitle, 0, 0);
        myFingerprintPanel.Controls.Add(lblKx2MyFingerprint, 0, 1);
        var myButtons = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, BackColor = Theme.Surface };
        myButtons.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        myButtons.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        myButtons.Controls.Add(btnKx2CopyMyPub, 0, 0);
        myButtons.Controls.Add(btnKx2ExportMyPub, 1, 0);
        var identityFields = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 3, BackColor = Theme.Surface, Margin = new Padding(0) };
        identityFields.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 56));
        identityFields.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        identityFields.RowStyles.Add(new RowStyle(SizeType.Absolute, 24));
        identityFields.RowStyles.Add(new RowStyle(SizeType.Absolute, 24));
        identityFields.RowStyles.Add(new RowStyle(SizeType.Absolute, 24));
        var lblIdName = MakeLabel("Name", 8f, bold: true); lblIdName.Dock = DockStyle.Fill; lblIdName.TextAlign = ContentAlignment.MiddleLeft;
        var lblIdEmail = MakeLabel("Email", 8f, bold: true); lblIdEmail.Dock = DockStyle.Fill; lblIdEmail.TextAlign = ContentAlignment.MiddleLeft;
        var lblIdDevice = MakeLabel("Device", 8f, bold: true); lblIdDevice.Dock = DockStyle.Fill; lblIdDevice.TextAlign = ContentAlignment.MiddleLeft;
        identityFields.Controls.Add(lblIdName, 0, 0);
        identityFields.Controls.Add(txtKx2IdentityName, 1, 0);
        identityFields.Controls.Add(lblIdEmail, 0, 1);
        identityFields.Controls.Add(txtKx2IdentityEmail, 1, 1);
        identityFields.Controls.Add(lblIdDevice, 0, 2);
        identityFields.Controls.Add(txtKx2IdentityDevice, 1, 2);
        myKeyCard.Controls.Add(lblMyKey, 0, 0);
        myKeyCard.Controls.Add(myFingerprintPanel, 0, 1);
        myKeyCard.Controls.Add(identityFields, 0, 2);
        myKeyCard.Controls.Add(myButtons, 0, 3);
        myKeyCard.Controls.Add(btnKx2ToggleFullKey, 0, 4);
        btnKx2ToggleFullKey.Click += (_, _) =>
        {
            if (string.IsNullOrWhiteSpace(kx2MyPubRaw))
            {
                Kx2Status("No raw public key available.", true);
                return;
            }
            using var rawDlg = new Form
            {
                Text = "Raw Public Key",
                StartPosition = FormStartPosition.CenterParent,
                FormBorderStyle = FormBorderStyle.FixedDialog,
                MaximizeBox = false,
                MinimizeBox = false,
                ShowInTaskbar = false,
                ClientSize = new Size(760, 460),
                BackColor = Theme.Bg,
                ForeColor = Theme.TextMain,
                Font = Theme.SafeMono(9f),
            };
            var rawTxt = MakeTextBox();
            rawTxt.Multiline = true;
            rawTxt.ScrollBars = ScrollBars.Both;
            rawTxt.WordWrap = false;
            rawTxt.ReadOnly = true;
            rawTxt.Text = Kx2FormatBase64ForDisplay(Convert.FromBase64String(kx2MyPubRaw), 64);
            var warn = MakeLabel("Raw key material. Share only when you intentionally want someone to encrypt to you.", 8.5f, bold: true);
            warn.Dock = DockStyle.Fill;
            warn.TextAlign = ContentAlignment.MiddleLeft;
            warn.ForeColor = Theme.Error;
            warn.AutoSize = false;
            var btnCopyRaw = new NeonButton { Text = "COPY TO CLIPBOARD", Dock = DockStyle.Fill, Margin = new Padding(0, 2, 0, 2) };
            var btnCloseRaw = new NeonButton { Text = "CLOSE", Dock = DockStyle.Fill, Margin = new Padding(0, 2, 0, 2) };
            btnCopyRaw.Click += (_, _) => { Clipboard.SetText(kx2MyPubRaw); Kx2Status("Raw key copied to clipboard."); };
            btnCloseRaw.Click += (_, _) => rawDlg.Close();
            var rawBtns = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, BackColor = Theme.Bg };
            rawBtns.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            rawBtns.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            rawBtns.Controls.Add(btnCopyRaw, 0, 0);
            rawBtns.Controls.Add(btnCloseRaw, 1, 0);
            var rawRoot = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3, Padding = new Padding(12), BackColor = Theme.Bg };
            rawRoot.RowStyles.Add(new RowStyle(SizeType.Absolute, 28));
            rawRoot.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            rawRoot.RowStyles.Add(new RowStyle(SizeType.Absolute, 36));
            rawRoot.Controls.Add(warn, 0, 0);
            rawRoot.Controls.Add(rawTxt, 0, 1);
            rawRoot.Controls.Add(rawBtns, 0, 2);
            rawDlg.Controls.Add(rawRoot);
            rawDlg.ShowDialog(this);
        };

        var recipientCard = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3, BackColor = Theme.Surface, Margin = new Padding(8, 0, 0, 0), Padding = new Padding(8, 6, 8, 6) };
        recipientCard.RowStyles.Add(new RowStyle(SizeType.Absolute, 24));
        recipientCard.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        recipientCard.RowStyles.Add(new RowStyle(SizeType.Absolute, 32));
        var lblRecipients = MakeLabel("TRUSTED CONTACTS", 9f, bold: true); lblRecipients.Dock = DockStyle.Fill; lblRecipients.TextAlign = ContentAlignment.MiddleLeft; lblRecipients.ForeColor = Theme.Accent;
        recipientCard.Controls.Add(lblRecipients, 0, 0);
        recipientCard.Controls.Add(lvKx2Recipients, 0, 1);
        recipientCard.Controls.Add(btnKx2FocusAdd, 0, 2);

        topGrid.Controls.Add(myKeyCard, 0, 0);
        topGrid.Controls.Add(recipientCard, 1, 0);
        outerKx2.Controls.Add(topGrid, 0, 1);

        var detailsCard = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 3,
            BackColor = Theme.Surface,
            Padding = new Padding(8, 6, 8, 8),
            Margin = new Padding(0),
        };
        detailsCard.RowStyles.Add(new RowStyle(SizeType.Absolute, 24));
        detailsCard.RowStyles.Add(new RowStyle(SizeType.Absolute, 128));
        detailsCard.RowStyles.Add(new RowStyle(SizeType.Absolute, 32));
        var lblDetails = MakeLabel("CONTACT DETAILS", 9f, bold: true);
        lblDetails.Dock = DockStyle.Fill;
        lblDetails.TextAlign = ContentAlignment.MiddleLeft;
        lblDetails.ForeColor = Theme.Accent;
        var detailsInfo = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 4, RowCount = 4, BackColor = Theme.Surface, Margin = new Padding(0) };
        detailsInfo.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 94));
        detailsInfo.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        detailsInfo.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 94));
        detailsInfo.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        detailsInfo.RowStyles.Add(new RowStyle(SizeType.Absolute, 28));
        detailsInfo.RowStyles.Add(new RowStyle(SizeType.Absolute, 28));
        detailsInfo.RowStyles.Add(new RowStyle(SizeType.Absolute, 28));
        detailsInfo.RowStyles.Add(new RowStyle(SizeType.Absolute, 28));
        Label Kx2DetailLabel(string text)
        {
            var l = MakeLabel(text, 8f, bold: true);
            l.Dock = DockStyle.Fill;
            l.TextAlign = ContentAlignment.MiddleLeft;
            l.Margin = new Padding(0, 0, 8, 0);
            return l;
        }
        lblKx2ContactNameVal.Margin = new Padding(0);
        lblKx2ContactFpVal.Margin = new Padding(0);
        lblKx2ContactDateVal.Margin = new Padding(0);
        lblKx2ContactEmailVal.Margin = new Padding(0);
        lblKx2ContactDeviceVal.Margin = new Padding(0);
        lblKx2ContactCreatedVal.Margin = new Padding(0);
        lblKx2ContactAlgoVal.Margin = new Padding(0);
        lblKx2ContactTypeVal.Margin = new Padding(0);
        detailsInfo.Controls.Add(Kx2DetailLabel("Name"), 0, 0);
        detailsInfo.Controls.Add(lblKx2ContactNameVal, 1, 0);
        detailsInfo.Controls.Add(Kx2DetailLabel("Added"), 2, 0);
        detailsInfo.Controls.Add(lblKx2ContactDateVal, 3, 0);
        detailsInfo.Controls.Add(Kx2DetailLabel("Fingerprint"), 0, 1);
        detailsInfo.Controls.Add(lblKx2ContactFpVal, 1, 1);
        detailsInfo.Controls.Add(Kx2DetailLabel("Key Type"), 2, 1);
        detailsInfo.Controls.Add(lblKx2ContactTypeVal, 3, 1);
        detailsInfo.Controls.Add(Kx2DetailLabel("Email"), 0, 2);
        detailsInfo.Controls.Add(lblKx2ContactEmailVal, 1, 2);
        detailsInfo.Controls.Add(Kx2DetailLabel("Device"), 2, 2);
        detailsInfo.Controls.Add(lblKx2ContactDeviceVal, 3, 2);
        detailsInfo.Controls.Add(Kx2DetailLabel("Identity Time"), 0, 3);
        detailsInfo.Controls.Add(lblKx2ContactCreatedVal, 1, 3);
        detailsInfo.Controls.Add(Kx2DetailLabel("Algorithm"), 2, 3);
        detailsInfo.Controls.Add(lblKx2ContactAlgoVal, 3, 3);
        var bottomActions = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, RowCount = 1, BackColor = Theme.Bg, Margin = new Padding(0) };
        bottomActions.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.34f));
        bottomActions.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.33f));
        bottomActions.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.33f));
        bottomActions.Controls.Add(btnKx2CopyFp, 0, 0);
        bottomActions.Controls.Add(btnKx2ExportContact, 1, 0);
        bottomActions.Controls.Add(btnKx2Delete, 2, 0);
        detailsCard.Controls.Add(lblDetails, 0, 0);
        detailsCard.Controls.Add(detailsInfo, 0, 1);
        detailsCard.Controls.Add(bottomActions, 0, 2);
        var detailsContainer = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Surface, Padding = new Padding(0), Margin = new Padding(0) };
        detailsContainer.Controls.Add(detailsCard);
        detailsContainer.Paint += (_, pe) =>
        {
            using var pen = new Pen(Theme.Border, 1f);
            pe.Graphics.DrawRectangle(pen, 0, 0, detailsContainer.Width - 1, detailsContainer.Height - 1);
        };
        outerKx2.Controls.Add(detailsContainer, 0, 2);
        var activityCard = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, BackColor = Theme.Surface, Padding = new Padding(8, 6, 8, 8), Margin = new Padding(0) };
        activityCard.RowStyles.Add(new RowStyle(SizeType.Absolute, 24));
        activityCard.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        var lblActivity = MakeLabel("ACTIVITY", 9f, bold: true); lblActivity.Dock = DockStyle.Fill; lblActivity.TextAlign = ContentAlignment.MiddleLeft; lblActivity.ForeColor = Theme.Accent;
        var kx2LogContainer = new Panel { Dock = DockStyle.Fill, BackColor = Theme.LogBg };
        kx2LogContainer.Controls.Add(rtbKx2Log);
        kx2LogContainer.Paint += (_, pe) =>
        {
            using var pen = new Pen(Theme.Border, 1f);
            pe.Graphics.DrawRectangle(pen, 0, 0, kx2LogContainer.Width - 1, kx2LogContainer.Height - 1);
        };
        activityCard.Controls.Add(lblActivity, 0, 0);
        activityCard.Controls.Add(kx2LogContainer, 0, 1);
        var activityContainer = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Surface, Padding = new Padding(0), Margin = new Padding(0) };
        activityContainer.Controls.Add(activityCard);
        activityContainer.Paint += (_, pe) =>
        {
            using var pen = new Pen(Theme.Border, 1f);
            pe.Graphics.DrawRectangle(pen, 0, 0, activityContainer.Width - 1, activityContainer.Height - 1);
        };
        outerKx2.Controls.Add(activityContainer, 0, 3);
        outerKx2.Controls.Add(lblKx2Status, 0, 4);

        Kx2LoadIdentityProfile();
        Kx2LoadRecipients();
        _ = Kx2RefreshMyPublicKeyAsync();
        // ==================================================================
        // SETTINGS TAB - centralized sensitive actions
        // ==================================================================
        var txtSettingsKeys = MakeTextBox();
        txtSettingsKeys.ReadOnly = true;
        txtSettingsKeys.Multiline = true;
        txtSettingsKeys.ScrollBars = ScrollBars.Vertical;

        var btnSettingsGenerate = new NeonButton { Text = "GENERATE NEW KEYPAIR", Dock = DockStyle.Fill, Margin = new Padding(0, 2, 0, 2) };
        var btnSettingsBackup = new NeonButton { Text = "BACKUP LOCAL KEYPAIR", Dock = DockStyle.Fill, Margin = new Padding(0, 2, 4, 2) };
        var btnSettingsRestore = new NeonButton { Text = "RESTORE LOCAL KEYPAIR", Dock = DockStyle.Fill, Margin = new Padding(4, 2, 0, 2) };
        btnSettingsGenerate.Click += async (_, _) =>
        {
            if (!ConfirmKeyGenerationRisk()) return;
            if (!File.Exists(ExePath))
            {
                MessageBox.Show($"obsidianq.exe not found at:\n{ExePath}", "Key Generation", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            btnSettingsGenerate.Enabled = false;
            try
            {
                var (exitCode, pubPath, privPath, stdout, stderr) = await RunWithBusyDialogAsync(
                    "Key Generation",
                    "Generating keypair...",
                    () => RunDefaultKeygenAsync());
                if (exitCode != 0)
                {
                    string err = string.IsNullOrWhiteSpace(stderr) ? $"exit {exitCode}" : stderr.Trim();
                    MessageBox.Show($"Key generation failed: {err}", "Key Generation", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                txtSettingsKeys.Text =
                    $"Public Key:  {pubPath}{Environment.NewLine}" +
                    $"Private Key: {privPath}{Environment.NewLine}{Environment.NewLine}" +
                    "Keep old private keys for older vaults/files/packets.";
                if (!string.IsNullOrWhiteSpace(stdout))
                    txtSettingsKeys.Text += Environment.NewLine + Environment.NewLine + stdout.Trim();
                TryAutoLoadDefaultKeyPath(force: true);
                TryAutoLoadVaultKeyPath(force: true);
                RefreshMyPublicKeyText();
                await Kx2RefreshMyPublicKeyAsync();
            }
            finally
            {
                btnSettingsGenerate.Enabled = true;
            }
        };
        btnSettingsBackup.Click += (_, _) =>
        {
            try
            {
                if (!TryResolveLatestLocalKeypair(out var pubPath, out var privPath, out var resolveNote))
                {
                    MessageBox.Show(
                        this,
                        "No local keypair was found to back up.\n\nGenerate or restore a keypair first.",
                        "Backup Local Keypair",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Information);
                    return;
                }

                string stamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
                using var save = new SaveFileDialog
                {
                    Title = "Backup Local Keypair",
                    Filter = "ObsidianQ key backup (*.obsqkeys)|*.obsqkeys|Zip archive (*.zip)|*.zip|All files (*.*)|*.*",
                    FileName = $"obsidianq_keypair_backup_{stamp}.obsqkeys",
                    AddExtension = true,
                    DefaultExt = "obsqkeys",
                    OverwritePrompt = true,
                };
                if (save.ShowDialog(this) != DialogResult.OK) return;

                using (var fs = new FileStream(save.FileName, FileMode.Create, FileAccess.Write, FileShare.None))
                using (var zip = new ZipArchive(fs, ZipArchiveMode.Create))
                {
                    zip.CreateEntryFromFile(pubPath, Path.GetFileName(pubPath), CompressionLevel.Optimal);
                    zip.CreateEntryFromFile(privPath, Path.GetFileName(privPath), CompressionLevel.Optimal);
                    var meta = zip.CreateEntry("backup_info.txt", CompressionLevel.Optimal);
                    using var sw = new StreamWriter(meta.Open(), Encoding.UTF8);
                    sw.WriteLine("ObsidianQ Local Keypair Backup");
                    sw.WriteLine($"CreatedUtc: {DateTime.UtcNow:O}");
                    sw.WriteLine($"PublicKey: {Path.GetFileName(pubPath)}");
                    sw.WriteLine($"PrivateKey: {Path.GetFileName(privPath)}");
                    if (!string.IsNullOrWhiteSpace(resolveNote))
                        sw.WriteLine($"Note: {resolveNote}");
                }

                txtSettingsKeys.Text =
                    $"Backup created: {save.FileName}{Environment.NewLine}" +
                    $"Public Key:  {pubPath}{Environment.NewLine}" +
                    $"Private Key: {privPath}";
                MessageBox.Show(this, "Local keypair backup created.", "Backup Local Keypair", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, $"Backup failed:\n{ex.Message}", "Backup Local Keypair", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        };
        btnSettingsRestore.Click += async (_, _) =>
        {
            try
            {
                using var open = new OpenFileDialog
                {
                    Title = "Restore Local Keypair Backup",
                    Filter = "ObsidianQ key backup (*.obsqkeys;*.zip)|*.obsqkeys;*.zip|All files (*.*)|*.*",
                    CheckFileExists = true,
                    Multiselect = false,
                };
                if (open.ShowDialog(this) != DialogResult.OK) return;

                string keysDir = EnsureDefaultKeyDir();
                using var fs = new FileStream(open.FileName, FileMode.Open, FileAccess.Read, FileShare.Read);
                using var zip = new ZipArchive(fs, ZipArchiveMode.Read);
                var keyEntries = zip.Entries
                    .Where(e => !string.IsNullOrWhiteSpace(e.Name))
                    .Where(e => e.Name.StartsWith("obsidianq", StringComparison.OrdinalIgnoreCase))
                    .Where(e =>
                        e.Name.EndsWith(".bin", StringComparison.OrdinalIgnoreCase)
                        || e.Name.EndsWith(".pem", StringComparison.OrdinalIgnoreCase))
                    .ToList();

                var pubEntry = keyEntries
                    .Where(e => IsPublicKeyName(e.Name))
                    .OrderByDescending(e => e.LastWriteTime.UtcDateTime)
                    .ThenByDescending(e => e.Length)
                    .FirstOrDefault();
                var privEntry = keyEntries
                    .Where(e => IsPrivateKeyName(e.Name))
                    .OrderByDescending(e => e.LastWriteTime.UtcDateTime)
                    .ThenByDescending(e => e.Length)
                    .FirstOrDefault();

                if (pubEntry == null || privEntry == null)
                {
                    MessageBox.Show(
                        this,
                        "Backup does not contain a recognizable public/private keypair.",
                        "Restore Local Keypair",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Error);
                    return;
                }

                string stamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
                string pubExt = Path.GetExtension(pubEntry.Name);
                string privExt = Path.GetExtension(privEntry.Name);
                if (string.IsNullOrWhiteSpace(pubExt)) pubExt = ".bin";
                if (string.IsNullOrWhiteSpace(privExt)) privExt = ".bin";
                string pubOut = Path.Combine(keysDir, $"obsidianq_restore_{stamp}_pub{pubExt}");
                string privOut = Path.Combine(keysDir, $"obsidianq_restore_{stamp}_priv{privExt}");
                int suffix = 1;
                while (File.Exists(pubOut) || File.Exists(privOut))
                {
                    pubOut = Path.Combine(keysDir, $"obsidianq_restore_{stamp}_{suffix:00}_pub{pubExt}");
                    privOut = Path.Combine(keysDir, $"obsidianq_restore_{stamp}_{suffix:00}_priv{privExt}");
                    suffix++;
                }

                using (var src = pubEntry.Open())
                using (var dst = new FileStream(pubOut, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                    src.CopyTo(dst);
                using (var src = privEntry.Open())
                using (var dst = new FileStream(privOut, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                    src.CopyTo(dst);

                TryAutoLoadDefaultKeyPath(force: true);
                TryAutoLoadTextKeyPath(force: true);
                TryAutoLoadVaultKeyPath(force: true);
                RefreshMyPublicKeyText();
                await Kx2RefreshMyPublicKeyAsync();

                txtSettingsKeys.Text =
                    $"Restored keypair from: {open.FileName}{Environment.NewLine}" +
                    $"Public Key:  {pubOut}{Environment.NewLine}" +
                    $"Private Key: {privOut}{Environment.NewLine}{Environment.NewLine}" +
                    "Keys were restored into your local key directory.";
                MessageBox.Show(this, "Local keypair restored.", "Restore Local Keypair", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, $"Restore failed:\n{ex.Message}", "Restore Local Keypair", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        };

        var settingsKeypairOpsRow = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 1,
            BackColor = Theme.Bg,
            Margin = new Padding(0),
        };
        settingsKeypairOpsRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        settingsKeypairOpsRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        settingsKeypairOpsRow.Controls.Add(btnSettingsBackup, 0, 0);
        settingsKeypairOpsRow.Controls.Add(btnSettingsRestore, 1, 0);

        void PromptFirstRunKeypairSetupIfNeeded()
        {
            if (GetFirstRunKeypairPrompted()) return;
            SetFirstRunKeypairPrompted(true); // one-time first-run prompt

            if (TryResolveLatestLocalKeypair(out _, out _, out _)) return;

            var result = MessageBox.Show(
                this,
                "No local keypair was found for Secure Contacts.\n\n" +
                "Yes = Generate a new local keypair now\n" +
                "No = Restore a keypair backup\n" +
                "Cancel = Continue for now",
                "Set Up Local Keypair",
                MessageBoxButtons.YesNoCancel,
                MessageBoxIcon.Information,
                MessageBoxDefaultButton.Button1);
            if (result == DialogResult.Yes)
            {
                _tabs.SelectedIndex = 6; // Settings
                btnSettingsGenerate.PerformClick();
            }
            else if (result == DialogResult.No)
            {
                _tabs.SelectedIndex = 6; // Settings
                btnSettingsRestore.PerformClick();
            }
        }

        var settingsIntegrationRow = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 1,
            BackColor = Theme.Bg,
            Margin = new Padding(0),
        };
        settingsIntegrationRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        settingsIntegrationRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        var btnSettingsInstallIntegration = new NeonButton
        {
            Text = "INSTALL SHELL INTEGRATION",
            Dock = DockStyle.Fill,
            Margin = new Padding(0, 2, 4, 2)
        };
        var btnSettingsUninstallIntegration = new NeonButton
        {
            Text = "UNINSTALL SHELL INTEGRATION",
            Dock = DockStyle.Fill,
            Margin = new Padding(4, 2, 0, 2)
        };
        btnSettingsInstallIntegration.Click += (_, _) =>
        {
            try
            {
                InstallShellAndAssociations();
                SetSkipShellSetupPrompt(true);
                MessageBox.Show(
                    "Shell integration installed.\n\nContext menus, file associations, and Explorer New entry were updated.",
                    "Integration installed",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"Failed to install shell integration:\n{ex.Message}",
                    "Install failed",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
            }
        };
        btnSettingsUninstallIntegration.Click += (_, _) =>
        {
            var confirm = MessageBox.Show(
                "Remove ObsidianQ shell entries and file associations for this user?",
                "Uninstall Integration",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button2);
            if (confirm != DialogResult.Yes) return;
            try
            {
                UninstallShellAndAssociations();
                SetSkipShellSetupPrompt(false);
                MessageBox.Show(
                    "Shell integration removed for current user.",
                    "Integration removed",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"Failed to uninstall shell integration:\n{ex.Message}",
                    "Uninstall failed",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
            }
        };
        settingsIntegrationRow.Controls.Add(btnSettingsInstallIntegration, 0, 0);
        settingsIntegrationRow.Controls.Add(btnSettingsUninstallIntegration, 1, 0);

        var outerSettings = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 5,
            Padding = new Padding(16),
            BackColor = Theme.Bg,
        };
        outerSettings.RowStyles.Add(new RowStyle(SizeType.Absolute, 52));
        outerSettings.RowStyles.Add(new RowStyle(SizeType.Absolute, 42));
        outerSettings.RowStyles.Add(new RowStyle(SizeType.Absolute, 42));
        outerSettings.RowStyles.Add(new RowStyle(SizeType.Absolute, 42));
        outerSettings.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        outerSettings.Controls.Add(MakeTabHeader(
            "SETTINGS",
            "Manage local keys, backups, and shell integration."), 0, 0);
        outerSettings.Controls.Add(btnSettingsGenerate, 0, 1);
        outerSettings.Controls.Add(settingsKeypairOpsRow, 0, 2);
        outerSettings.Controls.Add(settingsIntegrationRow, 0, 3);
        outerSettings.Controls.Add(txtSettingsKeys, 0, 4);

        // ==================================================================
        // ABOUT TAB - product overview and usage guide
        // ==================================================================
        var aboutWrapLabels = new List<Label>();
        var aboutScroll = new Panel
        {
            Dock = DockStyle.Fill,
            AutoScroll = true,
            BackColor = Theme.Bg,
            Padding = new Padding(0, 0, 4, 0),
        };
        var aboutStack = new TableLayoutPanel
        {
            Dock = DockStyle.Top,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            ColumnCount = 1,
            RowCount = 0,
            BackColor = Theme.Bg,
            Margin = new Padding(0),
            Padding = new Padding(0),
        };
        aboutStack.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

        Label MakeAboutText(string text, float size = 9f, bool bold = false, Color? color = null)
        {
            var lbl = MakeLabel(text, size, bold: bold);
            lbl.AutoSize = true;
            lbl.Margin = new Padding(0, 0, 0, 8);
            lbl.ForeColor = color ?? Theme.TextMain;
            aboutWrapLabels.Add(lbl);
            return lbl;
        }

        Panel MakeAboutCard(string title)
        {
            var card = new Panel
            {
                Dock = DockStyle.Top,
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                BackColor = Theme.Surface,
                Margin = new Padding(0, 0, 0, 12),
                Padding = new Padding(14, 12, 14, 10),
            };
            card.Paint += (_, pe) =>
            {
                using var pen = new Pen(Color.FromArgb(140, Theme.Border), 1f);
                pe.Graphics.DrawRectangle(pen, 0, 0, card.Width - 1, card.Height - 1);
            };

            var content = new TableLayoutPanel
            {
                Dock = DockStyle.Top,
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                ColumnCount = 1,
                RowCount = 0,
                BackColor = Color.Transparent,
                Margin = new Padding(0),
                Padding = new Padding(0),
            };
            content.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

            var header = MakeAboutText(title, 9.75f, bold: true, color: Theme.Accent);
            header.Margin = new Padding(0, 0, 0, 10);
            content.Controls.Add(header);
            card.Controls.Add(content);
            return card;
        }

        void AddAboutParagraph(Panel card, string text, bool muted = false)
        {
            if (card.Controls.Count == 0 || card.Controls[0] is not TableLayoutPanel t) return;
            var lbl = MakeAboutText(text, 9f, bold: false, color: muted ? Theme.TextDim : Theme.TextMain);
            t.Controls.Add(lbl);
        }

        void AddAboutBullet(Panel card, string text)
        {
            AddAboutParagraph(card, $"- {text}");
        }

        var cardIntro = MakeAboutCard("About ObsidianQ");
        AddAboutParagraph(cardIntro, "Secure file encryption for the modern era.");
        AddAboutParagraph(cardIntro, "ObsidianQ is a high-performance encryption tool designed to make strong file protection simple and approachable. It combines modern cryptography, trusted contact workflows, and secure vault features in a clean desktop interface.");

        var cardSecurity = MakeAboutCard("Security Architecture");
        AddAboutParagraph(cardSecurity, "ObsidianQ is built around modern, well-established cryptographic components chosen for strong security and practical performance.");
        AddAboutBullet(cardSecurity, "Post-Quantum Key Exchange: ML-KEM-768 (Kyber) for quantum-resistant public-key protection");
        AddAboutBullet(cardSecurity, "Authenticated Encryption: XChaCha20-Poly1305 for confidentiality and integrity");
        AddAboutBullet(cardSecurity, "Password Hardening: Argon2id for strong password-based protection");
        AddAboutBullet(cardSecurity, "Hashing and Fingerprints: BLAKE3 for fast, modern hashing and identity fingerprints");
        AddAboutBullet(cardSecurity, "Chunked Encryption Engine: designed for strong integrity and efficient large-file handling");

        var cardPerf = MakeAboutCard("Performance");
        AddAboutParagraph(cardPerf, "ObsidianQ is designed to handle large files efficiently using a chunked encryption pipeline optimized for modern systems.");
        AddAboutBullet(cardPerf, "Typical encryption performance on modern hardware can reach approximately 1.2-1.4 GB/s");
        AddAboutBullet(cardPerf, "Typical decryption performance may vary depending on workflow, storage, and mount mode");
        AddAboutBullet(cardPerf, "Real-world performance depends on hardware, storage speed, and file size");

        var cardQuickStart = MakeAboutCard("Quick Start");
        AddAboutParagraph(cardQuickStart, "1. Set up your identity in Secure Contacts");
        AddAboutParagraph(cardQuickStart, "2. Add trusted contacts or choose password-based protection");
        AddAboutParagraph(cardQuickStart, "3. Encrypt files, protect text, inspect packages, or work in a secure vault");

        var cardTabs = MakeAboutCard("Tabs Overview");
        AddAboutBullet(cardTabs, "File: Encrypt and decrypt files using a password or trusted contact keys.");
        AddAboutBullet(cardTabs, "Text: Protect short text, clipboard content, or pasted ciphertext.");
        AddAboutBullet(cardTabs, "Vault: Create and mount encrypted vaults for working with protected files.");
        AddAboutBullet(cardTabs, "Inspect: Review encrypted packages and view supported metadata without decrypting them.");
        AddAboutBullet(cardTabs, "Secure Contacts: Manage your identity and trusted contacts for secure file exchange.");
        AddAboutBullet(cardTabs, "Settings: Configure application behavior, paths, and preferences.");
        AddAboutBullet(cardTabs, "About: View security information, guidance, and version details.");

        var cardPrivacy = MakeAboutCard("Privacy & Trust Model");
        AddAboutParagraph(cardPrivacy, "ObsidianQ follows a local-first trust model.");
        AddAboutBullet(cardPrivacy, "Encryption and decryption happen locally on your machine");
        AddAboutBullet(cardPrivacy, "Private keys remain under your control");
        AddAboutBullet(cardPrivacy, "Public identities are exchanged directly between users");
        AddAboutBullet(cardPrivacy, "No external cloud service or key server is required");

        var cardBest = MakeAboutCard("Best Practices");
        AddAboutBullet(cardBest, "Verify fingerprints before trusting a new contact");
        AddAboutBullet(cardBest, "Keep private keys backed up and protected");
        AddAboutBullet(cardBest, "Use strong passwords for password-based encryption");
        AddAboutBullet(cardBest, "Store recovery material securely");
        AddAboutBullet(cardBest, "Keep the application updated when new releases are available");

        var cardVersion = MakeAboutCard("Version");
        AddAboutParagraph(cardVersion, "ObsidianQ Version: 1.0");
        AddAboutParagraph(cardVersion, "Built for secure, high-performance encryption and post-quantum readiness");
        AddAboutParagraph(cardVersion, "Local-first security | Modern cryptography | Trusted file exchange", muted: true);

        aboutStack.Controls.Add(cardIntro);
        aboutStack.Controls.Add(cardSecurity);
        aboutStack.Controls.Add(cardPerf);
        aboutStack.Controls.Add(cardQuickStart);
        aboutStack.Controls.Add(cardTabs);
        aboutStack.Controls.Add(cardPrivacy);
        aboutStack.Controls.Add(cardBest);
        aboutStack.Controls.Add(cardVersion);
        aboutScroll.Controls.Add(aboutStack);

        void RefreshAboutLayout()
        {
            int width = Math.Max(280, aboutScroll.ClientSize.Width - (aboutScroll.VerticalScroll.Visible ? SystemInformation.VerticalScrollBarWidth : 0) - 6);
            aboutStack.Width = width;
            foreach (Control c in aboutStack.Controls)
                c.Width = width;
            int wrap = Math.Max(220, width - 34);
            foreach (var lbl in aboutWrapLabels)
                lbl.MaximumSize = new Size(wrap, 0);
        }
        aboutScroll.Resize += (_, _) => RefreshAboutLayout();

        var outerAbout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 1,
            Padding = new Padding(16),
            BackColor = Theme.Bg,
        };
        outerAbout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        outerAbout.Controls.Add(aboutScroll, 0, 0);
        outerAbout.HandleCreated += (_, _) => BeginInvoke(new Action(RefreshAboutLayout));

        // ==================================================================
        // INSPECT TAB - auto-detect container metadata for .obsq/.vault
        // ==================================================================
        var inspectDrop = new DropZonePanel
        {
            Dock = DockStyle.Fill,
            Margin = new Padding(0, 2, 0, 2),
            Filter = "Supported containers|*.obsq;*.vault;*.obsqv;*.zip;*.exe|ObsidianQ files|*.obsq|Vault files|*.vault;*.obsqv|Self-Extracting Package|*_SecureDelivery.zip;*.zip;*_SecureDelivery.exe;*.exe|All files|*.*",
        };
        var txtInspectPath = MakeTextBox();
        txtInspectPath.ReadOnly = true;
        txtInspectPath.PlaceholderText = "Drop or browse a container file (.obsq, .vault, .obsqv, .zip, .exe)";
        var lblInspectTypeVal = MakeLabel("-", 8.5f); lblInspectTypeVal.ForeColor = Theme.Accent; lblInspectTypeVal.Dock = DockStyle.Fill;
        var lblInspectModeVal = MakeLabel("-", 8.5f); lblInspectModeVal.ForeColor = Theme.Accent; lblInspectModeVal.Dock = DockStyle.Fill;
        var lblInspectVersionVal = MakeLabel("-", 8.5f); lblInspectVersionVal.ForeColor = Theme.Accent; lblInspectVersionVal.Dock = DockStyle.Fill;
        var lblInspectSizeVal = MakeLabel("-", 8.5f); lblInspectSizeVal.ForeColor = Theme.Accent; lblInspectSizeVal.Dock = DockStyle.Fill;
        var lblInspectStatus = MakeLabel("READY", 8.5f); lblInspectStatus.ForeColor = Theme.Accent; lblInspectStatus.Dock = DockStyle.Fill;
        var rtbInspect = new RichTextBox
        {
            Dock = DockStyle.Fill,
            ReadOnly = true,
            WordWrap = false,
            BackColor = Theme.LogBg,
            ForeColor = Theme.TextMain,
            BorderStyle = BorderStyle.None,
            ScrollBars = RichTextBoxScrollBars.Both,
            Font = Theme.SafeMono(8.5f),
        };
        rtbInspect.HandleCreated += (_, _) => SetWindowTheme(rtbInspect.Handle, "DarkMode_Explorer", null);

        static bool StartsWithSig(byte[] data, int n, byte[] sig)
        {
            if (n < sig.Length) return false;
            for (int i = 0; i < sig.Length; i++) if (data[i] != sig[i]) return false;
            return true;
        }
        void InspectStatus(string text, bool error = false)
        {
            lblInspectStatus.ForeColor = error ? Theme.Error : Theme.Accent;
            lblInspectStatus.Text = text;
        }
        void ResetInspect()
        {
            lblInspectTypeVal.Text = "-";
            lblInspectModeVal.Text = "-";
            lblInspectVersionVal.Text = "-";
            lblInspectSizeVal.Text = "-";
            rtbInspect.Clear();
        }
        async Task<(int ExitCode, string Stdout, string Stderr)> RunInspectCliAsync(string args)
        {
            var psi = new ProcessStartInfo
            {
                FileName = ExePath,
                Arguments = args,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var proc = new Process { StartInfo = psi };
            proc.Start();
            string stdout = await proc.StandardOutput.ReadToEndAsync();
            string stderr = await proc.StandardError.ReadToEndAsync();
            await proc.WaitForExitAsync();
            return (proc.ExitCode, stdout, stderr);
        }
        async Task InspectPathAsync(string path)
        {
            const string inspectSfxMagic = "OBSQSFX1";
            const int inspectSfxTrailerSize = 24;

            bool TryGetEmbeddedSfxInfoForInspect(string hostExePath, out long packageOffset, out long packageLength, out long cliOffset, out long cliLength)
            {
                packageOffset = packageLength = cliOffset = cliLength = 0;
                try
                {
                    using var fs = new FileStream(hostExePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    if (fs.Length <= inspectSfxTrailerSize) return false;
                    fs.Seek(-inspectSfxTrailerSize, SeekOrigin.End);
                    Span<byte> trailer = stackalloc byte[inspectSfxTrailerSize];
                    int got = fs.Read(trailer);
                    if (got != inspectSfxTrailerSize) return false;

                    string magic = Encoding.ASCII.GetString(trailer.Slice(16, 8));
                    if (!string.Equals(magic, inspectSfxMagic, StringComparison.Ordinal)) return false;

                    long pkgLen = BitConverter.ToInt64(trailer.Slice(0, 8));
                    long cLen = BitConverter.ToInt64(trailer.Slice(8, 8));
                    if (pkgLen <= 0 || cLen <= 0) return false;

                    long payloadStart = fs.Length - inspectSfxTrailerSize - pkgLen - cLen;
                    if (payloadStart < 0) return false;
                    long cOff = payloadStart + pkgLen;
                    if (cOff < 0 || cOff + cLen > fs.Length) return false;

                    packageOffset = payloadStart;
                    packageLength = pkgLen;
                    cliOffset = cOff;
                    cliLength = cLen;
                    return true;
                }
                catch
                {
                    return false;
                }
            }

            bool TryExtractEmbeddedPackageZip(string hostExePath, long packageOffset, long packageLength, out string tempZipPath)
            {
                tempZipPath = string.Empty;
                try
                {
                    string tempDir = Path.Combine(Path.GetTempPath(), "ObsidianQ", "inspect");
                    Directory.CreateDirectory(tempDir);
                    tempZipPath = Path.Combine(tempDir, $"inspect_{Guid.NewGuid():N}.zip");

                    using var src = new FileStream(hostExePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var dst = new FileStream(tempZipPath, FileMode.Create, FileAccess.Write, FileShare.None);
                    src.Seek(packageOffset, SeekOrigin.Begin);

                    byte[] buf = new byte[128 * 1024];
                    long remain = packageLength;
                    while (remain > 0)
                    {
                        int want = (int)Math.Min(buf.Length, remain);
                        int n = src.Read(buf, 0, want);
                        if (n <= 0) break;
                        dst.Write(buf, 0, n);
                        remain -= n;
                    }
                    dst.Flush();
                    return remain == 0 && File.Exists(tempZipPath);
                }
                catch
                {
                    try { if (!string.IsNullOrWhiteSpace(tempZipPath) && File.Exists(tempZipPath)) File.Delete(tempZipPath); } catch { }
                    tempZipPath = string.Empty;
                    return false;
                }
            }

            bool TryExtractZipEntryToTempFile(string zipPath, string entryName, string tempExtension, out string tempFilePath)
            {
                tempFilePath = string.Empty;
                try
                {
                    using var zf = ZipFile.OpenRead(zipPath);
                    var entry = zf.Entries.FirstOrDefault(e =>
                        string.Equals(e.FullName, entryName, StringComparison.OrdinalIgnoreCase));
                    if (entry == null) return false;

                    string tempDir = Path.Combine(Path.GetTempPath(), "ObsidianQ", "inspect");
                    Directory.CreateDirectory(tempDir);
                    tempFilePath = Path.Combine(tempDir, $"inspect_{Guid.NewGuid():N}{tempExtension}");

                    using var src = entry.Open();
                    using var dst = new FileStream(tempFilePath, FileMode.Create, FileAccess.Write, FileShare.None);
                    src.CopyTo(dst);
                    dst.Flush();
                    return File.Exists(tempFilePath);
                }
                catch
                {
                    try { if (!string.IsNullOrWhiteSpace(tempFilePath) && File.Exists(tempFilePath)) File.Delete(tempFilePath); } catch { }
                    tempFilePath = string.Empty;
                    return false;
                }
            }

            ResetInspect();
            txtInspectPath.Text = path;
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            {
                InspectStatus("File not found.", error: true);
                return;
            }

            byte[] head = new byte[64];
            int n = 0;
            try
            {
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                n = fs.Read(head, 0, head.Length);
            }
            catch (Exception ex)
            {
                InspectStatus($"Read failed: {ex.Message}", error: true);
                return;
            }

            long size = 0;
            DateTime modified = DateTime.MinValue;
            try
            {
                var fi = new FileInfo(path);
                size = fi.Length;
                modified = fi.LastWriteTime;
            }
            catch { /* best effort */ }
            lblInspectSizeVal.Text = $"{FormatBytes(size)}  ({size} bytes)";

            bool isVaultMagic = StartsWithSig(head, n, Encoding.ASCII.GetBytes("OBSQVAULT"))
                || StartsWithSig(head, n, Encoding.ASCII.GetBytes("OBSQV"))
                || StartsWithSig(head, n, Encoding.ASCII.GetBytes("OBSV"));
            bool isObsqMagic = StartsWithSig(head, n, Encoding.ASCII.GetBytes("OBSQ"));
            bool isZip = string.Equals(Path.GetExtension(path), ".zip", StringComparison.OrdinalIgnoreCase);
            bool isExe = string.Equals(Path.GetExtension(path), ".exe", StringComparison.OrdinalIgnoreCase);

            var sb = new StringBuilder();
            sb.AppendLine($"Path: {path}");
            sb.AppendLine($"Modified: {(modified == DateTime.MinValue ? "-" : modified.ToString("yyyy-MM-dd HH:mm:ss"))}");

            if (isExe && TryGetEmbeddedSfxInfoForInspect(path, out var pkgOff, out var pkgLen, out _, out _))
            {
                lblInspectTypeVal.Text = "Self-Extracting Package (EXE)";
                lblInspectModeVal.Text = "Password";

                string? tempZip = null;
                try
                {
                    if (!TryExtractEmbeddedPackageZip(path, pkgOff, pkgLen, out var extractedZip))
                    {
                        lblInspectVersionVal.Text = "Unknown";
                        sb.AppendLine("Container: Self-Extracting Package (EXE)");
                        sb.AppendLine("Embedded package: detected");
                        sb.AppendLine("Inspect detail: failed to extract embedded package segment.");
                        rtbInspect.Text = sb.ToString();
                        InspectStatus("Detected SFX EXE, but failed to read embedded package.", error: true);
                        return;
                    }
                    tempZip = extractedZip;

                    var (dCode, dStdout, dStderr) = await RunInspectCliAsync($"delivery inspect --json \"{tempZip}\"");
                    if (!string.IsNullOrWhiteSpace(dStderr))
                        sb.AppendLine($"Inspect stderr: {dStderr.TrimEnd()}");

                    string schema = "Unknown";
                    string packageName = Path.GetFileNameWithoutExtension(path);
                    string packageFormat = "secure_delivery_zip";
                    string itemCount = "Unknown";
                    string totalBytes = "Unknown";
                    string hash = "Unknown";
                    string instructions = "Unknown";

                    if (dCode == 0 && !string.IsNullOrWhiteSpace(dStdout))
                    {
                        try
                        {
                            using var doc = JsonDocument.Parse(dStdout);
                            if (doc.RootElement.TryGetProperty("data", out var data))
                            {
                                if (data.TryGetProperty("schema_version", out var sv)) schema = sv.GetRawText();
                                if (data.TryGetProperty("package_name", out var pn)) packageName = pn.GetString() ?? packageName;
                                if (data.TryGetProperty("package_format", out var pf)) packageFormat = pf.GetString() ?? packageFormat;
                                if (data.TryGetProperty("source_item_count", out var ic)) itemCount = ic.GetRawText();
                                if (data.TryGetProperty("source_total_bytes", out var tb)) totalBytes = tb.GetRawText();
                                if (data.TryGetProperty("payload_sha256", out var hs)) hash = hs.GetString() ?? hash;
                                if (data.TryGetProperty("has_instructions", out var hi)) instructions = hi.GetRawText();
                            }
                        }
                        catch { }
                    }

                    lblInspectVersionVal.Text = schema;
                    sb.AppendLine("Container: Self-Extracting Package (EXE)");
                    sb.AppendLine($"Schema version: {schema}");
                    sb.AppendLine($"Package name: {packageName}");
                    sb.AppendLine($"Package format: {packageFormat}");
                    sb.AppendLine($"Source item count: {itemCount}");
                    sb.AppendLine($"Source total bytes: {totalBytes}");
                    sb.AppendLine($"Has instructions: {instructions}");
                    sb.AppendLine($"Payload SHA-256: {hash}");
                    sb.AppendLine();

                    var (vCode, vStdout, vStderr) = await RunInspectCliAsync($"delivery verify --json \"{tempZip}\"");
                    if (vCode == 0)
                    {
                        sb.AppendLine("Integrity: VERIFIED");
                        InspectStatus("Self-Extracting EXE package verified.");
                    }
                    else
                    {
                        string verifyErr = !string.IsNullOrWhiteSpace(vStderr) ? vStderr.TrimEnd() : "verification failed";
                        try
                        {
                            using var vdoc = JsonDocument.Parse(vStdout);
                            if (vdoc.RootElement.TryGetProperty("error", out var err) &&
                                err.TryGetProperty("message", out var msg))
                                verifyErr = msg.GetString() ?? verifyErr;
                        }
                        catch { }
                        sb.AppendLine($"Integrity: FAILED ({verifyErr})");
                        InspectStatus("Self-Extracting EXE package verification failed.", error: true);
                    }

                    rtbInspect.Text = sb.ToString();
                    return;
                }
                finally
                {
                    try { if (!string.IsNullOrWhiteSpace(tempZip) && File.Exists(tempZip)) File.Delete(tempZip); } catch { }
                }
            }

            if (isZip)
            {
                bool looksLikeDelivery = false;
                bool looksLikeWrappedExe = false;
                try
                {
                    using var zf = ZipFile.OpenRead(path);
                    looksLikeDelivery = zf.Entries.Any(e =>
                        string.Equals(e.FullName, "secure_delivery_manifest.json", StringComparison.OrdinalIgnoreCase));
                    looksLikeWrappedExe = zf.Entries.Any(e =>
                        string.Equals(Path.GetFileName(e.FullName), "Click_Here_to_Decrypt.exe", StringComparison.OrdinalIgnoreCase));
                }
                catch { /* not a valid zip or inaccessible */ }

                if (looksLikeDelivery)
                {
                    lblInspectTypeVal.Text = "Self-Extracting Package";
                    lblInspectModeVal.Text = "Password";

                    var (dCode, dStdout, dStderr) = await RunInspectCliAsync($"delivery inspect --json \"{path}\"");
                    if (!string.IsNullOrWhiteSpace(dStderr))
                        sb.AppendLine($"Inspect stderr: {dStderr.TrimEnd()}");

                    string schema = "Unknown";
                    string packageName = Path.GetFileNameWithoutExtension(path);
                    string packageFormat = "secure_delivery_zip";
                    string itemCount = "Unknown";
                    string totalBytes = "Unknown";
                    string hash = "Unknown";
                    string instructions = "Unknown";

                    if (dCode == 0 && !string.IsNullOrWhiteSpace(dStdout))
                    {
                        try
                        {
                            using var doc = JsonDocument.Parse(dStdout);
                            if (doc.RootElement.TryGetProperty("data", out var data))
                            {
                                if (data.TryGetProperty("schema_version", out var sv)) schema = sv.GetRawText();
                                if (data.TryGetProperty("package_name", out var pn)) packageName = pn.GetString() ?? packageName;
                                if (data.TryGetProperty("package_format", out var pf)) packageFormat = pf.GetString() ?? packageFormat;
                                if (data.TryGetProperty("source_item_count", out var ic)) itemCount = ic.GetRawText();
                                if (data.TryGetProperty("source_total_bytes", out var tb)) totalBytes = tb.GetRawText();
                                if (data.TryGetProperty("payload_sha256", out var hs)) hash = hs.GetString() ?? hash;
                                if (data.TryGetProperty("has_instructions", out var hi)) instructions = hi.GetRawText();
                            }
                        }
                        catch { /* leave defaults */ }
                    }

                    lblInspectVersionVal.Text = schema;
                    sb.AppendLine("Container: Self-Extracting Package");
                    sb.AppendLine($"Schema version: {schema}");
                    sb.AppendLine($"Package name: {packageName}");
                    sb.AppendLine($"Package format: {packageFormat}");
                    sb.AppendLine($"Source item count: {itemCount}");
                    sb.AppendLine($"Source total bytes: {totalBytes}");
                    sb.AppendLine($"Has instructions: {instructions}");
                    sb.AppendLine($"Payload SHA-256: {hash}");
                    sb.AppendLine();

                    var (vCode, vStdout, vStderr) = await RunInspectCliAsync($"delivery verify --json \"{path}\"");
                    if (vCode == 0)
                    {
                        sb.AppendLine("Integrity: VERIFIED");
                        InspectStatus("Self-Extracting package verified.");
                    }
                    else
                    {
                        string verifyErr = !string.IsNullOrWhiteSpace(vStderr) ? vStderr.TrimEnd() : "verification failed";
                        try
                        {
                            using var vdoc = JsonDocument.Parse(vStdout);
                            if (vdoc.RootElement.TryGetProperty("error", out var err) &&
                                err.TryGetProperty("message", out var msg))
                                verifyErr = msg.GetString() ?? verifyErr;
                        }
                        catch { /* keep stderr fallback */ }
                        sb.AppendLine($"Integrity: FAILED ({verifyErr})");
                        InspectStatus("Self-Extracting package verification failed.", error: true);
                    }

                    rtbInspect.Text = sb.ToString();
                    return;
                }

                if (looksLikeWrappedExe)
                {
                    string? tempExe = null;
                    string? tempZip = null;
                    try
                    {
                        if (!TryExtractZipEntryToTempFile(path, "Click_Here_to_Decrypt.exe", ".exe", out var extractedExe))
                        {
                            lblInspectTypeVal.Text = "Self-Extracting Package (ZIP)";
                            lblInspectModeVal.Text = "Password";
                            lblInspectVersionVal.Text = "Unknown";
                            sb.AppendLine("Container: Self-Extracting Package (ZIP)");
                            sb.AppendLine("Embedded launcher: detected");
                            sb.AppendLine("Inspect detail: failed to extract Click_Here_to_Decrypt.exe from archive.");
                            rtbInspect.Text = sb.ToString();
                            InspectStatus("Detected wrapped SFX ZIP, but failed to read embedded launcher.", error: true);
                            return;
                        }
                        tempExe = extractedExe;

                        if (!TryGetEmbeddedSfxInfoForInspect(tempExe, out var wrappedPkgOff, out var wrappedPkgLen, out _, out _))
                        {
                            lblInspectTypeVal.Text = "Self-Extracting Package (ZIP)";
                            lblInspectModeVal.Text = "Password";
                            lblInspectVersionVal.Text = "Unknown";
                            sb.AppendLine("Container: Self-Extracting Package (ZIP)");
                            sb.AppendLine("Embedded launcher: present");
                            sb.AppendLine("Inspect detail: launcher does not contain an embedded ObsidianQ package.");
                            rtbInspect.Text = sb.ToString();
                            InspectStatus("Wrapped SFX ZIP found, but the embedded launcher was not a valid package.", error: true);
                            return;
                        }

                        if (!TryExtractEmbeddedPackageZip(tempExe, wrappedPkgOff, wrappedPkgLen, out var extractedZip))
                        {
                            lblInspectTypeVal.Text = "Self-Extracting Package (ZIP)";
                            lblInspectModeVal.Text = "Password";
                            lblInspectVersionVal.Text = "Unknown";
                            sb.AppendLine("Container: Self-Extracting Package (ZIP)");
                            sb.AppendLine("Embedded package: detected");
                            sb.AppendLine("Inspect detail: failed to extract embedded package segment from launcher.");
                            rtbInspect.Text = sb.ToString();
                            InspectStatus("Wrapped SFX ZIP found, but failed to extract the embedded package.", error: true);
                            return;
                        }
                        tempZip = extractedZip;

                        lblInspectTypeVal.Text = "Self-Extracting Package (ZIP)";
                        lblInspectModeVal.Text = "Password";

                        var (dCode, dStdout, dStderr) = await RunInspectCliAsync($"delivery inspect --json \"{tempZip}\"");
                        if (!string.IsNullOrWhiteSpace(dStderr))
                            sb.AppendLine($"Inspect stderr: {dStderr.TrimEnd()}");

                        string schema = "Unknown";
                        string packageName = Path.GetFileNameWithoutExtension(path).Replace("_SecureDelivery", "", StringComparison.OrdinalIgnoreCase);
                        string packageFormat = "secure_delivery_zip";
                        string itemCount = "Unknown";
                        string totalBytes = "Unknown";
                        string hash = "Unknown";
                        string instructions = "Unknown";

                        if (dCode == 0 && !string.IsNullOrWhiteSpace(dStdout))
                        {
                            try
                            {
                                using var doc = JsonDocument.Parse(dStdout);
                                if (doc.RootElement.TryGetProperty("data", out var data))
                                {
                                    if (data.TryGetProperty("schema_version", out var sv)) schema = sv.GetRawText();
                                    if (data.TryGetProperty("package_name", out var pn)) packageName = pn.GetString() ?? packageName;
                                    if (data.TryGetProperty("package_format", out var pf)) packageFormat = pf.GetString() ?? packageFormat;
                                    if (data.TryGetProperty("source_item_count", out var ic)) itemCount = ic.GetRawText();
                                    if (data.TryGetProperty("source_total_bytes", out var tb)) totalBytes = tb.GetRawText();
                                    if (data.TryGetProperty("payload_sha256", out var hs)) hash = hs.GetString() ?? hash;
                                    if (data.TryGetProperty("has_instructions", out var hi)) instructions = hi.GetRawText();
                                }
                            }
                            catch { /* leave defaults */ }
                        }

                        lblInspectVersionVal.Text = schema;
                        sb.AppendLine("Container: Self-Extracting Package (ZIP)");
                        sb.AppendLine($"Schema version: {schema}");
                        sb.AppendLine($"Package name: {packageName}");
                        sb.AppendLine($"Package format: {packageFormat}");
                        sb.AppendLine($"Source item count: {itemCount}");
                        sb.AppendLine($"Source total bytes: {totalBytes}");
                        sb.AppendLine($"Has instructions: {instructions}");
                        sb.AppendLine($"Payload SHA-256: {hash}");
                        sb.AppendLine();

                        var (vCode, vStdout, vStderr) = await RunInspectCliAsync($"delivery verify --json \"{tempZip}\"");
                        if (vCode == 0)
                        {
                            sb.AppendLine("Integrity: VERIFIED");
                            InspectStatus("Self-Extracting ZIP package verified.");
                        }
                        else
                        {
                            string verifyErr = !string.IsNullOrWhiteSpace(vStderr) ? vStderr.TrimEnd() : "verification failed";
                            try
                            {
                                using var vdoc = JsonDocument.Parse(vStdout);
                                if (vdoc.RootElement.TryGetProperty("error", out var err) &&
                                    err.TryGetProperty("message", out var msg))
                                    verifyErr = msg.GetString() ?? verifyErr;
                            }
                            catch { /* keep stderr fallback */ }
                            sb.AppendLine($"Integrity: FAILED ({verifyErr})");
                            InspectStatus("Self-Extracting ZIP package verification failed.", error: true);
                        }

                        rtbInspect.Text = sb.ToString();
                        return;
                    }
                    finally
                    {
                        try { if (!string.IsNullOrWhiteSpace(tempZip) && File.Exists(tempZip)) File.Delete(tempZip); } catch { }
                        try { if (!string.IsNullOrWhiteSpace(tempExe) && File.Exists(tempExe)) File.Delete(tempExe); } catch { }
                    }
                }
            }

            if (isVaultMagic || IsNativeVaultPath(path))
            {
                int magicLen = StartsWithSig(head, n, Encoding.ASCII.GetBytes("OBSQVAULT")) ? 9
                    : StartsWithSig(head, n, Encoding.ASCII.GetBytes("OBSQV")) ? 5
                    : StartsWithSig(head, n, Encoding.ASCII.GetBytes("OBSV")) ? 4
                    : 0;
                byte version = (magicLen > 0 && n > magicLen) ? head[magicLen] : (byte)0;
                var mode = DetectVaultAccessMode(path);
                lblInspectTypeVal.Text = "Vault Container";
                lblInspectModeVal.Text = mode switch
                {
                    VaultAccessModeHint.Password => "Password",
                    VaultAccessModeHint.Pqc => "PQC",
                    _ => "Unknown",
                };
                lblInspectVersionVal.Text = version == 0 ? "Unknown" : version.ToString();

                sb.AppendLine("Container: Vault");
                sb.AppendLine($"Magic: {(magicLen == 9 ? "OBSQVAULT" : magicLen == 5 ? "OBSQV" : magicLen == 4 ? "OBSV" : "Unknown")}");
                sb.AppendLine($"Version byte: {(version == 0 ? "Unknown" : version)}");
                sb.AppendLine($"Access mode: {lblInspectModeVal.Text}");
                sb.AppendLine();
                sb.AppendLine("Notes:");
                sb.AppendLine("- Header-only inspection (no password/private key required).");
                sb.AppendLine("- To validate full contents, load the vault in the VAULT tab.");
                rtbInspect.Text = sb.ToString();
                InspectStatus("Vault metadata detected.");
                return;
            }

            if (isObsqMagic)
            {
                byte version = n > 4 ? head[4] : (byte)0;
                var mode = DetectObsqAccessMode(path);
                lblInspectTypeVal.Text = "Encrypted File (.obsq)";
                lblInspectModeVal.Text = mode switch
                {
                    ContainerAccessModeHint.Password => "Password",
                    ContainerAccessModeHint.Pqc => "PQC",
                    _ => "Unknown",
                };
                lblInspectVersionVal.Text = version == 0 ? "Unknown" : version.ToString();

                sb.AppendLine("Container: Encrypted File (.obsq)");
                sb.AppendLine($"Version byte: {(version == 0 ? "Unknown" : version)}");
                sb.AppendLine($"Access mode: {lblInspectModeVal.Text}");
                sb.AppendLine();

                if (File.Exists(ExePath))
                {
                    var (code, stdout, stderr) = await RunInspectCliAsync($"inspect \"{path}\"");
                    if (!string.IsNullOrWhiteSpace(stdout))
                    {
                        sb.AppendLine("CLI Inspect Output:");
                        sb.AppendLine(stdout.TrimEnd());
                    }
                    if (!string.IsNullOrWhiteSpace(stderr))
                    {
                        sb.AppendLine();
                        sb.AppendLine("CLI Inspect Errors:");
                        sb.AppendLine(stderr.TrimEnd());
                    }
                    InspectStatus(code == 0 ? "Encrypted file metadata detected." : $"inspect exited with code {code}.");
                }
                else
                    InspectStatus("obsidianq.exe not found; showing header-only details.", error: true);

                rtbInspect.Text = sb.ToString();
                return;
            }

            lblInspectTypeVal.Text = "Unknown";
            lblInspectModeVal.Text = "Unknown";
            lblInspectVersionVal.Text = "Unknown";
            sb.AppendLine("Container: Unknown");
            sb.AppendLine();
            sb.AppendLine("Could not detect a recognized ObsidianQ container header.");
            rtbInspect.Text = sb.ToString();
            InspectStatus("Unknown container type.", error: true);
        }

        inspectDrop.FileDropped += async (_, p) => await InspectPathAsync(p);
        var btnInspectBrowse = new NeonButton { Text = "BROWSE", Dock = DockStyle.Fill, Margin = new Padding(3, 2, 0, 2) };
        btnInspectBrowse.Click += (_, _) =>
        {
            using var dlg = new OpenFileDialog
            {
                Title = "Select container to inspect",
                Filter = "Supported containers|*.obsq;*.vault;*.obsqv;*.zip;*.exe|All files|*.*",
            };
            if (dlg.ShowDialog(this) == DialogResult.OK)
                inspectDrop.SetFile(dlg.FileName);
        };
        var btnInspectRefresh = new NeonButton { Text = "REFRESH", Dock = DockStyle.Fill, Margin = new Padding(3, 2, 0, 2) };
        btnInspectRefresh.Click += async (_, _) =>
        {
            if (!string.IsNullOrWhiteSpace(txtInspectPath.Text))
                await InspectPathAsync(txtInspectPath.Text);
        };

        var inspectInfoGrid = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 4, BackColor = Theme.Bg, Margin = new Padding(0) };
        inspectInfoGrid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 148));
        inspectInfoGrid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        inspectInfoGrid.RowStyles.Add(new RowStyle(SizeType.Percent, 25));
        inspectInfoGrid.RowStyles.Add(new RowStyle(SizeType.Percent, 25));
        inspectInfoGrid.RowStyles.Add(new RowStyle(SizeType.Percent, 25));
        inspectInfoGrid.RowStyles.Add(new RowStyle(SizeType.Percent, 25));
        inspectInfoGrid.Controls.Add(MakeLabel("CONTAINER TYPE:", 8.5f), 0, 0);
        inspectInfoGrid.Controls.Add(lblInspectTypeVal, 1, 0);
        inspectInfoGrid.Controls.Add(MakeLabel("ACCESS MODE:", 8.5f), 0, 1);
        inspectInfoGrid.Controls.Add(lblInspectModeVal, 1, 1);
        inspectInfoGrid.Controls.Add(MakeLabel("VERSION:", 8.5f), 0, 2);
        inspectInfoGrid.Controls.Add(lblInspectVersionVal, 1, 2);
        inspectInfoGrid.Controls.Add(MakeLabel("SIZE:", 8.5f), 0, 3);
        inspectInfoGrid.Controls.Add(lblInspectSizeVal, 1, 3);

        var inspectPathRow = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, RowCount = 1, BackColor = Theme.Bg, Margin = new Padding(0) };
        inspectPathRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        inspectPathRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 92));
        inspectPathRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 92));
        inspectPathRow.Controls.Add(txtInspectPath, 0, 0);
        inspectPathRow.Controls.Add(btnInspectBrowse, 1, 0);
        inspectPathRow.Controls.Add(btnInspectRefresh, 2, 0);

        var inspectLogBox = new Panel { Dock = DockStyle.Fill, BackColor = Theme.LogBg };
        inspectLogBox.Controls.Add(rtbInspect);
        inspectLogBox.Paint += (_, pe) =>
        {
            using var pen = new Pen(Theme.Border, 1f);
            pe.Graphics.DrawRectangle(pen, 0, 0, inspectLogBox.Width - 1, inspectLogBox.Height - 1);
        };

        var outerInspect = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 6,
            Padding = new Padding(16),
            BackColor = Theme.Bg,
        };
        outerInspect.RowStyles.Add(new RowStyle(SizeType.Absolute, 52));
        outerInspect.RowStyles.Add(new RowStyle(SizeType.Absolute, 68));
        outerInspect.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
        outerInspect.RowStyles.Add(new RowStyle(SizeType.Absolute, 100));
        outerInspect.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        outerInspect.RowStyles.Add(new RowStyle(SizeType.Absolute, 28));
        outerInspect.Controls.Add(MakeTabHeader(
            "INSPECT",
            "Review supported containers and verify package integrity without decrypting contents."), 0, 0);
        outerInspect.Controls.Add(inspectDrop, 0, 1);
        outerInspect.Controls.Add(inspectPathRow, 0, 2);
        outerInspect.Controls.Add(inspectInfoGrid, 0, 3);
        outerInspect.Controls.Add(inspectLogBox, 0, 4);
        outerInspect.Controls.Add(lblInspectStatus, 0, 5);

        // ==================================================================
        // SELF-EXTRACTING PACKAGE TAB - self-extracting package workflows
        // ==================================================================
        var txtDelPassword = MakeTextBox(password: true);
        var txtDelPasswordConfirm = MakeTextBox(password: true);
        var txtDelName = MakeTextBox();
        txtDelName.PlaceholderText = "Package name (without extension)";
        txtDelName.Text = "delivery";
        var txtDelOutputDir = MakeTextBox();
        txtDelOutputDir.Text = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        var txtDelPackagePath = MakeTextBox();
        txtDelPackagePath.PlaceholderText = "Self-Extracting package path (.zip/.exe)";
        var txtDelInstructions = MakeTextBox();
        txtDelInstructions.Multiline = true;
        txtDelInstructions.ScrollBars = ScrollBars.Vertical;
        txtDelInstructions.Text =
            "1) If you received a ZIP, extract all files first." + "\r\n" +
            "2) Run Click_Here_to_Decrypt.exe (or open the Single EXE package)." + "\r\n" +
            "3) Enter your password when prompted." + "\r\n" +
            "4) Choose where to extract your files.";
        var txtDelExtractOut = MakeTextBox();
        txtDelExtractOut.Text = string.Empty;
        var chkDelCompress = new CheckBox { Text = "Compress files before packaging", AutoSize = true, ForeColor = Theme.TextMain, BackColor = Theme.Bg, Font = Theme.SafeMono(8.5f) };
        var chkDelIncludeInstructions = new CheckBox { Text = "Include custom extraction instructions", AutoSize = true, Checked = false, ForeColor = Theme.TextMain, BackColor = Theme.Bg, Font = Theme.SafeMono(8.5f) };
        var rbDelZip = new RadioButton { Text = "ZIP Archive (Recommended)", AutoSize = true, Checked = true, ForeColor = Theme.TextMain, BackColor = Theme.Bg, Font = Theme.SafeMono(8.5f) };
        var rbDelExe = new RadioButton { Text = "Single EXE File", AutoSize = true, ForeColor = Theme.TextMain, BackColor = Theme.Bg, Font = Theme.SafeMono(8.5f) };
        var lstDelSources = new ListBox
        {
            Dock = DockStyle.Fill,
            BackColor = Theme.Surface,
            ForeColor = Theme.TextMain,
            BorderStyle = BorderStyle.FixedSingle,
            Font = Theme.SafeMono(8.5f),
            IntegralHeight = false,
            HorizontalScrollbar = true,
        };
        lstDelSources.HandleCreated += (_, _) => SetWindowTheme(lstDelSources.Handle, "DarkMode_Explorer", null);
        var txtDelDetailsLog = MakeTextBox();
        txtDelDetailsLog.Multiline = true;
        txtDelDetailsLog.ScrollBars = ScrollBars.Both;
        txtDelDetailsLog.ReadOnly = true;
        txtDelDetailsLog.WordWrap = false;
        txtDelDetailsLog.BackColor = Theme.LogBg;
        txtDelDetailsLog.ForeColor = Theme.Accent;
        txtDelDetailsLog.Font = Theme.SafeMono(8.5f);
        var lblDelActivity = MakeLabel("No activity yet.", 8.5f);
        lblDelActivity.ForeColor = Theme.TextDim;
        lblDelActivity.AutoSize = false;
        lblDelActivity.AutoEllipsis = true;
        lblDelActivity.Dock = DockStyle.Fill;
        lblDelActivity.TextAlign = ContentAlignment.MiddleLeft;
        var lblDelStatus = MakeLabel("READY", 8.5f);
        lblDelStatus.ForeColor = Theme.Accent;
        lblDelStatus.AutoSize = false;
        lblDelStatus.AutoEllipsis = true;
        lblDelStatus.Dock = DockStyle.Fill;
        lblDelStatus.TextAlign = ContentAlignment.MiddleLeft;
        var lblDelSummary = MakeLabel("0 source items", 8.5f);
        lblDelSummary.ForeColor = Theme.TextDim;
        lblDelSummary.AutoSize = false;
        lblDelSummary.AutoEllipsis = true;
        lblDelSummary.Dock = DockStyle.Fill;
        lblDelSummary.TextAlign = ContentAlignment.MiddleLeft;
        var lblDelOutputPreview = MakeLabel("-", 8.5f);
        lblDelOutputPreview.ForeColor = Theme.Accent;
        lblDelOutputPreview.AutoSize = false;
        lblDelOutputPreview.AutoEllipsis = true;
        lblDelOutputPreview.Dock = DockStyle.Fill;
        lblDelOutputPreview.TextAlign = ContentAlignment.MiddleLeft;
        var lblDelPasswordStrength = MakeLabel("Password strength: -", 8.5f);
        lblDelPasswordStrength.ForeColor = Theme.TextDim;
        lblDelPasswordStrength.AutoSize = false;
        lblDelPasswordStrength.AutoEllipsis = true;
        lblDelPasswordStrength.Dock = DockStyle.Fill;
        lblDelPasswordStrength.TextAlign = ContentAlignment.MiddleLeft;
        NeonButton btnDelCreate = new();
        var delProgress = new NeonProgressBar
        {
            Dock = DockStyle.Fill,
            Minimum = 0,
            Maximum = 100,
            Value = 0,
            Style = ProgressBarStyle.Continuous,
        };
        Action<bool> setDeliveryProgressVisibility = _ => { };
        bool delNameUserEdited = false;
        bool suppressDelNameUserEditedTracking = false;
        string? lastAutoDeliveryName = null;
        var delDetailsLogSb = new StringBuilder();

        string ToSingleLine(string text)
        {
            var line = (text ?? string.Empty)
                .Replace("\r", " ")
                .Replace("\n", " ")
                .Trim();
            if (line.Length > 180) line = line[..177] + "...";
            return line;
        }

        void DelLog(string text, Color color)
        {
            string entry = text ?? string.Empty;
            if (delDetailsLogSb.Length > 0) delDetailsLogSb.AppendLine();
            delDetailsLogSb.Append(entry);
            txtDelDetailsLog.Text = delDetailsLogSb.ToString();
            txtDelDetailsLog.SelectionStart = txtDelDetailsLog.TextLength;
            txtDelDetailsLog.ScrollToCaret();

            string line = ToSingleLine(entry);
            if (!string.IsNullOrWhiteSpace(line))
            {
                lblDelActivity.ForeColor = color == Theme.Error ? Theme.Error : Theme.TextDim;
                lblDelActivity.Text = line;
            }
        }

        void DelStatus(string text, bool error = false)
        {
            lblDelStatus.ForeColor = error ? Theme.Error : Theme.Accent;
            lblDelStatus.Text = text;
            DelLog((error ? "[ERR] " : "[OK] ") + text, error ? Theme.Error : Theme.Accent);
        }

        string BuildDeliveryPackagePath()
        {
            string zipPath = BuildDeliveryZipPath();
            if (!rbDelExe.Checked) return zipPath;
            return Path.ChangeExtension(zipPath, ".exe");
        }

        string BuildDeliveryZipPath()
        {
            string name = string.IsNullOrWhiteSpace(txtDelName.Text) ? "delivery" : txtDelName.Text.Trim();
            string safeName = string.Join("_", name.Split(Path.GetInvalidFileNameChars(), StringSplitOptions.RemoveEmptyEntries)).Trim();
            if (string.IsNullOrWhiteSpace(safeName)) safeName = "delivery";
            string dir = string.IsNullOrWhiteSpace(txtDelOutputDir.Text)
                ? Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory)
                : txtDelOutputDir.Text.Trim();
            return Path.Combine(dir, $"{safeName}_SecureDelivery.zip");
        }

        string? GetDeliveryOutputDirFromSource(string sourcePath)
        {
            if (Directory.Exists(sourcePath))
            {
                try
                {
                    string fullDir = Path.GetFullPath(sourcePath);
                    var parent = Directory.GetParent(fullDir);
                    return parent?.FullName ?? fullDir;
                }
                catch
                {
                    return sourcePath;
                }
            }
            if (File.Exists(sourcePath))
                return Path.GetDirectoryName(sourcePath);
            return null;
        }

        string? GetDeliverySuggestedNameFromSource(string sourcePath)
        {
            try
            {
                if (Directory.Exists(sourcePath))
                {
                    string fullDir = Path.GetFullPath(sourcePath);
                    var di = new DirectoryInfo(fullDir);
                    return string.IsNullOrWhiteSpace(di.Name) ? null : di.Name;
                }
                if (File.Exists(sourcePath))
                {
                    string fullPath = Path.GetFullPath(sourcePath);
                    string name = Path.GetFileNameWithoutExtension(fullPath);
                    return string.IsNullOrWhiteSpace(name) ? null : name;
                }
            }
            catch { }
            return null;
        }

        void TryAutoSetDeliveryNameFromSource(string sourcePath)
        {
            string? suggested = GetDeliverySuggestedNameFromSource(sourcePath);
            if (string.IsNullOrWhiteSpace(suggested)) return;

            string current = txtDelName.Text?.Trim() ?? string.Empty;
            bool isDefault = string.IsNullOrWhiteSpace(current) || string.Equals(current, "delivery", StringComparison.OrdinalIgnoreCase);
            bool isPreviousAuto = !string.IsNullOrWhiteSpace(lastAutoDeliveryName)
                && string.Equals(current, lastAutoDeliveryName, StringComparison.OrdinalIgnoreCase);
            bool allowAuto = !delNameUserEdited || isDefault || isPreviousAuto;
            if (!allowAuto) return;

            suppressDelNameUserEditedTracking = true;
            try { txtDelName.Text = suggested; }
            finally { suppressDelNameUserEditedTracking = false; }
            lastAutoDeliveryName = suggested;
            delNameUserEdited = false;
        }

        void RefreshDeliverySummary()
        {
            string pw = txtDelPassword.Text ?? string.Empty;
            int len = pw.Length;
            bool hasUpper = pw.Any(char.IsUpper);
            bool hasLower = pw.Any(char.IsLower);
            bool hasDigit = pw.Any(char.IsDigit);
            bool hasSymbol = pw.Any(ch => !char.IsLetterOrDigit(ch));
            int classes = (hasUpper ? 1 : 0) + (hasLower ? 1 : 0) + (hasDigit ? 1 : 0) + (hasSymbol ? 1 : 0);
            string strength;
            Color strengthColor;
            if (len == 0)
            {
                strength = "Required";
                strengthColor = Theme.TextDim;
            }
            else if (len < 8)
            {
                strength = "Too short (min 8)";
                strengthColor = Theme.Error;
            }
            else if (len >= 12 && classes >= 3)
            {
                strength = "Strong";
                strengthColor = Theme.Accent;
            }
            else
            {
                strength = "Okay";
                strengthColor = Theme.AccentDim;
            }
            lblDelPasswordStrength.Text = $"Password strength: {strength}";
            lblDelPasswordStrength.ForeColor = strengthColor;

            bool nameOk = !string.IsNullOrWhiteSpace(txtDelName.Text);
            bool outOk = !string.IsNullOrWhiteSpace(txtDelOutputDir.Text);
            bool passwordOk = len >= 8;
            bool confirmOk = string.Equals(txtDelPassword.Text, txtDelPasswordConfirm.Text, StringComparison.Ordinal);
            bool sourcesOk = lstDelSources.Items.Count > 0;
            bool formatOk = rbDelZip.Checked || rbDelExe.Checked;
            btnDelCreate.Enabled = nameOk && outOk && passwordOk && confirmOk && sourcesOk && formatOk;

            string validationHint = string.Empty;
            if (!sourcesOk)
                validationHint = "Add at least one source item.";
            else if (!nameOk)
                validationHint = "Enter a package name.";
            else if (!outOk)
                validationHint = "Select an output folder.";
            else if (!passwordOk)
                validationHint = "Password must be at least 8 characters.";
            else if (!confirmOk && (!string.IsNullOrWhiteSpace(txtDelPassword.Text) || !string.IsNullOrWhiteSpace(txtDelPasswordConfirm.Text)))
                validationHint = "Passwords do not match.";
            else if (!formatOk)
                validationHint = "Select output format.";

            lblDelSummary.ForeColor = string.IsNullOrWhiteSpace(validationHint) ? Theme.TextDim : Theme.Error;
            lblDelSummary.Text = string.IsNullOrWhiteSpace(validationHint)
                ? $"{lstDelSources.Items.Count} source item(s)  |  Ready"
                : $"{lstDelSources.Items.Count} source item(s)  |  {validationHint}";
            lblDelOutputPreview.Text = BuildDeliveryPackagePath();
            txtDelPackagePath.Text = BuildDeliveryPackagePath();
            txtDelInstructions.Enabled = chkDelIncludeInstructions.Checked;
        }

        async Task<(int ExitCode, string Stdout, string Stderr)> RunDeliveryCliAsync(string args, IEnumerable<string>? stdinLines = null)
            => await RunVaultCliWithInputsAsync(args, stdinLines);

        bool TryParseJsonMessage(string json, out string message, out string? outputPath)
        {
            message = string.Empty;
            outputPath = null;
            try
            {
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;
                if (root.TryGetProperty("error", out var err) && err.TryGetProperty("message", out var msg))
                    message = msg.GetString() ?? string.Empty;
                if (root.TryGetProperty("data", out var data) && data.TryGetProperty("output_path", out var op))
                    outputPath = op.GetString();
                if (string.IsNullOrWhiteSpace(message) && root.TryGetProperty("ok", out var ok) && ok.GetBoolean())
                    message = "Operation completed successfully.";
                return true;
            }
            catch { return false; }
        }

        bool TryBuildZipWithSingleExeEntrypoint(string packagePath, bool includeStartHere, string? customInstructions, out string error)
        {
            error = string.Empty;
            try
            {
                if (string.IsNullOrWhiteSpace(packagePath) || !File.Exists(packagePath))
                {
                    error = "Package output not found.";
                    return false;
                }
                string tempRoot = Path.Combine(Path.GetTempPath(), $"obsq_delivery_zip_wrap_{Guid.NewGuid():N}");
                Directory.CreateDirectory(tempRoot);
                string tempExePath = Path.Combine(tempRoot, "Click_Here_to_Decrypt.exe");
                string tempZipPath = Path.Combine(tempRoot, Path.GetFileName(packagePath));

                if (!TryBuildSingleExeFromPackage(packagePath, tempExePath, includeStartHere, out var exeErr))
                {
                    error = exeErr;
                    return false;
                }

                const string startHereText =
                    "ObsidianQ Self-Extracting Package\r\n\r\n" +
                    "1) Extract all files from this ZIP.\r\n" +
                    "2) Run Click_Here_to_Decrypt.exe.\r\n" +
                    "3) Enter your password when prompted.\r\n" +
                    "4) Choose where to extract your files.\r\n";

                using (var zip = ZipFile.Open(tempZipPath, ZipArchiveMode.Create))
                {
                    zip.CreateEntryFromFile(tempExePath, "Click_Here_to_Decrypt.exe", CompressionLevel.Optimal);
                    if (!string.IsNullOrWhiteSpace(customInstructions))
                    {
                        var customEntry = zip.CreateEntry("INSTRUCTIONS.txt", CompressionLevel.Optimal);
                        using var sw = new StreamWriter(customEntry.Open(), new UTF8Encoding(false));
                        sw.Write(customInstructions);
                    }
                    else if (includeStartHere)
                    {
                        var infoEntry = zip.CreateEntry("START_HERE.txt", CompressionLevel.Optimal);
                        using var sw = new StreamWriter(infoEntry.Open(), new UTF8Encoding(false));
                        sw.Write(startHereText);
                    }
                }

                try { File.Delete(packagePath); } catch { }
                File.Move(tempZipPath, packagePath, overwrite: true);
                try { Directory.Delete(tempRoot, recursive: true); } catch { }
                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }

        bool TryBuildSingleExeFromPackage(string packageZipPath, string outputExePath, bool includeStartHere, out string error)
        {
            error = string.Empty;
            if (!File.Exists(packageZipPath))
            {
                error = "Package ZIP not found for EXE conversion.";
                return false;
            }

            if (!File.Exists(ExePath))
            {
                error = "obsidianq.exe not found; cannot build single EXE package.";
                return false;
            }

            if (!File.Exists(ExtractorStubPath))
            {
                error = $"Single EXE bootstrapper not found at: {ExtractorStubPath}";
                return false;
            }

            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(outputExePath) ?? Environment.CurrentDirectory);
                if (File.Exists(outputExePath)) File.Delete(outputExePath);
                File.Copy(ExtractorStubPath, outputExePath, overwrite: true);

                byte[] packageBytes = File.ReadAllBytes(packageZipPath);
                byte[] cliBytes = File.ReadAllBytes(ExePath);
                byte[] magic = Encoding.ASCII.GetBytes("OBSQSFX1");
                if (magic.Length != 8) throw new InvalidOperationException("Invalid SFX magic length.");

                using var fs = new FileStream(outputExePath, FileMode.Append, FileAccess.Write, FileShare.None);
                fs.Write(packageBytes, 0, packageBytes.Length);
                fs.Write(cliBytes, 0, cliBytes.Length);
                fs.Write(BitConverter.GetBytes((long)packageBytes.Length), 0, 8);
                fs.Write(BitConverter.GetBytes((long)cliBytes.Length), 0, 8);
                fs.Write(magic, 0, magic.Length);
                fs.Flush(true);
                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }

        void AddDeliverySource(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return;
            if (!File.Exists(path) && !Directory.Exists(path)) return;
            foreach (var item in lstDelSources.Items.Cast<string>())
                if (string.Equals(item, path, StringComparison.OrdinalIgnoreCase))
                    return;
            lstDelSources.Items.Add(path);
            RefreshDeliverySummary();
        }

        _openDeliveryWithSource = path =>
        {
            if (string.IsNullOrWhiteSpace(path)) return;
            if (!File.Exists(path) && !Directory.Exists(path)) return;
            _tabs.SelectedIndex = 4; // Self-Extracting Package
            TryAutoSetDeliveryNameFromSource(path);
            string? outputDir = GetDeliveryOutputDirFromSource(path);
            if (!string.IsNullOrWhiteSpace(outputDir))
                txtDelOutputDir.Text = outputDir!;
            AddDeliverySource(path);
            DelStatus("Added source from Explorer context menu.");
        };

        WireFileDrop(lstDelSources, files =>
        {
            TryAutoSetDeliveryNameFromSource(files[0]);
            string? outputDir = GetDeliveryOutputDirFromSource(files[0]);
            if (!string.IsNullOrWhiteSpace(outputDir))
                txtDelOutputDir.Text = outputDir!;
            foreach (var f in files) AddDeliverySource(f);
            DelStatus("Added dropped source item(s).");
        });

        var btnDelAddFiles = new NeonButton { Text = "ADD FILES", Dock = DockStyle.Fill, Margin = new Padding(0, 2, 3, 2) };
        var btnDelAddFolder = new NeonButton { Text = "ADD FOLDER", Dock = DockStyle.Fill, Margin = new Padding(3, 2, 3, 2) };
        var btnDelRemove = new NeonButton { Text = "REMOVE SELECTED", Dock = DockStyle.Fill, Margin = new Padding(3, 2, 3, 2) };
        var btnDelClear = new NeonButton { Text = "CLEAR", Dock = DockStyle.Fill, Margin = new Padding(3, 2, 0, 2) };
        btnDelAddFiles.Click += (_, _) =>
        {
            using var dlg = new OpenFileDialog { Title = "Select files", Filter = "All files|*.*", Multiselect = true };
            if (dlg.ShowDialog(this) != DialogResult.OK) return;
            TryAutoSetDeliveryNameFromSource(dlg.FileNames[0]);
            string? outputDir = GetDeliveryOutputDirFromSource(dlg.FileNames[0]);
            if (!string.IsNullOrWhiteSpace(outputDir))
                txtDelOutputDir.Text = outputDir!;
            foreach (var f in dlg.FileNames) AddDeliverySource(f);
            DelStatus("Added source file(s).");
        };
        btnDelAddFolder.Click += (_, _) =>
        {
            using var dlg = new FolderBrowserDialog { Description = "Select source folder", UseDescriptionForTitle = true, ShowNewFolderButton = true };
            if (dlg.ShowDialog(this) != DialogResult.OK) return;
            TryAutoSetDeliveryNameFromSource(dlg.SelectedPath);
            string? outputDir = GetDeliveryOutputDirFromSource(dlg.SelectedPath);
            if (!string.IsNullOrWhiteSpace(outputDir))
                txtDelOutputDir.Text = outputDir!;
            AddDeliverySource(dlg.SelectedPath);
            DelStatus("Added source folder.");
        };
        btnDelRemove.Click += (_, _) =>
        {
            var selected = lstDelSources.SelectedItems.Cast<object>().ToList();
            foreach (var item in selected) lstDelSources.Items.Remove(item);
            RefreshDeliverySummary();
        };
        btnDelClear.Click += (_, _) => { lstDelSources.Items.Clear(); RefreshDeliverySummary(); };

        var btnDelBrowseOutDir = new NeonButton { Text = "BROWSE", Dock = DockStyle.Fill, Margin = new Padding(3, 2, 0, 2) };
        int delOutBrowseHeight = Math.Max(22, txtDelOutputDir.PreferredHeight);
        btnDelBrowseOutDir.MinimumSize = new Size(0, delOutBrowseHeight);
        btnDelBrowseOutDir.MaximumSize = new Size(int.MaxValue, delOutBrowseHeight);
        btnDelBrowseOutDir.Font = Theme.SafeMono(8.5f);
        btnDelBrowseOutDir.Click += (_, _) =>
        {
            using var dlg = new FolderBrowserDialog { Description = "Select package output folder", UseDescriptionForTitle = true, ShowNewFolderButton = true };
            if (dlg.ShowDialog(this) != DialogResult.OK) return;
            txtDelOutputDir.Text = dlg.SelectedPath;
            RefreshDeliverySummary();
        };
        btnDelCreate = new NeonButton { Text = "CREATE PACKAGE", Dock = DockStyle.Fill, Margin = new Padding(0, 2, 3, 2) };
        var btnDelOpenOut = new NeonButton { Text = "OPEN OUTPUT FOLDER", Dock = DockStyle.Fill, Margin = new Padding(0, 2, 0, 2) };
        var btnDelViewDetails = new NeonButton { Text = "VIEW DETAILS", Dock = DockStyle.Fill, Margin = new Padding(3, 2, 0, 2) };
        btnDelOpenOut.Click += (_, _) =>
        {
            string dir = string.IsNullOrWhiteSpace(txtDelOutputDir.Text) ? Environment.CurrentDirectory : txtDelOutputDir.Text;
            try { Process.Start(new ProcessStartInfo("explorer.exe", $"\"{dir}\"") { UseShellExecute = true }); } catch { }
        };
        btnDelViewDetails.Click += (_, _) =>
        {
            using var dlg = new Form
            {
                Text = "Self-Extracting Package Details",
                StartPosition = FormStartPosition.CenterParent,
                FormBorderStyle = FormBorderStyle.Sizable,
                MinimizeBox = false,
                MaximizeBox = true,
                ShowInTaskbar = false,
                ClientSize = new Size(860, 520),
                MinimumSize = new Size(700, 420),
                BackColor = Theme.Bg,
                ForeColor = Theme.TextMain,
                Font = Theme.SafeMono(9f),
            };
            var body = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, Padding = new Padding(12), BackColor = Theme.Bg };
            body.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            body.RowStyles.Add(new RowStyle(SizeType.Absolute, 34));
            var txt = MakeTextBox();
            txt.Multiline = true;
            txt.ScrollBars = ScrollBars.Both;
            txt.ReadOnly = true;
            txt.WordWrap = false;
            txt.Dock = DockStyle.Fill;
            txt.BackColor = Theme.LogBg;
            txt.ForeColor = Theme.Accent;
            txt.Font = Theme.SafeMono(8.5f);
            txt.Text = delDetailsLogSb.Length == 0 ? "No details captured yet." : delDetailsLogSb.ToString();
            txt.SelectionStart = txt.TextLength;
            txt.ScrollToCaret();
            var btns = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, BackColor = Theme.Bg };
            btns.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            btns.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            var btnCopy = new NeonButton { Text = "COPY", Dock = DockStyle.Fill, Margin = new Padding(0, 0, 4, 0) };
            var btnClose = new NeonButton { Text = "CLOSE", Dock = DockStyle.Fill, Margin = new Padding(4, 0, 0, 0) };
            btnCopy.Click += (_, _) => { try { Clipboard.SetText(txt.Text ?? string.Empty); } catch { } };
            btnClose.Click += (_, _) => dlg.Close();
            btns.Controls.Add(btnCopy, 0, 0);
            btns.Controls.Add(btnClose, 1, 0);
            body.Controls.Add(txt, 0, 0);
            body.Controls.Add(btns, 0, 1);
            dlg.Controls.Add(body);
            dlg.ShowDialog(this);
        };

        btnDelCreate.Click += async (_, _) =>
        {
            if (!File.Exists(ExePath)) { DelStatus("obsidianq.exe not found.", true); return; }
            if (lstDelSources.Items.Count == 0) { DelStatus("Add at least one source file/folder.", true); return; }
            if (string.IsNullOrWhiteSpace(txtDelPassword.Text)) { DelStatus("Enter package password.", true); return; }
            if (txtDelPassword.Text.Length < 8) { DelStatus("Password too short. Minimum length is 8 characters.", true); return; }
            if (!string.Equals(txtDelPassword.Text, txtDelPasswordConfirm.Text, StringComparison.Ordinal))
            {
                DelStatus("Password confirmation does not match.", true);
                return;
            }
            Directory.CreateDirectory(txtDelOutputDir.Text);

            var argsSb = new StringBuilder();
            argsSb.Append("delivery create --json --password-stdin --format zip ");
            argsSb.Append($"--output \"{txtDelOutputDir.Text}\" ");
            argsSb.Append($"--name \"{txtDelName.Text}\" ");
            if (chkDelCompress.Checked) argsSb.Append("--compress ");
            string? tempInstructions = null;
            if (chkDelIncludeInstructions.Checked)
            {
                argsSb.Append("--include-instructions ");
                tempInstructions = Path.Combine(Path.GetTempPath(), $"obsq_delivery_instructions_{Guid.NewGuid():N}.txt");
                File.WriteAllText(tempInstructions, txtDelInstructions.Text ?? string.Empty);
                argsSb.Append($"--instructions-file \"{tempInstructions}\" ");
            }
            argsSb.Append("--overwrite ");
            foreach (string src in lstDelSources.Items.Cast<string>())
                argsSb.Append($"\"{src}\" ");

            setDeliveryProgressVisibility(true);
            delProgress.Style = ProgressBarStyle.Marquee;
            delProgress.MarqueeAnimationSpeed = 20;
            btnDelCreate.Enabled = false;
            try
            {
                DelLog($"[CMD] obsidianq {argsSb}", Theme.TextDim);
                var (code, stdout, stderr) = await RunWithBusyDialogAsync(
                    "Self-Extracting Package",
                    "Creating self-extracting package...",
                    () => RunDeliveryCliAsync(argsSb.ToString(), [txtDelPassword.Text]));
                if (!string.IsNullOrWhiteSpace(stderr)) DelLog(stderr.TrimEnd(), Theme.Error);
                if (!string.IsNullOrWhiteSpace(stdout)) DelLog(stdout.TrimEnd(), Theme.AccentDim);

                bool parsed = TryParseJsonMessage(stdout, out var msg, out var outputPath);
                if (code == 0)
                {
                    if (!string.IsNullOrWhiteSpace(outputPath))
                        txtDelPackagePath.Text = outputPath!;
                    string finalZipPath = !string.IsNullOrWhiteSpace(outputPath) ? outputPath! : BuildDeliveryZipPath();
                    bool includeStartHere = !chkDelIncludeInstructions.Checked;
                    if (rbDelZip.Checked)
                    {
                        string? customZipInstructions = chkDelIncludeInstructions.Checked ? (txtDelInstructions.Text ?? string.Empty) : null;
                        if (TryBuildZipWithSingleExeEntrypoint(finalZipPath, includeStartHere, customZipInstructions, out var embedErr))
                        {
                            DelLog("[OK] Built ZIP package with single EXE entrypoint.", Theme.AccentDim);
                            DelStatus(string.IsNullOrWhiteSpace(msg) ? "ZIP package created with single EXE entrypoint." : $"{msg} ZIP package includes one EXE entrypoint.");
                        }
                        else
                        {
                            DelLog($"[ERR] Failed to build ZIP with EXE entrypoint: {embedErr}", Theme.Error);
                            DelStatus(string.IsNullOrWhiteSpace(msg) ? "Package created (ZIP entrypoint wrap failed)." : $"{msg} ZIP entrypoint wrap failed.", error: true);
                        }
                    }
                    else
                    {
                        string finalExePath = BuildDeliveryPackagePath();
                        if (TryBuildSingleExeFromPackage(finalZipPath, finalExePath, includeStartHere, out var exeErr))
                        {
                            try { File.Delete(finalZipPath); } catch { }
                            txtDelPackagePath.Text = finalExePath;
                            DelStatus(string.IsNullOrWhiteSpace(msg) ? "Single EXE package created." : $"{msg} Single EXE package created.");
                        }
                        else
                        {
                            DelLog($"[ERR] Failed to build single EXE package: {exeErr}", Theme.Error);
                            string? customZipInstructions = chkDelIncludeInstructions.Checked ? (txtDelInstructions.Text ?? string.Empty) : null;
                            if (TryBuildZipWithSingleExeEntrypoint(finalZipPath, includeStartHere, customZipInstructions, out var zipFallbackErr))
                            {
                                txtDelPackagePath.Text = finalZipPath;
                                DelLog("[OK] Fallback: created ZIP package with single EXE entrypoint.", Theme.AccentDim);
                                DelStatus(string.IsNullOrWhiteSpace(msg)
                                    ? "EXE conversion failed; fallback ZIP package created."
                                    : $"{msg} EXE conversion failed; fallback ZIP package created.",
                                    error: true);
                            }
                            else
                            {
                                DelLog($"[ERR] ZIP fallback also failed: {zipFallbackErr}", Theme.Error);
                                DelStatus(string.IsNullOrWhiteSpace(msg)
                                    ? "Package created, but EXE conversion failed."
                                    : $"{msg} EXE conversion failed.",
                                    error: true);
                            }
                        }
                    }
                }
                else
                {
                    string detail = parsed && !string.IsNullOrWhiteSpace(msg)
                        ? msg
                        : $"Create failed (exit {code}).";
                    DelStatus(detail, error: true);
                }
            }
            finally
            {
                if (!string.IsNullOrWhiteSpace(tempInstructions))
                {
                    try { File.Delete(tempInstructions); } catch { }
                }
                delProgress.Style = ProgressBarStyle.Continuous;
                delProgress.Value = 0;
                delProgress.MarqueeAnimationSpeed = 0;
                setDeliveryProgressVisibility(false);
                RefreshDeliverySummary();
            }
        };

        txtDelName.TextChanged += (_, _) =>
        {
            if (!suppressDelNameUserEditedTracking)
                delNameUserEdited = true;
            RefreshDeliverySummary();
        };
        txtDelOutputDir.TextChanged += (_, _) => RefreshDeliverySummary();
        txtDelPassword.TextChanged += (_, _) => RefreshDeliverySummary();
        txtDelPasswordConfirm.TextChanged += (_, _) => RefreshDeliverySummary();
        chkDelIncludeInstructions.CheckedChanged += (_, _) => RefreshDeliverySummary();
        rbDelZip.CheckedChanged += (_, _) => RefreshDeliverySummary();
        rbDelExe.CheckedChanged += (_, _) => RefreshDeliverySummary();
        chkDelCompress.CheckedChanged += (_, _) => RefreshDeliverySummary();
        RefreshDeliverySummary();

        var delAccess = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 4, RowCount = 1, BackColor = Theme.Bg, Margin = new Padding(0) };
        delAccess.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 120));
        delAccess.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        delAccess.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 120));
        delAccess.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        delAccess.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        delAccess.Controls.Add(MakeLabel("PASSWORD", 8.5f, true), 0, 0);
        delAccess.Controls.Add(txtDelPassword, 1, 0);
        delAccess.Controls.Add(MakeLabel("CONFIRM", 8.5f, true), 2, 0);
        delAccess.Controls.Add(txtDelPasswordConfirm, 3, 0);

        var delSourcesButtons = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 4, RowCount = 1, BackColor = Theme.Bg, Margin = new Padding(0) };
        delSourcesButtons.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 25));
        delSourcesButtons.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 25));
        delSourcesButtons.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 25));
        delSourcesButtons.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 25));
        delSourcesButtons.Controls.Add(btnDelAddFiles, 0, 0);
        delSourcesButtons.Controls.Add(btnDelAddFolder, 1, 0);
        delSourcesButtons.Controls.Add(btnDelRemove, 2, 0);
        delSourcesButtons.Controls.Add(btnDelClear, 3, 0);

        var delOutRow = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, BackColor = Theme.Bg, Margin = new Padding(0) };
        delOutRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        delOutRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 92));
        delOutRow.Controls.Add(txtDelOutputDir, 0, 0);
        delOutRow.Controls.Add(btnDelBrowseOutDir, 1, 0);
        var delOutputHost = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, BackColor = Theme.Bg, Margin = new Padding(0) };
        delOutputHost.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 120));
        delOutputHost.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        delOutputHost.Controls.Add(MakeLabel("OUTPUT FOLDER", 8.5f, true), 0, 0);
        delOutputHost.Controls.Add(delOutRow, 1, 0);

        var delOptionsCompact = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 6, BackColor = Theme.Bg, Margin = new Padding(0), Padding = new Padding(0) };
        delOptionsCompact.RowStyles.Add(new RowStyle(SizeType.Absolute, 24));
        delOptionsCompact.RowStyles.Add(new RowStyle(SizeType.Absolute, 24));
        delOptionsCompact.RowStyles.Add(new RowStyle(SizeType.Absolute, 24));
        delOptionsCompact.RowStyles.Add(new RowStyle(SizeType.Absolute, 24));
        delOptionsCompact.RowStyles.Add(new RowStyle(SizeType.Absolute, 24));
        delOptionsCompact.RowStyles.Add(new RowStyle(SizeType.Absolute, 24));
        var delNameRow = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, BackColor = Theme.Bg, Margin = new Padding(0) };
        delNameRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 110));
        delNameRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        delNameRow.Controls.Add(MakeLabel("PACKAGE NAME", 8.5f, true), 0, 0);
        delNameRow.Controls.Add(txtDelName, 1, 0);
        delOptionsCompact.Controls.Add(delNameRow, 0, 0);
        delOptionsCompact.Controls.Add(rbDelZip, 0, 1);
        delOptionsCompact.Controls.Add(rbDelExe, 0, 2);
        delOptionsCompact.Controls.Add(chkDelCompress, 0, 3);
        delOptionsCompact.Controls.Add(chkDelIncludeInstructions, 0, 4);
        var delFinalOutputHost = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, BackColor = Theme.Bg, Margin = new Padding(0) };
        delFinalOutputHost.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 120));
        delFinalOutputHost.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        delFinalOutputHost.Controls.Add(MakeLabel("FINAL OUTPUT", 8.5f, true), 0, 0);
        delFinalOutputHost.Controls.Add(lblDelOutputPreview, 1, 0);

        var delActions = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, RowCount = 1, BackColor = Theme.Bg, Margin = new Padding(0) };
        delActions.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 34));
        delActions.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33));
        delActions.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33));
        delActions.Controls.Add(btnDelCreate, 0, 0);
        delActions.Controls.Add(btnDelOpenOut, 1, 0);
        delActions.Controls.Add(btnDelViewDetails, 2, 0);

        var delLogContainer = new Panel { Dock = DockStyle.Fill, BackColor = Theme.LogBg };
        delLogContainer.Controls.Add(lblDelActivity);
        delLogContainer.Paint += (_, pe) =>
        {
            using var pen = new Pen(Theme.Border, 1f);
            pe.Graphics.DrawRectangle(pen, 0, 0, delLogContainer.Width - 1, delLogContainer.Height - 1);
        };

        var outerDelivery = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 12,
            Padding = new Padding(16),
            BackColor = Theme.Bg,
        };
        outerDelivery.RowStyles.Add(new RowStyle(SizeType.Absolute, 52));
        outerDelivery.RowStyles.Add(new RowStyle(SizeType.Absolute, 34));
        outerDelivery.RowStyles.Add(new RowStyle(SizeType.Absolute, 24));
        outerDelivery.RowStyles.Add(new RowStyle(SizeType.Absolute, 34));
        outerDelivery.RowStyles.Add(new RowStyle(SizeType.Absolute, 120));
        outerDelivery.RowStyles.Add(new RowStyle(SizeType.Absolute, 34));
        outerDelivery.RowStyles.Add(new RowStyle(SizeType.Absolute, 188));
        outerDelivery.RowStyles.Add(new RowStyle(SizeType.Absolute, 24));
        outerDelivery.RowStyles.Add(new RowStyle(SizeType.Absolute, 34));
        outerDelivery.RowStyles.Add(new RowStyle(SizeType.Absolute, 0));
        outerDelivery.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        outerDelivery.RowStyles.Add(new RowStyle(SizeType.Absolute, 28));
        outerDelivery.Controls.Add(MakeTabHeader(
            "SELF-EXTRACTING PACKAGE",
            "Create portable password-protected packages for recipients without ObsidianQ."), 0, 0);
        outerDelivery.Controls.Add(delAccess, 0, 1);
        var delSummaryRow = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, BackColor = Theme.Bg, Margin = new Padding(0) };
        delSummaryRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        delSummaryRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        delSummaryRow.Controls.Add(lblDelSummary, 0, 0);
        delSummaryRow.Controls.Add(lblDelPasswordStrength, 1, 0);
        outerDelivery.Controls.Add(delSummaryRow, 0, 2);
        outerDelivery.Controls.Add(delSourcesButtons, 0, 3);
        outerDelivery.Controls.Add(lstDelSources, 0, 4);
        outerDelivery.Controls.Add(delOutputHost, 0, 5);
        var delFormatHost = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 4, BackColor = Theme.Bg, Margin = new Padding(0) };
        delFormatHost.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 45));
        delFormatHost.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 55));
        delFormatHost.RowStyles.Add(new RowStyle(SizeType.Absolute, 28));
        delFormatHost.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        delFormatHost.RowStyles.Add(new RowStyle(SizeType.Absolute, 0));
        delFormatHost.RowStyles.Add(new RowStyle(SizeType.Absolute, 0));
        delFormatHost.Controls.Add(MakeLabel("OPTIONS", 8.5f, true), 0, 0);
        delFormatHost.Controls.Add(MakeLabel("INSTRUCTIONS", 8.5f, true), 1, 0);
        delFormatHost.Controls.Add(delOptionsCompact, 0, 1);
        delFormatHost.Controls.Add(txtDelInstructions, 1, 1);
        outerDelivery.Controls.Add(delFormatHost, 0, 6);
        outerDelivery.Controls.Add(delFinalOutputHost, 0, 7);
        outerDelivery.Controls.Add(delActions, 0, 8);
        outerDelivery.Controls.Add(delProgress, 0, 9);
        outerDelivery.Controls.Add(delLogContainer, 0, 10);
        outerDelivery.Controls.Add(lblDelStatus, 0, 11);
        setDeliveryProgressVisibility = visible =>
        {
            delProgress.Visible = visible;
            outerDelivery.RowStyles[9].Height = visible ? 28f : 0f;
            outerDelivery.PerformLayout();
        };
        setDeliveryProgressVisibility(false);

        // ==================================================================
        // ASSEMBLE TAB CONTROL
        // ==================================================================
        var tabFile  = new TabPage { Text = "FILE",  BackColor = Theme.Bg, ForeColor = Theme.TextMain, Padding = new Padding(0), UseVisualStyleBackColor = false };
        var tabText  = new TabPage { Text = "TEXT",  BackColor = Theme.Bg, ForeColor = Theme.TextMain, Padding = new Padding(0), UseVisualStyleBackColor = false };
        var tabVault = new TabPage { Text = "VAULT", BackColor = Theme.Bg, ForeColor = Theme.TextMain, Padding = new Padding(0), UseVisualStyleBackColor = false };
        var tabInspect = new TabPage { Text = "INSPECT", BackColor = Theme.Bg, ForeColor = Theme.TextMain, Padding = new Padding(0), UseVisualStyleBackColor = false };
        var tabDelivery = new TabPage { Text = "SELF-EXTRACTING PACKAGE", BackColor = Theme.Bg, ForeColor = Theme.TextMain, Padding = new Padding(0), UseVisualStyleBackColor = false };
        var tabExchange = new TabPage { Text = "FILE SEND / RECEIVE", BackColor = Theme.Bg, ForeColor = Theme.TextMain, Padding = new Padding(0), UseVisualStyleBackColor = false };
        var tabKeyExchange2 = new TabPage { Text = "SECURE CONTACTS", BackColor = Theme.Bg, ForeColor = Theme.TextMain, Padding = new Padding(0), UseVisualStyleBackColor = false };
        var tabSettings = new TabPage { Text = "SETTINGS", BackColor = Theme.Bg, ForeColor = Theme.TextMain, Padding = new Padding(0), UseVisualStyleBackColor = false };
        var tabAbout = new TabPage { Text = "ABOUT", BackColor = Theme.Bg, ForeColor = Theme.TextMain, Padding = new Padding(0), UseVisualStyleBackColor = false };
        tabFile.Controls.Add(outerFile);
        tabText.Controls.Add(outerText);
        tabVault.Controls.Add(outerVault);
        tabInspect.Controls.Add(outerInspect);
        tabDelivery.Controls.Add(outerDelivery);
        tabExchange.Controls.Add(outerExchange);
        tabKeyExchange2.Controls.Add(outerKx2);
        tabSettings.Controls.Add(outerSettings);
        tabAbout.Controls.Add(outerAbout);

        _tabs = new CyberpunkTabControl { Dock = DockStyle.Fill };
        // File Send / Receive is currently hidden (workflow sugar; core capability lives in File/Text tabs).
        _tabs.TabPages.AddRange([tabFile, tabText, tabVault, tabInspect, tabDelivery, tabKeyExchange2, tabSettings, tabAbout]);
        _tabs.SelectedIndexChanged += (_, _) =>
        {
            if (_tabs.SelectedIndex == 2) RefreshDriveLetter();
        };

        // ==================================================================
        // ADD TO FORM  (shimmer first → DockStyle.Top at the very top)
        // ==================================================================
        Controls.Add(_shimmer);
        Controls.Add(_tabs);
        ApplyDarkThemeRecursive(this);

        // Set default mode after all controls are initialized and parented.
        _toggle.SetSelected(SegmentedToggle.Segment.Pqc);
        _toggleText.SetSelected(SegmentedToggle.Segment.Pqc);
        _toggleVault.SetSelected(SegmentedToggle.Segment.Pqc);

        // ==================================================================
        // FORM-LEVEL WIRING
        // ==================================================================
        AllowDrop = true;
        DragEnter += (_, e) =>
        {
            if (e.Data?.GetDataPresent(DataFormats.FileDrop) == true) e.Effect = DragDropEffects.Copy;
        };
        DragDrop += (_, e) =>
        {
            if (e.Data?.GetData(DataFormats.FileDrop) is string[] { Length: > 0 } files)
                _dropZone.SetFile(files[0]);
        };

        try
        {
            var exeIcon = Icon.ExtractAssociatedIcon(Environment.ProcessPath ?? Application.ExecutablePath);
            if (exeIcon != null) Icon = exeIcon;
        }
        catch { /* ignore in dev/test scenarios where icon isn't embedded */ }

        HandleStartupIntent(preloadPath, createVaultOnStart, createVaultTarget, createPackageOnStart, createPackageTarget, encryptFolderOnStart, encryptFolderTarget, useDefaultAutoLoadWhenEmpty: true);

        Paint += FormPaint;

        if (!File.Exists(ExePath))
            Load += (_, _) => WarnMissingCli();

        Shown += (_, _) =>
        {
            PromptShellSetupIfNeeded();
            if (preloadPath == null && !createVaultOnStart && !createPackageOnStart && !encryptFolderOnStart)
                PromptFirstRunKeypairSetupIfNeeded();
        };
        UpdateTextInputActionHints();
        UpdateVaultUiState();
        CleanupStaleExternalOpenSessions();
        MigrateLegacyVaultNewEntry();
    }

    public void HandleExternalLaunch(
        string? preloadPath,
        bool createVaultOnStart,
        string? createVaultTarget,
        bool createPackageOnStart,
        string? createPackageTarget,
        bool encryptFolderOnStart,
        string? encryptFolderTarget)
    {
        if (InvokeRequired)
        {
            BeginInvoke(new Action(() => HandleExternalLaunch(preloadPath, createVaultOnStart, createVaultTarget, createPackageOnStart, createPackageTarget, encryptFolderOnStart, encryptFolderTarget)));
            return;
        }

        if (WindowState == FormWindowState.Minimized)
            WindowState = FormWindowState.Normal;
        Show();
        Activate();
        BringToFront();

        HandleStartupIntent(preloadPath, createVaultOnStart, createVaultTarget, createPackageOnStart, createPackageTarget, encryptFolderOnStart, encryptFolderTarget, useDefaultAutoLoadWhenEmpty: false);
    }

    private void HandleStartupIntent(
        string? preloadPath,
        bool createVaultOnStart,
        string? createVaultTarget,
        bool createPackageOnStart,
        string? createPackageTarget,
        bool encryptFolderOnStart,
        string? encryptFolderTarget,
        bool useDefaultAutoLoadWhenEmpty)
    {
        if (!string.IsNullOrWhiteSpace(preloadPath))
        {
            if (preloadPath.EndsWith(".obsqpub", StringComparison.OrdinalIgnoreCase))
            {
                _tabs.SelectedIndex = 5; // Secure Contacts
                RunWhenHandleReady(() =>
                {
                    try
                    {
                        string text = File.ReadAllText(preloadPath);
                        if (_openAddContactDialog != null)
                            _openAddContactDialog(text, true);
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show(this, $"Unable to open public identity file:\n{ex.Message}", "Secure Contacts", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                    return Task.CompletedTask;
                });
                return;
            }

            if (IsNativeVaultPath(preloadPath))
                AutoPopulateVault(preloadPath);
            else
                AutoPopulate(preloadPath);
            return;
        }

        if (createVaultOnStart)
        {
            RunWhenHandleReady(() => StartCreateVaultWizardAsync(createVaultTarget));
            return;
        }

        if (createPackageOnStart && !string.IsNullOrWhiteSpace(createPackageTarget))
        {
            _tabs.SelectedIndex = 4; // Self-Extracting Package
            RunWhenHandleReady(() =>
            {
                try
                {
                    _openDeliveryWithSource?.Invoke(createPackageTarget);
                }
                catch (Exception ex)
                {
                    MessageBox.Show(this, $"Unable to load source for package creation:\n{ex.Message}", "Self-Extracting Package", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
                return Task.CompletedTask;
            });
            return;
        }

        if (encryptFolderOnStart && !string.IsNullOrWhiteSpace(encryptFolderTarget))
        {
            RunWhenHandleReady(() =>
            {
                try
                {
                    string zipPath = CreateTempZipFromFolderForEncrypt(encryptFolderTarget);
                    AutoPopulate(zipPath);
                    string desiredOut = BuildEncryptedOutputPathForFolder(encryptFolderTarget);
                    _lblOutPath.Text = desiredOut;
                    _lblOutPath.ForeColor = Theme.Accent;
                }
                catch (Exception ex)
                {
                    MessageBox.Show(this, $"Unable to prepare folder for encryption:\n{ex.Message}", "File Encryption", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
                return Task.CompletedTask;
            });
            return;
        }

        if (useDefaultAutoLoadWhenEmpty)
            TryAutoLoadDefaultKeyPath(force: false);
    }

    private void WarnMissingCli()
    {
        StatusError("obsidianq.exe not found - see startup warning.");
        MessageBox.Show(
            $"obsidianq.exe was not found at:\n  {ExePath}\n\n" +
            "This usually means one of:\n" +
            "  - The bundle was not fully extracted (both files must be in the same folder).\n" +
            "  - Windows Defender or another antivirus quarantined obsidianq.exe\n" +
            "    during extraction. Check your AV quarantine and restore the file.\n\n" +
            "Encryption and decryption will not work until obsidianq.exe is present\n" +
            "alongside ObsidianQ.Launcher.exe.",
            "obsidianq.exe not found",
            MessageBoxButtons.OK,
            MessageBoxIcon.Warning);
    }

    private void PromptShellSetupIfNeeded()
    {
        try
        {
            if (!ShouldOfferShellSetupPrompt()) return;

            using var dlg = new ShellSetupPromptForm();
            var result = dlg.ShowDialog(this);

            if (dlg.DontAskAgain)
                SetSkipShellSetupPrompt(true);

            if (result != DialogResult.Yes) return;

            InstallShellAndAssociations();
            MessageBox.Show(
                "ObsidianQ shell entries, .vault/.obsqpub associations, and New > Obsidian Vault have been installed.",
                "Integration installed",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                $"Failed to install shell entries/file associations:\n{ex.Message}",
                "Install failed",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
        }
    }

    private static bool ShouldOfferShellSetupPrompt()
    {
        if (GetSkipShellSetupPrompt()) return false;
        bool hasShellMenus = HasShellMenuEntries();
        bool hasVaultAssoc = HasVaultAssociation();
        bool hasIdentityAssoc = HasPublicIdentityAssociation();
        bool hasVaultNewItem = HasVaultNewMenuEntry();
        return !(hasShellMenus && hasVaultAssoc && hasIdentityAssoc && hasVaultNewItem);
    }

    private static bool GetSkipShellSetupPrompt()
    {
        using var key = Registry.CurrentUser.OpenSubKey(LauncherPrefsKey);
        return (key?.GetValue(SkipShellPromptValue) as int?) == 1;
    }

    private static void SetSkipShellSetupPrompt(bool skip)
    {
        using var key = Registry.CurrentUser.CreateSubKey(LauncherPrefsKey, true);
        key?.SetValue(SkipShellPromptValue, skip ? 1 : 0, RegistryValueKind.DWord);
    }

    private static bool GetSkipKeygenRiskPrompt()
    {
        using var key = Registry.CurrentUser.OpenSubKey(LauncherPrefsKey);
        return (key?.GetValue(SkipKeygenPromptValue) as int?) == 1;
    }

    private static void SetSkipKeygenRiskPrompt(bool skip)
    {
        using var key = Registry.CurrentUser.CreateSubKey(LauncherPrefsKey, true);
        key?.SetValue(SkipKeygenPromptValue, skip ? 1 : 0, RegistryValueKind.DWord);
    }

    private static bool GetFirstRunKeypairPrompted()
    {
        using var key = Registry.CurrentUser.OpenSubKey(LauncherPrefsKey);
        return (key?.GetValue(FirstRunKeypairPromptedValue) as int?) == 1;
    }

    private static void SetFirstRunKeypairPrompted(bool prompted)
    {
        using var key = Registry.CurrentUser.CreateSubKey(LauncherPrefsKey, true);
        key?.SetValue(FirstRunKeypairPromptedValue, prompted ? 1 : 0, RegistryValueKind.DWord);
    }

    private bool ConfirmKeyGenerationRisk()
    {
        if (GetSkipKeygenRiskPrompt()) return true;
        using var dlg = new KeygenRiskPromptForm();
        var result = dlg.ShowDialog(this);
        if (dlg.DontAskAgain)
            SetSkipKeygenRiskPrompt(true);
        return result == DialogResult.OK;
    }

    private static bool HasShellMenuEntries()
    {
        using var keyAny = Registry.CurrentUser.OpenSubKey(@"Software\Classes\*\shell\ObsidianQEncryptDecrypt\command");
        using var keyAnyPkg = Registry.CurrentUser.OpenSubKey(@"Software\Classes\*\shell\ObsidianQEncryptPackage\command");
        using var keyDir = Registry.CurrentUser.OpenSubKey(@"Software\Classes\Directory\shell\ObsidianQEncryptFolder\command");
        using var keyDirPkg = Registry.CurrentUser.OpenSubKey(@"Software\Classes\Directory\shell\ObsidianQEncryptPackage\command");
        using var keyObsq = Registry.CurrentUser.OpenSubKey(@"Software\Classes\obsq_auto_file\shell\ObsidianQDecrypt\command");
        return keyAny?.GetValue(null) is string
            && keyAnyPkg?.GetValue(null) is string
            && keyDir?.GetValue(null) is string
            && keyDirPkg?.GetValue(null) is string
            && keyObsq?.GetValue(null) is string;
    }

    private static bool HasVaultAssociation()
    {
        using var ext = Registry.CurrentUser.OpenSubKey(@"Software\Classes\.vault");
        using var extLegacy = Registry.CurrentUser.OpenSubKey(@"Software\Classes\.obsqv");
        var progId = ext?.GetValue(null) as string;
        var progIdLegacy = extLegacy?.GetValue(null) as string;
        bool vaultMapped = string.Equals(progId, "obsidianq_vault_file", StringComparison.OrdinalIgnoreCase);
        bool obsqvMapped = string.Equals(progIdLegacy, "obsidianq_vault_file", StringComparison.OrdinalIgnoreCase);
        if (!vaultMapped || !obsqvMapped)
            return false;

        using var cmd = Registry.CurrentUser.OpenSubKey(@"Software\Classes\obsidianq_vault_file\shell\open\command");
        return cmd?.GetValue(null) is string;
    }

    private static bool HasPublicIdentityAssociation()
    {
        using var ext = Registry.CurrentUser.OpenSubKey(@"Software\Classes\.obsqpub");
        var progId = ext?.GetValue(null) as string;
        if (!string.Equals(progId, "obsidianq_identity_file", StringComparison.OrdinalIgnoreCase))
            return false;
        using var cmd = Registry.CurrentUser.OpenSubKey(@"Software\Classes\obsidianq_identity_file\shell\open\command");
        return cmd?.GetValue(null) is string;
    }

    private static bool HasVaultNewMenuEntry()
    {
        string? cmdExt = Registry.CurrentUser
            .OpenSubKey(@"Software\Classes\.vault\ShellNew")
            ?.GetValue("Command") as string;
        string? cmdProg = Registry.CurrentUser
            .OpenSubKey(@"Software\Classes\obsidianq_vault_file\ShellNew")
            ?.GetValue("Command") as string;
        bool okExt = !string.IsNullOrWhiteSpace(cmdExt) && cmdExt.Contains("--create-vault", StringComparison.OrdinalIgnoreCase);
        bool okProg = !string.IsNullOrWhiteSpace(cmdProg) && cmdProg.Contains("--create-vault", StringComparison.OrdinalIgnoreCase);
        return okExt || okProg;
    }

    private static bool HasLegacyVaultNewNullFile()
    {
        bool ext = Registry.CurrentUser
            .OpenSubKey(@"Software\Classes\.vault\ShellNew")
            ?.GetValueNames()
            .Any(n => string.Equals(n, "NullFile", StringComparison.OrdinalIgnoreCase)) == true;
        bool prog = Registry.CurrentUser
            .OpenSubKey(@"Software\Classes\obsidianq_vault_file\ShellNew")
            ?.GetValueNames()
            .Any(n => string.Equals(n, "NullFile", StringComparison.OrdinalIgnoreCase)) == true;
        return ext || prog;
    }

    private static void MigrateLegacyVaultNewEntry()
    {
        try
        {
            if (HasVaultNewMenuEntry()) return;
            if (!HasLegacyVaultNewNullFile()) return;
            string launcherPath = Environment.ProcessPath ?? Application.ExecutablePath;
            using var keyExt = Registry.CurrentUser.CreateSubKey(@"Software\Classes\.vault\ShellNew", true);
            keyExt?.DeleteValue("NullFile", false);
            keyExt?.SetValue("Command", $"\"{launcherPath}\" --create-vault \"%1\"", RegistryValueKind.String);
            using var keyProg = Registry.CurrentUser.CreateSubKey(@"Software\Classes\obsidianq_vault_file\ShellNew", true);
            keyProg?.DeleteValue("NullFile", false);
            keyProg?.SetValue("Command", $"\"{launcherPath}\" --create-vault \"%1\"", RegistryValueKind.String);
            Registry.CurrentUser.Flush();
            ShellRefresh.NotifyAssocChanged();
        }
        catch
        {
            // best effort migration; prompt/install flow still handles missing entry
        }
    }

    private static void InstallShellAndAssociations()
    {
        string launcherPath = Environment.ProcessPath ?? Application.ExecutablePath;
        string iconValue = $"\"{launcherPath}\",0";
        string commandValue = $"\"{launcherPath}\" \"%1\"";
        string packageCommandValue = $"\"{launcherPath}\" --create-package \"%1\"";
        string folderEncryptCommandValue = $"\"{launcherPath}\" --encrypt-folder \"%1\"";

        using (var key = Registry.CurrentUser.CreateSubKey(@"Software\Classes\*\shell\ObsidianQEncryptDecrypt", true))
        {
            key?.SetValue(null, "ObsidianQ Encrypt File");
            key?.SetValue("Icon", iconValue);
            key?.SetValue("Position", "Bottom");
        }
        using (var key = Registry.CurrentUser.CreateSubKey(@"Software\Classes\*\shell\ObsidianQEncryptDecrypt\command", true))
            key?.SetValue(null, commandValue);
        using (var key = Registry.CurrentUser.CreateSubKey(@"Software\Classes\*\shell\ObsidianQEncryptPackage", true))
        {
            key?.SetValue(null, "ObsidianQ Encrypt and make Package");
            key?.SetValue("Icon", iconValue);
            key?.SetValue("Position", "Bottom");
        }
        using (var key = Registry.CurrentUser.CreateSubKey(@"Software\Classes\*\shell\ObsidianQEncryptPackage\command", true))
            key?.SetValue(null, packageCommandValue);

        using (var key = Registry.CurrentUser.CreateSubKey(@"Software\Classes\Directory\shell\ObsidianQEncryptPackage", true))
        {
            key?.SetValue(null, "ObsidianQ Encrypt Folder and make Package");
            key?.SetValue("Icon", iconValue);
            key?.SetValue("Position", "Bottom");
        }
        using (var key = Registry.CurrentUser.CreateSubKey(@"Software\Classes\Directory\shell\ObsidianQEncryptPackage\command", true))
            key?.SetValue(null, packageCommandValue);
        using (var key = Registry.CurrentUser.CreateSubKey(@"Software\Classes\Directory\shell\ObsidianQEncryptFolder", true))
        {
            key?.SetValue(null, "ObsidianQ Encrypt Folder");
            key?.SetValue("Icon", iconValue);
            key?.SetValue("Position", "Bottom");
        }
        using (var key = Registry.CurrentUser.CreateSubKey(@"Software\Classes\Directory\shell\ObsidianQEncryptFolder\command", true))
            key?.SetValue(null, folderEncryptCommandValue);

        using (var key = Registry.CurrentUser.CreateSubKey(@"Software\Classes\.obsq", true))
            key?.SetValue(null, "obsq_auto_file");
        using (var key = Registry.CurrentUser.CreateSubKey(@"Software\Classes\obsq_auto_file", true))
            key?.SetValue(null, "ObsidianQ Encrypted File");
        using (var key = Registry.CurrentUser.CreateSubKey(@"Software\Classes\obsq_auto_file\DefaultIcon", true))
            key?.SetValue(null, iconValue);
        using (var key = Registry.CurrentUser.CreateSubKey(@"Software\Classes\obsq_auto_file\shell\ObsidianQDecrypt", true))
        {
            key?.SetValue(null, "ObsidianQ Decrypt...");
            key?.SetValue("Icon", iconValue);
        }
        using (var key = Registry.CurrentUser.CreateSubKey(@"Software\Classes\obsq_auto_file\shell\ObsidianQDecrypt\command", true))
            key?.SetValue(null, commandValue);

        using (var key = Registry.CurrentUser.CreateSubKey(@"Software\Classes\.vault", true))
            key?.SetValue(null, "obsidianq_vault_file");
        using (var key = Registry.CurrentUser.CreateSubKey(@"Software\Classes\.obsqv", true))
            key?.SetValue(null, "obsidianq_vault_file");
        using (var key = Registry.CurrentUser.CreateSubKey(@"Software\Classes\.obsqpub", true))
            key?.SetValue(null, "obsidianq_identity_file");
        using (var key = Registry.CurrentUser.CreateSubKey(@"Software\Classes\.vault\ShellNew", true))
        {
            key?.DeleteValue("NullFile", false);
            key?.SetValue("Command", $"\"{launcherPath}\" --create-vault \"%1\"", RegistryValueKind.String);
        }
        using (var key = Registry.CurrentUser.CreateSubKey(@"Software\Classes\obsidianq_vault_file", true))
            key?.SetValue(null, "Obsidian Vault");
        using (var key = Registry.CurrentUser.CreateSubKey(@"Software\Classes\obsidianq_vault_file\ShellNew", true))
        {
            key?.DeleteValue("NullFile", false);
            key?.SetValue("Command", $"\"{launcherPath}\" --create-vault \"%1\"", RegistryValueKind.String);
        }
        using (var key = Registry.CurrentUser.CreateSubKey(@"Software\Classes\obsidianq_vault_file\DefaultIcon", true))
            key?.SetValue(null, iconValue);
        using (var key = Registry.CurrentUser.CreateSubKey(@"Software\Classes\obsidianq_vault_file\shell\open", true))
            key?.SetValue(null, "Open with ObsidianQ");
        using (var key = Registry.CurrentUser.CreateSubKey(@"Software\Classes\obsidianq_vault_file\shell\open\command", true))
            key?.SetValue(null, commandValue);
        using (var key = Registry.CurrentUser.CreateSubKey(@"Software\Classes\obsidianq_identity_file", true))
            key?.SetValue(null, "ObsidianQ Public Identity");
        using (var key = Registry.CurrentUser.CreateSubKey(@"Software\Classes\obsidianq_identity_file\DefaultIcon", true))
            key?.SetValue(null, iconValue);
        using (var key = Registry.CurrentUser.CreateSubKey(@"Software\Classes\obsidianq_identity_file\shell\open", true))
            key?.SetValue(null, "Open with ObsidianQ");
        using (var key = Registry.CurrentUser.CreateSubKey(@"Software\Classes\obsidianq_identity_file\shell\open\command", true))
            key?.SetValue(null, commandValue);
        using (var key = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.vault\OpenWithProgids", true))
            key?.SetValue("obsidianq_vault_file", Array.Empty<byte>(), RegistryValueKind.None);
        using (var key = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.obsqpub\OpenWithProgids", true))
            key?.SetValue("obsidianq_identity_file", Array.Empty<byte>(), RegistryValueKind.None);

        Registry.CurrentUser.Flush();
        ShellRefresh.NotifyAssocChanged();
    }

    private static void UninstallShellAndAssociations()
    {
        static void DeleteKeyTree(string subkey)
        {
            try { Registry.CurrentUser.DeleteSubKeyTree(subkey, throwOnMissingSubKey: false); } catch { /* best effort */ }
        }
        static void DeleteValue(string subkey, string valueName)
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(subkey, writable: true);
                key?.DeleteValue(valueName, throwOnMissingValue: false);
            }
            catch { /* best effort */ }
        }

        DeleteKeyTree(@"Software\Classes\*\shell\ObsidianQEncryptDecrypt");
        DeleteKeyTree(@"Software\Classes\*\shell\ObsidianQEncryptPackage");
        DeleteKeyTree(@"Software\Classes\Directory\shell\ObsidianQEncryptFolder");
        DeleteKeyTree(@"Software\Classes\Directory\shell\ObsidianQEncryptPackage");
        DeleteKeyTree(@"Software\Classes\obsq_auto_file");
        DeleteKeyTree(@"Software\Classes\obsidianq_vault_file");
        DeleteKeyTree(@"Software\Classes\obsidianq_identity_file");
        DeleteKeyTree(@"Software\Classes\.vault");
        DeleteKeyTree(@"Software\Classes\.obsqv");
        DeleteKeyTree(@"Software\Classes\.obsqpub");
        DeleteValue(@"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.vault\OpenWithProgids", "obsidianq_vault_file");
        DeleteValue(@"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.obsqpub\OpenWithProgids", "obsidianq_identity_file");

        Registry.CurrentUser.Flush();
        ShellRefresh.NotifyAssocChanged();
    }

    // -----------------------------------------------------------------------
    // Layout helpers
    // -----------------------------------------------------------------------
    private static Label MakeLabel(string text, float size = 9f, bool bold = false)
    {
        return new Label
        {
            Text = text, AutoSize = true,
            Font = bold ? Theme.SafeMono(size) : Theme.SafeMono(size),
            ForeColor = Theme.TextDim, BackColor = Color.Transparent,
        };
    }

    private static TableLayoutPanel MakeTabHeader(string title, string subtitle)
    {
        var titleLabel = MakeLabel(title, 10f, bold: true);
        titleLabel.ForeColor = Theme.Accent;
        titleLabel.Dock = DockStyle.Fill;
        titleLabel.TextAlign = ContentAlignment.MiddleLeft;
        titleLabel.Margin = new Padding(0, 0, 0, 0);
        titleLabel.AutoSize = false;

        var subtitleLabel = MakeLabel(subtitle, 8.5f);
        subtitleLabel.ForeColor = Theme.TextDim;
        subtitleLabel.Dock = DockStyle.Fill;
        subtitleLabel.TextAlign = ContentAlignment.MiddleLeft;
        subtitleLabel.Margin = new Padding(0, 0, 0, 0);
        subtitleLabel.AutoSize = false;

        var header = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 2,
            BackColor = Theme.Bg,
            Margin = new Padding(0, 0, 0, 0),
            Padding = new Padding(0, 0, 0, 4),
        };
        header.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        header.RowStyles.Add(new RowStyle(SizeType.Absolute, 24));
        header.RowStyles.Add(new RowStyle(SizeType.Absolute, 20));
        header.Controls.Add(titleLabel, 0, 0);
        header.Controls.Add(subtitleLabel, 0, 1);
        return header;
    }

    private static TextBox MakeTextBox(bool password = false)
    {
        return new TextBox
        {
            Dock = DockStyle.Fill, BackColor = Theme.Surface, ForeColor = Theme.Accent,
            BorderStyle = BorderStyle.FixedSingle, Margin = new Padding(0, 2, 0, 2),
            UseSystemPasswordChar = password,
        };
    }

    private static Panel MakeLabeled(string label, TextBox tb)
    {
        var p = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Bg, Margin = new Padding(0, 0, 4, 0) };
        var lbl = MakeLabel(label, 7.5f);
        lbl.Dock = DockStyle.Top; lbl.Height = 16;
        tb.Dock = DockStyle.Fill;
        p.Controls.Add(tb);
        p.Controls.Add(lbl);
        return p;
    }

    private static void BrowseKeyFile(TextBox target)
    {
        using var dlg = new OpenFileDialog
        {
            Title  = "Select key file",
            Filter = "Key files|*.bin;*.pem|BIN files|*.bin|PEM files|*.pem|All files|*.*",
        };
        if (dlg.ShowDialog() == DialogResult.OK) target.Text = dlg.FileName;
    }

    private void ShowSendCompleteDialog(string packagePath)
    {
        string fullPath = Path.GetFullPath(packagePath);
        string folder = Path.GetDirectoryName(fullPath) ?? Environment.CurrentDirectory;
        string name = Path.GetFileName(fullPath);
        long size = 0;
        try { if (File.Exists(fullPath)) size = new FileInfo(fullPath).Length; } catch { }

        using var dlg = new Form
        {
            Text = "Encryption Complete",
            StartPosition = FormStartPosition.CenterParent,
            FormBorderStyle = FormBorderStyle.FixedDialog,
            MaximizeBox = false,
            MinimizeBox = false,
            ShowInTaskbar = false,
            ClientSize = new Size(620, 300),
            BackColor = Theme.Bg,
            ForeColor = Theme.TextMain,
            Font = Theme.SafeMono(9f),
        };

        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 4, Padding = new Padding(14), BackColor = Theme.Bg };
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 170));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 36));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 36));

        var lbl = new Label
        {
            Dock = DockStyle.Fill,
            ForeColor = Theme.Accent,
            BackColor = Theme.Bg,
            TextAlign = ContentAlignment.TopLeft,
            Text = "Encryption Complete\r\n\r\n" +
                   $"Encrypted Package Created:\r\n{name}\r\nSize: {FormatBytes(size)}\r\n\r\n" +
                   $"Location:\r\n{folder}",
        };
        var row = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, RowCount = 1, BackColor = Theme.Bg };
        row.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        row.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        row.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 1));
        var btnOpen = new NeonButton { Text = "OPEN FOLDER", Dock = DockStyle.Fill, Margin = new Padding(0, 0, 4, 0) };
        var btnCopy = new NeonButton { Text = "COPY FILE PATH", Dock = DockStyle.Fill, Margin = new Padding(4, 0, 0, 0) };
        btnOpen.Click += (_, _) =>
        {
            try { Process.Start(new ProcessStartInfo("explorer.exe", $"\"{folder}\"") { UseShellExecute = true }); } catch { }
        };
        btnCopy.Click += (_, _) => { try { Clipboard.SetText(fullPath); } catch { } };
        row.Controls.Add(btnOpen, 0, 0);
        row.Controls.Add(btnCopy, 1, 0);
        var lblFoot = new Label
        {
            Dock = DockStyle.Fill,
            ForeColor = Theme.TextDim,
            BackColor = Theme.Bg,
            TextAlign = ContentAlignment.MiddleLeft,
            Text = "Send this file via email, messaging, or secure file transfer.",
        };
        var btnClose = new NeonButton { Text = "CLOSE", Dock = DockStyle.Right, Width = 120 };
        btnClose.Click += (_, _) => dlg.Close();
        var closeHost = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Bg };
        closeHost.Controls.Add(btnClose);

        root.Controls.Add(lbl, 0, 0);
        root.Controls.Add(row, 0, 1);
        root.Controls.Add(lblFoot, 0, 2);
        root.Controls.Add(closeHost, 0, 3);
        dlg.Controls.Add(root);
        dlg.ShowDialog(this);
    }

    private bool ShowReceiveInspectDialog(
        string packagePath,
        ref string outDir,
        string senderFingerprint,
        string matchedContact,
        string trustStatus,
        IReadOnlyList<string> packageContents)
    {
        using var dlg = new Form
        {
            Text = "Inspect Package",
            StartPosition = FormStartPosition.CenterParent,
            FormBorderStyle = FormBorderStyle.FixedDialog,
            MaximizeBox = false,
            MinimizeBox = false,
            ShowInTaskbar = false,
            ClientSize = new Size(700, 520),
            BackColor = Theme.Bg,
            ForeColor = Theme.TextMain,
            Font = Theme.SafeMono(9f),
        };

        long size = 0;
        try { if (File.Exists(packagePath)) size = new FileInfo(packagePath).Length; } catch { }
        var txtOut = new TextBox
        {
            Text = outDir,
            Dock = DockStyle.Fill,
            BackColor = Theme.Surface,
            ForeColor = Theme.Accent,
            BorderStyle = BorderStyle.FixedSingle,
        };
        txtOut.HandleCreated += (_, _) => SetWindowTheme(txtOut.Handle, "DarkMode_Explorer", null);

        var list = new ListBox
        {
            Dock = DockStyle.Fill,
            BackColor = Theme.Surface,
            ForeColor = Theme.TextMain,
            BorderStyle = BorderStyle.FixedSingle,
            IntegralHeight = false,
        };
        foreach (string item in packageContents)
            list.Items.Add(item);

        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 8, Padding = new Padding(14), BackColor = Theme.Bg };
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 56));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 84));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 34));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 8));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 36));

        var lblTop = new Label
        {
            Dock = DockStyle.Fill,
            ForeColor = Theme.Accent,
            BackColor = Theme.Bg,
            TextAlign = ContentAlignment.TopLeft,
            Text = $"Encrypted Package:\r\n{Path.GetFileName(packagePath)} ({FormatBytes(size)})",
        };
        var lblSender = new Label
        {
            Dock = DockStyle.Fill,
            ForeColor = Theme.TextMain,
            BackColor = Theme.Bg,
            TextAlign = ContentAlignment.TopLeft,
            Text = $"Sender Verification:\r\nFingerprint: {senderFingerprint}\r\nMatched Contact: {matchedContact}\r\nStatus: {trustStatus}",
        };
        var lblContents = MakeLabel("PACKAGE CONTENTS", 8f, bold: true); lblContents.Dock = DockStyle.Fill; lblContents.TextAlign = ContentAlignment.MiddleLeft;
        var lblOut = MakeLabel("EXTRACTION LOCATION", 8f, bold: true); lblOut.Dock = DockStyle.Fill; lblOut.TextAlign = ContentAlignment.MiddleLeft;
        var outRow = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, BackColor = Theme.Bg };
        outRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        outRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 92));
        var btnBrowse = new NeonButton { Text = "BROWSE", Dock = DockStyle.Fill, Margin = new Padding(0) };
        btnBrowse.Click += (_, _) =>
        {
            using var f = new FolderBrowserDialog { Description = "Select extraction folder", UseDescriptionForTitle = true, ShowNewFolderButton = true };
            if (f.ShowDialog(dlg) == DialogResult.OK) txtOut.Text = f.SelectedPath;
        };
        outRow.Controls.Add(txtOut, 0, 0);
        outRow.Controls.Add(btnBrowse, 1, 0);

        var actionRow = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, BackColor = Theme.Bg };
        actionRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        actionRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        var btnCancel = new NeonButton { Text = "CANCEL", Dock = DockStyle.Fill, Margin = new Padding(0, 0, 4, 0) };
        var btnDecrypt = new NeonButton { Text = "DECRYPT PACKAGE", Dock = DockStyle.Fill, Margin = new Padding(4, 0, 0, 0) };
        btnCancel.Click += (_, _) => { dlg.DialogResult = DialogResult.Cancel; dlg.Close(); };
        btnDecrypt.Click += (_, _) => { dlg.DialogResult = DialogResult.OK; dlg.Close(); };
        actionRow.Controls.Add(btnCancel, 0, 0);
        actionRow.Controls.Add(btnDecrypt, 1, 0);

        root.Controls.Add(lblTop, 0, 0);
        root.Controls.Add(lblSender, 0, 1);
        root.Controls.Add(lblContents, 0, 2);
        root.Controls.Add(list, 0, 3);
        root.Controls.Add(lblOut, 0, 4);
        root.Controls.Add(outRow, 0, 5);
        root.Controls.Add(new Panel { Dock = DockStyle.Fill, BackColor = Theme.Bg }, 0, 6);
        root.Controls.Add(actionRow, 0, 7);
        dlg.Controls.Add(root);

        bool ok = dlg.ShowDialog(this) == DialogResult.OK;
        if (ok) outDir = txtOut.Text.Trim();
        return ok;
    }

    private void ShowDecryptCompleteDialog(string outDir)
    {
        string safeDir = string.IsNullOrWhiteSpace(outDir) ? Environment.CurrentDirectory : outDir;
        var files = new List<string>();
        try
        {
            if (Directory.Exists(safeDir))
            {
                foreach (string f in Directory.GetFiles(safeDir, "*", SearchOption.AllDirectories).Take(200))
                    files.Add(Path.GetRelativePath(safeDir, f));
            }
        }
        catch { }

        using var dlg = new Form
        {
            Text = "Decryption Complete",
            StartPosition = FormStartPosition.CenterParent,
            FormBorderStyle = FormBorderStyle.FixedDialog,
            MaximizeBox = false,
            MinimizeBox = false,
            ShowInTaskbar = false,
            ClientSize = new Size(620, 360),
            BackColor = Theme.Bg,
            ForeColor = Theme.TextMain,
            Font = Theme.SafeMono(9f),
        };

        var list = new ListBox
        {
            Dock = DockStyle.Fill,
            BackColor = Theme.Surface,
            ForeColor = Theme.TextMain,
            BorderStyle = BorderStyle.FixedSingle,
            IntegralHeight = false,
        };
        if (files.Count == 0) list.Items.Add("(No files detected)");
        else foreach (var f in files) list.Items.Add(f);

        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 4, Padding = new Padding(14), BackColor = Theme.Bg };
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 74));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 36));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 36));
        var lbl = new Label
        {
            Dock = DockStyle.Fill,
            ForeColor = Theme.Accent,
            BackColor = Theme.Bg,
            TextAlign = ContentAlignment.TopLeft,
            Text = $"Decryption Complete\r\n\r\nFiles extracted to:\r\n{safeDir}",
        };
        var btnOpen = new NeonButton { Text = "OPEN FOLDER", Dock = DockStyle.Fill };
        btnOpen.Click += (_, _) =>
        {
            try { Process.Start(new ProcessStartInfo("explorer.exe", $"\"{safeDir}\"") { UseShellExecute = true }); } catch { }
        };
        var btnClose = new NeonButton { Text = "CLOSE", Dock = DockStyle.Fill };
        btnClose.Click += (_, _) => dlg.Close();
        root.Controls.Add(lbl, 0, 0);
        root.Controls.Add(list, 0, 1);
        root.Controls.Add(btnOpen, 0, 2);
        root.Controls.Add(btnClose, 0, 3);
        dlg.Controls.Add(root);
        dlg.ShowDialog(this);
    }

    private static void ApplyDarkThemeRecursive(Control root)
    {
        if (root is null) return;
        void ApplyNow(Control c)
        {
            if (c.IsHandleCreated)
                SetWindowTheme(c.Handle, "DarkMode_Explorer", null);
        }

        ApplyNow(root);
        root.HandleCreated += (_, _) =>
        {
            try { SetWindowTheme(root.Handle, "DarkMode_Explorer", null); } catch { }
        };

        foreach (Control child in root.Controls)
            ApplyDarkThemeRecursive(child);

        root.ControlAdded += (_, e) =>
        {
            if (e.Control is null) return;
            ApplyDarkThemeRecursive(e.Control);
        };
    }

    private void FormPaint(object? sender, PaintEventArgs e)
    {
        using var pen = new Pen(Theme.Border, 1f);
        e.Graphics.DrawRectangle(pen, 0, 0, Width - 1, Height - 1);
    }

    // -----------------------------------------------------------------------
    // FILE TAB – toggle / drop zone / key path handlers
    // -----------------------------------------------------------------------
    private void OnToggleChanged(object? sender, EventArgs e)
    {
        bool isPqc = _toggle.Selected == SegmentedToggle.Segment.Pqc;
        _pwPanel.Visible  = !isPqc;
        _pqcPanel.Visible =  isPqc;

        if (_btnAdvanced.Parent is TableLayoutPanel outer)
            outer.RowStyles[4] = new RowStyle(SizeType.Absolute, isPqc ? 26 : 44);

        UpdateKeyPlaceholder();
        if (isPqc) TryAutoLoadDefaultKeyPath(force: false);
    }

    private void OnFileDropped(object? sender, string path)
    {
        _lblOutPath.Text = path.EndsWith(".obsq", StringComparison.OrdinalIgnoreCase)
            ? Path.Combine(Path.GetDirectoryName(path)!, Path.GetFileNameWithoutExtension(path))
            : path + ".obsq";
        _lblOutPath.ForeColor = Theme.AccentDim;

        UpdateKeyPlaceholder();
        TryAutoLoadDefaultKeyPath(force: false);
    }

    private void ChangeOut_Click(object? sender, EventArgs e)
    {
        using var dlg = new SaveFileDialog
        {
            Title    = "Select output file",
            Filter   = "All files|*.*|ObsidianQ files|*.obsq",
            FileName = _lblOutPath.Text == "-" ? "" : _lblOutPath.Text,
        };
        if (dlg.ShowDialog() == DialogResult.OK)
        {
            _lblOutPath.Text      = dlg.FileName;
            _lblOutPath.ForeColor = Theme.Accent;
        }
    }

    private void BrowsePrivkey_Click(object? sender, EventArgs e)
    {
        using var dlg = new OpenFileDialog
        {
            Title  = "Select key file",
            Filter = "Key files|*.bin;*.pem|BIN files|*.bin|PEM files|*.pem|All files|*.*",
        };
        if (dlg.ShowDialog() == DialogResult.OK) _txtPrivkey.Text = dlg.FileName;
    }

    private async void BtnGenerateKeypair_Click(object? sender, EventArgs e)
        => await GenerateKeypairAsync(_btnGenerateKeypair, _txtPrivkey, preferPrivkey: !IsEncryptMode());

    // Shared keypair generation: runs obsidianq keygen, places pub+priv in LocalKeysDir,
    // then sets target to the appropriate path (pubkey when !preferPrivkey, privkey otherwise).
    private async Task GenerateKeypairAsync(NeonButton callerBtn, TextBox target, bool preferPrivkey)
    {
        if (!File.Exists(ExePath)) { StatusError($"obsidianq.exe not found at:\n{ExePath}"); return; }
        if (!ConfirmKeyGenerationRisk()) return;

        try
        {
            callerBtn.Enabled = false;
            var (exitCode, pubPath, privPath, stdout, stderr) = await RunWithBusyDialogAsync(
                "Key Generation",
                "Generating keypair...",
                () => RunDefaultKeygenAsync());

            if (!string.IsNullOrWhiteSpace(stdout)) Log(stdout.TrimEnd(), Theme.Accent);
            if (!string.IsNullOrWhiteSpace(stderr)) Log(stderr.TrimEnd(), Theme.Error);

            if (exitCode != 0) { StatusError($"Key generation failed (exit code {exitCode})."); return; }

            target.Text = preferPrivkey ? privPath : pubPath;
            StatusOk($"Generated new keypair (non-overwriting) in {Path.GetDirectoryName(pubPath)}");
            Log("[INFO] Keep old private keys if old vaults/files were encrypted with them.", Theme.AccentDim);
        }
        catch (Exception ex) { StatusError($"Key generation failed: {ex.Message}"); }
        finally { callerBtn.Enabled = true; }
    }

    private void AutoPopulate(string path)
    {
        _tabs.SelectedIndex = 0;
        _dropZone.SetFile(path);
        UpdateKeyPlaceholder();
        TryAutoLoadDefaultKeyPath(force: true);
        if (path.EndsWith(".obsq", StringComparison.OrdinalIgnoreCase))
            RunWhenHandleReady(() => TryAutoPrepareFileDecryptOnOpenAsync(path));
    }

    private static string CreateTempZipFromFolderForEncrypt(string folderPath)
    {
        if (string.IsNullOrWhiteSpace(folderPath) || !Directory.Exists(folderPath))
            throw new DirectoryNotFoundException("Folder not found.");

        string folderName = Path.GetFileName(Path.GetFullPath(folderPath).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        if (string.IsNullOrWhiteSpace(folderName)) folderName = "folder";
        string safeName = string.Concat(folderName.Select(ch => Path.GetInvalidFileNameChars().Contains(ch) ? '_' : ch));
        if (string.IsNullOrWhiteSpace(safeName)) safeName = "folder";

        string staging = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "ObsidianQ",
            "shell_staging");
        Directory.CreateDirectory(staging);

        string zipPath = Path.Combine(staging, $"{safeName}_{DateTime.Now:yyyyMMdd_HHmmss}.zip");
        ZipFile.CreateFromDirectory(folderPath, zipPath, CompressionLevel.Optimal, includeBaseDirectory: true);
        return zipPath;
    }

    private static string BuildEncryptedOutputPathForFolder(string folderPath)
    {
        string fullFolder = Path.GetFullPath(folderPath)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        string? parent = Path.GetDirectoryName(fullFolder);
        string folderName = Path.GetFileName(fullFolder);
        if (string.IsNullOrWhiteSpace(folderName)) folderName = "folder";
        string safeName = string.Concat(folderName.Select(ch => Path.GetInvalidFileNameChars().Contains(ch) ? '_' : ch));
        if (string.IsNullOrWhiteSpace(safeName)) safeName = "folder";
        string baseDir = string.IsNullOrWhiteSpace(parent) ? Environment.CurrentDirectory : parent;
        return Path.Combine(baseDir, $"{safeName}.obsq");
    }

    private void AutoPopulateVault(string path)
    {
        _tabs.SelectedIndex = 2;
        _suppressVaultFileDroppedHandler = true;
        try { _dropZoneVault.SetFile(path); }
        finally { _suppressVaultFileDroppedHandler = false; }
        RunWhenHandleReady(() => HandleVaultFileSelectedAsync(path, autoLoad: true));
        UpdateVaultUiState();
    }

    private async Task HandleVaultFileSelectedAsync(string path, bool autoLoad)
    {
        UpdateVaultUiState();
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return;

        var hint = DetectVaultAccessMode(path);
        if (hint == VaultAccessModeHint.Pqc)
        {
            _toggleVault.SetSelected(SegmentedToggle.Segment.Pqc);
            TryAutoLoadVaultKeyPath(force: false);
        }
        else if (hint == VaultAccessModeHint.Password)
        {
            _toggleVault.SetSelected(SegmentedToggle.Segment.Password);
        }

        if (IsNewVaultPlaceholder(path))
        {
            await InitializePlaceholderVaultAsync(path);
            UpdateVaultUiState();
            return;
        }

        if (autoLoad)
            await TryAutoLoadVaultOnOpenAsync(path);
        else if (VaultCredentialsReadyForList())
            await RefreshVaultContentsAsync();
        else
            VaultStatusOk("Vault loaded. Enter password/private key, then click LOAD VAULT.");

        UpdateVaultUiState();
    }

    private enum VaultAccessModeHint { Unknown, Password, Pqc }
    private enum ContainerAccessModeHint { Unknown, Password, Pqc }

    private static ContainerAccessModeHint DetectObsqAccessMode(string path)
    {
        try
        {
            if (!File.Exists(path)) return ContainerAccessModeHint.Unknown;
            byte[] head = new byte[8];
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            int n = fs.Read(head, 0, head.Length);
            if (n < 6) return ContainerAccessModeHint.Unknown;
            if (head[0] != (byte)'O' || head[1] != (byte)'B' || head[2] != (byte)'S' || head[3] != (byte)'Q')
                return ContainerAccessModeHint.Unknown;
            byte mode = head[5]; // [magic4][version1][mode1]
            return mode switch
            {
                0 => ContainerAccessModeHint.Password,
                1 => ContainerAccessModeHint.Pqc,
                _ => ContainerAccessModeHint.Unknown,
            };
        }
        catch
        {
            return ContainerAccessModeHint.Unknown;
        }
    }

    private static ContainerAccessModeHint DetectObsqAccessModeFromBase64(string b64)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(b64)) return ContainerAccessModeHint.Unknown;
            var sb = new StringBuilder(b64.Length);
            foreach (char ch in b64)
                if (!char.IsWhiteSpace(ch))
                    sb.Append(ch);
            byte[] raw = Convert.FromBase64String(sb.ToString());
            if (raw.Length < 6) return ContainerAccessModeHint.Unknown;
            if (raw[0] != (byte)'O' || raw[1] != (byte)'B' || raw[2] != (byte)'S' || raw[3] != (byte)'Q')
                return ContainerAccessModeHint.Unknown;
            byte mode = raw[5]; // [magic4][version1][mode1]
            return mode switch
            {
                0 => ContainerAccessModeHint.Password,
                1 => ContainerAccessModeHint.Pqc,
                _ => ContainerAccessModeHint.Unknown,
            };
        }
        catch
        {
            return ContainerAccessModeHint.Unknown;
        }
    }

    private bool TryResolveFilePrivateKey(out string keyPath)
    {
        keyPath = string.Empty;
        var keys = ParseRecipientKeyPaths(_txtPrivkey.Text);
        if (keys.Count == 0) return false;
        foreach (var k in keys)
        {
            if (File.Exists(k) && LooksLikePrivateKeyPath(k))
            {
                keyPath = k;
                return true;
            }
        }
        foreach (var k in keys)
        {
            if (File.Exists(k))
            {
                keyPath = k;
                return true;
            }
            if (LooksLikePublicKeyPath(k))
            {
                string? inferredPriv = InferPrivateKeyPathFromPublic(k);
                if (!string.IsNullOrWhiteSpace(inferredPriv) && File.Exists(inferredPriv))
                {
                    keyPath = inferredPriv;
                    return true;
                }
            }
        }
        return false;
    }

    private async Task TryAutoPrepareFileDecryptOnOpenAsync(string path)
    {
        if (!path.EndsWith(".obsq", StringComparison.OrdinalIgnoreCase)) return;
        if (!File.Exists(path)) return;
        if (_busy) return;

        var hint = DetectObsqAccessMode(path);
        bool isPqc;
        if (hint == ContainerAccessModeHint.Unknown)
        {
            var choice = MessageBox.Show(
                this,
                "Could not determine container access mode.\n\nYes = Password\nNo = PQC\nCancel = open only",
                "Open Encrypted File",
                MessageBoxButtons.YesNoCancel,
                MessageBoxIcon.Question,
                MessageBoxDefaultButton.Button1);
            if (choice == DialogResult.Cancel)
            {
                StatusOk("Encrypted file loaded. Provide credentials and click RUN.");
                return;
            }
            isPqc = choice == DialogResult.No;
        }
        else
        {
            isPqc = hint == ContainerAccessModeHint.Pqc;
        }

        _toggle.SetSelected(isPqc ? SegmentedToggle.Segment.Pqc : SegmentedToggle.Segment.Password);
        if (!TryConfirmAutoDecryptDestination(path, out var outPath))
        {
            StatusOk("Decryption cancelled.");
            return;
        }
        _lblOutPath.Text = outPath;
        _lblOutPath.ForeColor = Theme.Accent;

        if (isPqc)
        {
            TryAutoLoadDefaultKeyPath(force: true);
            if (!TryResolveFilePrivateKey(out var selectedPriv))
            {
                if (MessageBox.Show(
                    this,
                    "No local private key was found for this encrypted file.\n\nSelect a private key now?",
                    "Private Key Required",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Information) == DialogResult.Yes)
                {
                    BrowsePrivkey_Click(this, EventArgs.Empty);
                }
            }
            if (!TryResolveFilePrivateKey(out selectedPriv))
            {
                StatusError("No private key selected. Click RUN after selecting one.");
                return;
            }
            _txtPrivkey.Text = selectedPriv;
            await RunOperationAsync();
            return;
        }

        using var prompt = new TextPromptForm("Open Encrypted File", "Enter password:", password: true);
        if (prompt.ShowDialog(this) != DialogResult.OK)
        {
            StatusOk("Encrypted file loaded. Enter password and click RUN.");
            return;
        }
        if (string.IsNullOrWhiteSpace(prompt.Value))
        {
            StatusError("Password is required for decrypt.");
            return;
        }
        _txtPassword.Text = prompt.Value;
        await RunOperationAsync();
    }

    private bool TryConfirmAutoDecryptDestination(string inputPath, out string outputPath)
    {
        string defaultOut = Path.Combine(
            Path.GetDirectoryName(inputPath) ?? Environment.CurrentDirectory,
            Path.GetFileNameWithoutExtension(inputPath));

        outputPath = defaultOut;
        var choice = MessageBox.Show(
            this,
            "Decrypt to the same folder as the encrypted file?\n\n" +
            "Yes = same folder\nNo = choose destination folder\nCancel = abort",
            "Decrypt Destination",
            MessageBoxButtons.YesNoCancel,
            MessageBoxIcon.Question,
            MessageBoxDefaultButton.Button1);

        if (choice == DialogResult.Cancel) return false;
        if (choice == DialogResult.Yes) return true;

        using var dlg = new FolderBrowserDialog
        {
            Description = "Select destination folder for decrypted output",
            UseDescriptionForTitle = true,
            SelectedPath = Path.GetDirectoryName(defaultOut) ?? Environment.CurrentDirectory,
            ShowNewFolderButton = true,
        };
        if (dlg.ShowDialog(this) != DialogResult.OK || string.IsNullOrWhiteSpace(dlg.SelectedPath))
            return false;

        outputPath = Path.Combine(dlg.SelectedPath, Path.GetFileNameWithoutExtension(inputPath));
        return true;
    }

    private static VaultAccessModeHint DetectVaultAccessMode(string path)
    {
        try
        {
            if (!File.Exists(path)) return VaultAccessModeHint.Unknown;
            byte[] head = new byte[32];
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            int n = fs.Read(head, 0, head.Length);
            if (n < 8) return VaultAccessModeHint.Unknown;

            static bool StartsWith(byte[] data, int n, byte[] sig)
            {
                if (n < sig.Length) return false;
                for (int i = 0; i < sig.Length; i++) if (data[i] != sig[i]) return false;
                return true;
            }

            int magicLen;
            if (StartsWith(head, n, Encoding.ASCII.GetBytes("OBSQVAULT"))) magicLen = 9;
            else if (StartsWith(head, n, Encoding.ASCII.GetBytes("OBSQV"))) magicLen = 5;
            else if (StartsWith(head, n, Encoding.ASCII.GetBytes("OBSV"))) magicLen = 4;
            else return VaultAccessModeHint.Unknown;

            // [magic][version][mode]...
            if (n <= magicLen + 1) return VaultAccessModeHint.Unknown;
            byte mode = head[magicLen + 1];
            return mode switch
            {
                0 => VaultAccessModeHint.Password,
                1 => VaultAccessModeHint.Pqc,
                _ => VaultAccessModeHint.Unknown,
            };
        }
        catch
        {
            return VaultAccessModeHint.Unknown;
        }
    }

    private async Task TryAutoLoadVaultOnOpenAsync(string path)
    {
        var hint = DetectVaultAccessMode(path);
        bool isPqc;
        if (hint == VaultAccessModeHint.Unknown)
        {
            var choice = MessageBox.Show(
                this,
                "Could not determine vault access mode.\n\nYes = Password vault\nNo = PQC vault\nCancel = open tab only",
                "Load Vault",
                MessageBoxButtons.YesNoCancel,
                MessageBoxIcon.Question,
                MessageBoxDefaultButton.Button1);
            if (choice == DialogResult.Cancel)
            {
                VaultStatusOk("Vault loaded. Choose mode and click LOAD VAULT.");
                return;
            }
            isPqc = choice == DialogResult.No;
        }
        else
        {
            isPqc = hint == VaultAccessModeHint.Pqc;
        }

        _toggleVault.SetSelected(isPqc ? SegmentedToggle.Segment.Pqc : SegmentedToggle.Segment.Password);

        if (isPqc)
        {
            TryAutoLoadVaultKeyPath(force: true);
            if (!TryResolveVaultPrivateKey(out var selectedPriv))
            {
                if (MessageBox.Show(
                    this,
                    "No local private key was found for this PQC vault.\n\nSelect a private key now?",
                    "Private Key Required",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Information) == DialogResult.Yes)
                {
                    BrowseKeyFile(_txtPrivkeyVault);
                }
            }
            if (!TryResolveVaultPrivateKey(out selectedPriv))
            {
                VaultStatusError("No private key selected. Click LOAD VAULT after selecting one.");
                return;
            }
            _txtPrivkeyVault.Text = selectedPriv;
            await RefreshVaultContentsAsync();
            return;
        }

        using var prompt = new TextPromptForm("Load Vault", "Enter vault password:", password: true);
        if (prompt.ShowDialog(this) != DialogResult.OK)
        {
            VaultStatusOk("Vault loaded. Enter password and click LOAD VAULT.");
            return;
        }
        if (string.IsNullOrWhiteSpace(prompt.Value))
        {
            VaultStatusError("Password is required to load this vault.");
            return;
        }
        _txtPasswordVault.Text = prompt.Value;
        await RefreshVaultContentsAsync();
    }

    private void RunWhenHandleReady(Func<Task> action)
    {
        if (IsHandleCreated)
        {
            BeginInvoke(new Action(() => _ = action()));
            return;
        }

        EventHandler? shown = null;
        shown = (_, _) =>
        {
            Shown -= shown;
            _ = action();
        };
        Shown += shown;
    }

    private static bool IsNewVaultPlaceholder(string path)
    {
        if (!path.EndsWith(".vault", StringComparison.OrdinalIgnoreCase)) return false;
        try
        {
            return File.Exists(path) && new FileInfo(path).Length == 0;
        }
        catch
        {
            return false;
        }
    }

    private async Task InitializePlaceholderVaultAsync(string path)
    {
        if (!IsNewVaultPlaceholder(path)) return;
        var prompt = MessageBox.Show(
            $"'{Path.GetFileName(path)}' is a new placeholder vault.\n\nInitialize it now?",
            "Initialize vault",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Question,
            MessageBoxDefaultButton.Button1);
        if (prompt != DialogResult.Yes)
        {
            VaultStatusError("Vault not initialized yet.");
            return;
        }

        using var form = new VaultInitForm(path, ResolveDefaultPublicKeyPathForCreateWizard());
        if (form.ShowDialog(this) != DialogResult.OK) return;

        try
        {
            bool ok = await CreateVaultFromWizardAsync(form);
            if (!ok) return;
            if (!string.Equals(path, form.VaultPath, StringComparison.OrdinalIgnoreCase) && IsNewVaultPlaceholder(path))
            {
                try { File.Delete(path); } catch { /* best effort */ }
            }
        }
        catch (Exception ex)
        {
            VaultStatusError($"Initialize failed: {ex.Message}");
        }
    }

    private async Task StartCreateVaultWizardAsync(string? targetPath = null)
    {
        _tabs.SelectedIndex = 2;
        _toggleVault.GetType(); // ensure tab controls initialized

        string initialPath = !string.IsNullOrWhiteSpace(targetPath)
            ? targetPath!
            : Path.Combine(Environment.CurrentDirectory, "New Vault.vault");
        if (!initialPath.EndsWith(".vault", StringComparison.OrdinalIgnoreCase))
            initialPath += ".vault";

        using var init = new VaultInitForm(initialPath, ResolveDefaultPublicKeyPathForCreateWizard());
        if (init.ShowDialog(this) != DialogResult.OK) return;

        try
        {
            await CreateVaultFromWizardAsync(init);
        }
        catch (Exception ex)
        {
            VaultStatusError($"Create wizard failed: {ex.Message}");
        }
    }

    private async Task<bool> CreateVaultFromWizardAsync(VaultInitForm init)
    {
        if (!File.Exists(ExePath)) { VaultStatusError("obsidianq.exe not found."); return false; }

        string path = init.VaultPath;
        if (string.IsNullOrWhiteSpace(path))
        {
            VaultStatusError("Vault path is required.");
            return false;
        }

        string? dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrWhiteSpace(dir))
            Directory.CreateDirectory(dir);

        if (File.Exists(path))
        {
            var overwrite = MessageBox.Show(
                this,
                $"'{Path.GetFileName(path)}' already exists. Overwrite it?",
                "Overwrite vault",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button2);
            if (overwrite != DialogResult.Yes) return false;
            File.Delete(path);
        }

        bool isPqc = init.UsePqc;
        string args;
        if (isPqc)
        {
            var pubkeys = ParseRecipientKeyPaths(init.PubkeyPath);
            string? localPub = ResolveDefaultPublicKeyPathForCreateWizard();
            if (!string.IsNullOrWhiteSpace(localPub) && File.Exists(localPub))
                pubkeys.Insert(0, localPub);
            pubkeys = pubkeys
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Where(File.Exists)
                .ToList();
            if (pubkeys.Count == 0) { VaultStatusError("PQC vault creation requires at least one public key."); return false; }
            var sbCreate = new StringBuilder($"vault create --out \"{path}\"");
            foreach (var k in pubkeys) sbCreate.Append($" --pubkey \"{k}\"");
            args = sbCreate.ToString();
        }
        else
        {
            args = $"vault create --out \"{path}\" --password-stdin";
        }
        string? stdinPassword = isPqc ? null : init.Password;

        var (exitCode, stdout, stderr) = await RunVaultCliAsync(args, stdinPassword);
        if (!string.IsNullOrWhiteSpace(stdout)) LogVault(stdout.TrimEnd(), Theme.Accent);
        if (!string.IsNullOrWhiteSpace(stderr)) LogVault(stderr.TrimEnd(), Theme.Error);
        if (exitCode != 0)
        {
            VaultStatusError($"vault create failed (exit {exitCode}).");
            return false;
        }

        _suppressVaultFileDroppedHandler = true;
        try { _dropZoneVault.SetFile(path); }
        finally { _suppressVaultFileDroppedHandler = false; }
        if (!isPqc)
        {
            _toggleVault.SetSelected(SegmentedToggle.Segment.Password);
            _txtPasswordVault.Text = init.Password;
        }
        else
        {
            _toggleVault.SetSelected(SegmentedToggle.Segment.Pqc);
            if (string.IsNullOrWhiteSpace(_txtPrivkeyVault.Text) || !File.Exists(_txtPrivkeyVault.Text))
            {
                string? inferredPriv = InferPrivateKeyPathFromPublic(init.PubkeyPath);
                if (!string.IsNullOrWhiteSpace(inferredPriv) && File.Exists(inferredPriv))
                    _txtPrivkeyVault.Text = inferredPriv;
            }
            TryAutoLoadVaultKeyPath(force: false);
        }

        if (!isPqc)
        {
            VaultStatusOk("Vault created and loaded.");
            await RefreshVaultContentsAsync();
        }
        else
        {
            VaultStatusOk("PQC vault created. Provide private key and click LOAD VAULT.");
            if (!string.IsNullOrWhiteSpace(_txtPrivkeyVault.Text) && File.Exists(_txtPrivkeyVault.Text))
                await RefreshVaultContentsAsync();
        }
        return true;
    }

    private void BtnUnloadVault_Click(object? sender, EventArgs e)
    {
        if (_mountProc != null)
        {
            VaultStatusError("Unmount the vault drive before unloading.");
            return;
        }
        _dropZoneVault.ClearFile();
        _txtPasswordVault.Clear();
        _txtPrivkeyVault.Clear();
        _tvVaultContents.Nodes.Clear();
        _tvVaultContents.SelectedNode = null;
        VaultStatusOk("Vault unloaded.");
        UpdateVaultUiState();
    }

    private void UpdateVaultUiState()
    {
        bool hasVault = !string.IsNullOrWhiteSpace(_dropZoneVault.FilePath) && File.Exists(_dropZoneVault.FilePath);
        bool hasSelection = GetCheckedOrSelectedVaultItems().Count > 0;

        _btnLoadVault.Enabled = hasVault;
        _btnRekeyVault.Enabled = hasVault;
        _btnUnloadVault.Enabled = hasVault && _mountProc == null;
        _btnAddToVault.Enabled = hasVault;
        _btnRemoveVaultItem.Enabled = hasVault && hasSelection;
        _btnExtractVaultItem.Enabled = hasVault && hasSelection;
        if (_mountProc == null) _btnMountVault.Enabled = hasVault;
        UpdateVaultEmptyHint();
        UpdateVaultSelectionSummary();
    }

    private void UpdateVaultEmptyHint()
    {
        bool hasVault = !string.IsNullOrWhiteSpace(_dropZoneVault.FilePath) && File.Exists(_dropZoneVault.FilePath);
        _lblVaultEmptyHint.Visible = hasVault && _tvVaultContents.Nodes.Count == 0;
        if (_lblVaultEmptyHint.Visible) _lblVaultEmptyHint.BringToFront();
    }

    private void UpdateVaultSelectionSummary()
    {
        int checkedCount = CountCheckedNodes(_tvVaultContents.Nodes);
        string active = _tvVaultContents.SelectedNode?.Tag is ValueTuple<string, bool, long, string> t ? t.Item1 : "-";
        _lblVaultSelection.Text = $"Checked: {checkedCount}  Active: {active}";
    }

    private static int CountCheckedNodes(TreeNodeCollection nodes)
    {
        int n = 0;
        foreach (TreeNode node in nodes)
        {
            if (node.Checked) n++;
            n += CountCheckedNodes(node.Nodes);
        }
        return n;
    }

    private List<(string Path, bool IsDir)> GetCheckedOrSelectedVaultItems()
    {
        var checkedTop = new List<(string Path, bool IsDir)>();
        foreach (TreeNode n in _tvVaultContents.Nodes)
            CollectCheckedTopLevel(n, ancestorChecked: false, checkedTop);
        if (checkedTop.Count > 0) return checkedTop;

        if (_tvVaultContents.SelectedNode?.Tag is ValueTuple<string, bool, long, string> t && !string.IsNullOrWhiteSpace(t.Item1))
            return new List<(string Path, bool IsDir)> { (t.Item1, t.Item2) };
        return new List<(string Path, bool IsDir)>();
    }

    private Dictionary<string, TreeNode> BuildVaultNodeMap()
    {
        var map = new Dictionary<string, TreeNode>(StringComparer.Ordinal);
        foreach (TreeNode n in _tvVaultContents.Nodes)
            IndexVaultNodeRecursive(n, map);
        return map;
    }

    private static void IndexVaultNodeRecursive(TreeNode node, Dictionary<string, TreeNode> map)
    {
        if (node.Tag is ValueTuple<string, bool, long, string> t && !string.IsNullOrWhiteSpace(t.Item1))
            map[t.Item1] = node;
        foreach (TreeNode child in node.Nodes)
            IndexVaultNodeRecursive(child, map);
    }

    private static List<(string Path, bool IsDir)> CollectVaultSubtreeItems(TreeNode node)
    {
        var items = new List<(string Path, bool IsDir)>();
        CollectVaultSubtreeItemsRecursive(node, items);
        return items;
    }

    private static void CollectVaultSubtreeItemsRecursive(TreeNode node, List<(string Path, bool IsDir)> acc)
    {
        if (node.Tag is ValueTuple<string, bool, long, string> t && !string.IsNullOrWhiteSpace(t.Item1))
            acc.Add((t.Item1, t.Item2));
        foreach (TreeNode child in node.Nodes)
            CollectVaultSubtreeItemsRecursive(child, acc);
    }

    private static string GetVaultParentLocalSubdir(string vaultFilePath)
    {
        string clean = vaultFilePath.Trim('/');
        int slash = clean.LastIndexOf('/');
        if (slash <= 0) return string.Empty;
        return clean[..slash].Replace('/', Path.DirectorySeparatorChar);
    }

    private sealed record AddWorkItem(string SrcPath, string? DestPath, string DisplayPath);

    private static List<AddWorkItem> BuildAddWorkItems(IEnumerable<string> sourcePaths)
    {
        var work = new List<AddWorkItem>();
        foreach (string src in sourcePaths.Where(p => !string.IsNullOrWhiteSpace(p)))
        {
            if (File.Exists(src))
            {
                work.Add(new AddWorkItem(src, null, src));
                continue;
            }
            if (!Directory.Exists(src)) continue;

            string rootName = Path.GetFileName(src.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
            var files = Directory.EnumerateFiles(src, "*", SearchOption.AllDirectories).ToList();
            if (files.Count == 0)
            {
                work.Add(new AddWorkItem(src, null, src));
                continue;
            }
            foreach (var file in files)
            {
                string rel = Path.GetRelativePath(src, file).Replace('\\', '/');
                string dest = $"/{rootName}/{rel}";
                work.Add(new AddWorkItem(file, dest, dest));
            }
        }
        return work;
    }

    private static void CollectCheckedTopLevel(TreeNode node, bool ancestorChecked, List<(string Path, bool IsDir)> acc)
    {
        bool isChecked = node.Checked;
        if (isChecked && !ancestorChecked && node.Tag is ValueTuple<string, bool, long, string> t && !string.IsNullOrWhiteSpace(t.Item1))
            acc.Add((t.Item1, t.Item2));
        bool nextAncestor = ancestorChecked || isChecked;
        foreach (TreeNode child in node.Nodes)
            CollectCheckedTopLevel(child, nextAncestor, acc);
    }

    private bool IsEncryptMode()
        => !((_dropZone.FilePath ?? string.Empty).EndsWith(".obsq", StringComparison.OrdinalIgnoreCase));

    private string SelectDefaultKeyPathForCurrentOperation(string pubPath, string privPath)
        => IsEncryptMode() ? pubPath : privPath;

    private void UpdateKeyPlaceholder()
    {
        _txtPrivkey.PlaceholderText = IsEncryptMode()
            ? "Path to public key (.bin default, .pem also supported)"
            : "Path to private key (.bin default, .pem also supported)";
    }

    private string EnsureDefaultKeyDir()
    {
        Directory.CreateDirectory(LocalKeysDir);
        return LocalKeysDir;
    }

    private static bool IsPublicKeyName(string fileName)
    {
        return fileName.Contains("_pub", StringComparison.OrdinalIgnoreCase)
            || fileName.Contains("public", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsPrivateKeyName(string fileName)
    {
        return fileName.Contains("_priv", StringComparison.OrdinalIgnoreCase)
            || fileName.Contains("private", StringComparison.OrdinalIgnoreCase);
    }

    private static string? FindLatestKeyPath(bool wantPublic, params string[] dirs)
    {
        var candidates = new List<FileInfo>();
        foreach (string dir in dirs)
        {
            if (string.IsNullOrWhiteSpace(dir) || !Directory.Exists(dir)) continue;
            foreach (var fi in new DirectoryInfo(dir).EnumerateFiles("*.*", SearchOption.TopDirectoryOnly))
            {
                if (!fi.Extension.Equals(".bin", StringComparison.OrdinalIgnoreCase)
                    && !fi.Extension.Equals(".pem", StringComparison.OrdinalIgnoreCase))
                    continue;
                if (!fi.Name.StartsWith("obsidianq", StringComparison.OrdinalIgnoreCase))
                    continue;
                bool isMatch = wantPublic ? IsPublicKeyName(fi.Name) : IsPrivateKeyName(fi.Name);
                if (!isMatch) continue;
                candidates.Add(fi);
            }
        }

        return candidates
            .OrderByDescending(f => f.LastWriteTimeUtc)
            .ThenByDescending(f => f.DirectoryName?.StartsWith(LocalKeysDir, StringComparison.OrdinalIgnoreCase) ?? false)
            .Select(f => f.FullName)
            .FirstOrDefault();
    }

    private static bool TryResolveLatestLocalKeypair(out string pubPath, out string privPath, out string note)
    {
        note = string.Empty;
        pubPath = FindLatestKeyPath(wantPublic: true, LocalKeysDir) ?? string.Empty;
        privPath = FindLatestKeyPath(wantPublic: false, LocalKeysDir) ?? string.Empty;
        if (string.IsNullOrWhiteSpace(pubPath) || string.IsNullOrWhiteSpace(privPath))
            return false;

        string? inferredPriv = InferPrivateKeyPathFromPublic(pubPath);
        if (!string.IsNullOrWhiteSpace(inferredPriv) && File.Exists(inferredPriv))
        {
            privPath = inferredPriv;
            return true;
        }

        string? inferredPub = InferPublicKeyPathFromPrivate(privPath);
        if (!string.IsNullOrWhiteSpace(inferredPub) && File.Exists(inferredPub))
        {
            pubPath = inferredPub;
            return true;
        }

        note = "Using latest local public/private files. They may be from different generations.";
        return true;
    }

    private static (string PubPath, string PrivPath) BuildVersionedKeyPaths(string keysDir)
    {
        string stamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
        int suffix = 0;
        while (true)
        {
            string infix = suffix == 0 ? "" : $"_{suffix:00}";
            string pub = Path.Combine(keysDir, $"obsidianq_{stamp}{infix}_pub.bin");
            string priv = Path.Combine(keysDir, $"obsidianq_{stamp}{infix}_priv.bin");
            if (!File.Exists(pub) && !File.Exists(priv))
                return (pub, priv);
            suffix++;
        }
    }

    private async Task<(int ExitCode, string PubPath, string PrivPath, string Stdout, string Stderr)> RunDefaultKeygenAsync()
    {
        if (!File.Exists(ExePath))
            return (-1, string.Empty, string.Empty, string.Empty, "obsidianq.exe not found.");

        string keysDir = EnsureDefaultKeyDir();
        var (pubPath, privPath) = BuildVersionedKeyPaths(keysDir);
        var psi = new ProcessStartInfo
        {
            FileName = ExePath,
            Arguments = $"keygen --pubkey \"{pubPath}\" --privkey \"{privPath}\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        using var proc = new Process { StartInfo = psi };
        proc.Start();
        string stdout = await proc.StandardOutput.ReadToEndAsync();
        string stderr = await proc.StandardError.ReadToEndAsync();
        await proc.WaitForExitAsync();
        return (proc.ExitCode, pubPath, privPath, stdout, stderr);
    }

    private string? ResolveDefaultPublicKeyPathForCreateWizard()
    {
        return FindLatestKeyPath(wantPublic: true, LocalKeysDir, BundleKeysDir);
    }

    private static string? InferPrivateKeyPathFromPublic(string? pubkeyPath)
    {
        if (string.IsNullOrWhiteSpace(pubkeyPath)) return null;
        string path = pubkeyPath!;
        string file = Path.GetFileName(path);
        if (string.IsNullOrWhiteSpace(file)) return null;

        string inferredFile = file
            .Replace("_pub", "_priv", StringComparison.OrdinalIgnoreCase)
            .Replace("public", "private", StringComparison.OrdinalIgnoreCase);
        if (string.Equals(inferredFile, file, StringComparison.OrdinalIgnoreCase))
            return null;
        return Path.Combine(Path.GetDirectoryName(path) ?? string.Empty, inferredFile);
    }

    private static string? InferPublicKeyPathFromPrivate(string? privkeyPath)
    {
        if (string.IsNullOrWhiteSpace(privkeyPath)) return null;
        string path = privkeyPath!;
        string file = Path.GetFileName(path);
        if (string.IsNullOrWhiteSpace(file)) return null;

        string inferredFile = file
            .Replace("_priv", "_pub", StringComparison.OrdinalIgnoreCase)
            .Replace("private", "public", StringComparison.OrdinalIgnoreCase);
        if (string.Equals(inferredFile, file, StringComparison.OrdinalIgnoreCase))
            return null;
        return Path.Combine(Path.GetDirectoryName(path) ?? string.Empty, inferredFile);
    }

    private static bool LooksLikePublicKeyPath(string? keyPath)
    {
        if (string.IsNullOrWhiteSpace(keyPath)) return false;
        string name = Path.GetFileName(keyPath);
        return name.Contains("_pub", StringComparison.OrdinalIgnoreCase)
            || name.Contains("public", StringComparison.OrdinalIgnoreCase);
    }

    private static bool LooksLikePrivateKeyPath(string? keyPath)
    {
        if (string.IsNullOrWhiteSpace(keyPath)) return false;
        string name = Path.GetFileName(keyPath);
        return name.Contains("_priv", StringComparison.OrdinalIgnoreCase)
            || name.Contains("private", StringComparison.OrdinalIgnoreCase);
    }

    private static string BuildVaultBackupPath(string srcVault)
    {
        string dir = Path.GetDirectoryName(srcVault) ?? Environment.CurrentDirectory;
        string file = Path.GetFileName(srcVault);
        string candidate = Path.Combine(dir, file + ".bak");
        if (!File.Exists(candidate)) return candidate;
        for (int i = 1; i <= 999; i++)
        {
            candidate = Path.Combine(dir, $"{file}.bak.{i:000}");
            if (!File.Exists(candidate)) return candidate;
        }
        string stamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
        return Path.Combine(dir, $"{file}.bak.{stamp}");
    }

    private static string SwapInRekeyedVault(string srcVault, string dstVault)
    {
        string backupPath = BuildVaultBackupPath(srcVault);
        File.Move(srcVault, backupPath);
        try
        {
            File.Move(dstVault, srcVault);
            return backupPath;
        }
        catch
        {
            try
            {
                if (!File.Exists(srcVault) && File.Exists(backupPath))
                    File.Move(backupPath, srcVault);
            }
            catch { /* best effort rollback */ }
            throw;
        }
    }

    private static string BuildVaultUpdatedCandidatePath(string srcVault)
    {
        string dir = Path.GetDirectoryName(srcVault) ?? Environment.CurrentDirectory;
        string stem = Path.GetFileNameWithoutExtension(srcVault);
        string ext = Path.GetExtension(srcVault);
        if (string.IsNullOrWhiteSpace(ext)) ext = ".vault";
        string stamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
        string candidate = Path.Combine(dir, $"{stem}_updated_{stamp}{ext}");
        int i = 1;
        while (File.Exists(candidate))
        {
            candidate = Path.Combine(dir, $"{stem}_updated_{stamp}_{i:00}{ext}");
            i++;
        }
        return candidate;
    }

    private void TryAutoLoadDefaultKeyPath(bool force)
    {
        if (_toggle.Selected != SegmentedToggle.Segment.Pqc) return;
        if (!force && ParseRecipientKeyPaths(_txtPrivkey.Text).Any(File.Exists)) return;
        string? latest = IsEncryptMode()
            ? FindLatestKeyPath(wantPublic: true, LocalKeysDir, BundleKeysDir)
            : FindLatestKeyPath(wantPublic: false, LocalKeysDir, BundleKeysDir);
        if (!string.IsNullOrWhiteSpace(latest)) _txtPrivkey.Text = latest;
    }

    // Text tab auto-load: tries privkey first (decrypt is the dominant text-mode use case),
    // falls back to pubkey. Does not overwrite a valid existing path unless force = true.
    private void TryAutoLoadTextKeyPath(bool force)
    {
        if (!force && ParseRecipientKeyPaths(_txtPrivkeyText.Text).Any(File.Exists)) return;
        string? latestPriv = FindLatestKeyPath(wantPublic: false, LocalKeysDir, BundleKeysDir);
        if (!string.IsNullOrWhiteSpace(latestPriv)) { _txtPrivkeyText.Text = latestPriv; return; }
        string? latestPub = FindLatestKeyPath(wantPublic: true, LocalKeysDir, BundleKeysDir);
        if (!string.IsNullOrWhiteSpace(latestPub)) _txtPrivkeyText.Text = latestPub;
    }

    // At click time, silently refine the key path for the specific operation type
    // (pubkey for encrypt, privkey for decrypt). No-ops if a valid path is already set.
    private static void TrySilentKeyLoad(TextBox target, string[] names)
    {
        if (!string.IsNullOrWhiteSpace(target.Text))
        {
            var parts = target.Text.Split(new[] { ';', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(s => s.Trim().Trim('"'));
            if (parts.Any(File.Exists)) return;
        }
        bool wantPublic = names.Contains("obsidianq_test_pub.bin", StringComparer.OrdinalIgnoreCase)
            || names.Contains("obsidianq_pub.bin", StringComparer.OrdinalIgnoreCase);
        string? latest = FindLatestKeyPath(wantPublic, LocalKeysDir, BundleKeysDir);
        if (!string.IsNullOrWhiteSpace(latest)) target.Text = latest;
    }

    // Vault tab auto-load: vault is always decrypt, so privkey only.
    private void TryAutoLoadVaultKeyPath(bool force)
    {
        if (!force && !string.IsNullOrWhiteSpace(_txtPrivkeyVault.Text) && File.Exists(_txtPrivkeyVault.Text)) return;
        string? latest = FindLatestKeyPath(wantPublic: false, LocalKeysDir, BundleKeysDir);
        if (!string.IsNullOrWhiteSpace(latest)) _txtPrivkeyVault.Text = latest;
    }

    // Returns the highest available drive letter (scanning Z→D).
    private static char FindFirstAvailableDriveLetter()
    {
        var used = new HashSet<char>(
            DriveInfo.GetDrives().Select(d => char.ToUpperInvariant(d.Name[0])));
        for (char c = 'Z'; c >= 'D'; c--)
            if (!used.Contains(c)) return c;
        return 'Z'; // fallback (should not happen in practice)
    }

    // Refreshes _txtDriveLetter only if the current value is already taken.
    private void RefreshDriveLetter()
    {
        string cur = _txtDriveLetter.Text.Trim().TrimEnd(':').ToUpperInvariant();
        if (cur.Length == 1 && cur[0] >= 'A' && cur[0] <= 'Z')
        {
            var used = new HashSet<char>(
                DriveInfo.GetDrives().Select(d => char.ToUpperInvariant(d.Name[0])));
            if (!used.Contains(cur[0])) return; // still free — leave it alone
        }
        _txtDriveLetter.Text = FindFirstAvailableDriveLetter().ToString();
    }

    // -----------------------------------------------------------------------
    // TEXT TAB – toggle / encrypt / decrypt handlers
    // -----------------------------------------------------------------------
    private enum TextInputKind
    {
        Empty,
        Ciphertext,
        Plaintext,
        Ambiguous,
    }

    private static bool IsBase64Alphabet(char ch)
    {
        return (ch >= 'A' && ch <= 'Z')
            || (ch >= 'a' && ch <= 'z')
            || (ch >= '0' && ch <= '9')
            || ch == '+' || ch == '/' || ch == '=';
    }

    private static TextInputKind ClassifyTextInput(string input, out ContainerAccessModeHint detectedMode)
    {
        detectedMode = ContainerAccessModeHint.Unknown;
        if (string.IsNullOrWhiteSpace(input)) return TextInputKind.Empty;

        detectedMode = DetectObsqAccessModeFromBase64(input);
        if (detectedMode != ContainerAccessModeHint.Unknown)
            return TextInputKind.Ciphertext;

        int nonWs = 0;
        int invalidBase64Chars = 0;
        foreach (char ch in input)
        {
            if (char.IsWhiteSpace(ch)) continue;
            nonWs++;
            if (!IsBase64Alphabet(ch)) invalidBase64Chars++;
        }
        if (nonWs == 0) return TextInputKind.Empty;
        if (invalidBase64Chars >= 3 || (invalidBase64Chars * 100 / nonWs) >= 5)
            return TextInputKind.Plaintext;
        return TextInputKind.Ambiguous;
    }

    private void UpdateTextInputActionHints()
    {
        if (!IsHandleCreated) return;

        var kind = ClassifyTextInput(_txtInput.Text, out var detectedMode);
        bool force = _chkTextForceActions.Checked;

        if (kind == TextInputKind.Ciphertext)
        {
            if (detectedMode == ContainerAccessModeHint.Pqc)
                _toggleText.SetSelected(SegmentedToggle.Segment.Pqc);
            else if (detectedMode == ContainerAccessModeHint.Password)
                _toggleText.SetSelected(SegmentedToggle.Segment.Password);
        }

        bool enableEncrypt;
        bool enableDecrypt;
        string hint;
        bool hintError = false;

        if (kind == TextInputKind.Empty)
        {
            enableEncrypt = false;
            enableDecrypt = false;
            hint = "Input is empty.";
        }
        else if (force)
        {
            enableEncrypt = true;
            enableDecrypt = true;
            hint = "Force actions enabled.";
        }
        else if (kind == TextInputKind.Ciphertext)
        {
            enableEncrypt = false;
            enableDecrypt = true;
            hint = $"Detected ciphertext ({(detectedMode == ContainerAccessModeHint.Pqc ? "PQC" : detectedMode == ContainerAccessModeHint.Password ? "Password" : "Unknown")}). Decrypt recommended.";
        }
        else if (kind == TextInputKind.Plaintext)
        {
            enableEncrypt = true;
            enableDecrypt = false;
            hint = "Detected plaintext. Encrypt recommended.";
        }
        else
        {
            enableEncrypt = true;
            enableDecrypt = true;
            hint = "Input format ambiguous; both actions enabled.";
            hintError = true;
        }

        _btnTextEncrypt.Enabled = enableEncrypt;
        _btnTextDecrypt.Enabled = enableDecrypt;
        TextStatus(hint, error: hintError);
    }

    private void OnToggleTextChanged(object? sender, EventArgs e)
    {
        bool isPqc = _toggleText.Selected == SegmentedToggle.Segment.Pqc;
        _pwPanelText.Visible  = !isPqc;
        _pqcPanelText.Visible =  isPqc;

        if (_toggleText.Parent is TableLayoutPanel outerText)
            outerText.RowStyles[2] = new RowStyle(SizeType.Absolute, isPqc ? 26 : 44);

        if (isPqc) TryAutoLoadTextKeyPath(force: false);
        UpdateTextInputActionHints();
    }

    private async void BtnTextEncrypt_Click(object? sender, EventArgs e)
    {
        if (!File.Exists(ExePath)) { TextStatus("obsidianq.exe not found.", error: true); return; }
        string plaintext = _txtInput.Text;
        if (string.IsNullOrEmpty(plaintext)) { TextStatus("Input is empty.", error: true); return; }
        var kind = ClassifyTextInput(plaintext, out var detectedMode);
        if (kind == TextInputKind.Ciphertext)
        {
            if (!_chkTextForceActions.Checked)
            {
                TextStatus("Detected ciphertext. Use DECRYPT or enable FORCE ACTIONS.", error: true);
                return;
            }
            var confirm = MessageBox.Show(
                this,
                $"Input appears to already be encrypted ({(detectedMode == ContainerAccessModeHint.Pqc ? "PQC" : detectedMode == ContainerAccessModeHint.Password ? "Password" : "Unknown")}).\n\nEncrypt again anyway?",
                "Double Encryption Warning",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button2);
            if (confirm != DialogResult.Yes)
            {
                TextStatus("Encryption cancelled.", error: true);
                return;
            }
        }

        bool isPqc = _toggleText.Selected == SegmentedToggle.Segment.Pqc;
        if (isPqc)
        {
            string? picked = ShowRecipientsPicker(_txtPrivkeyText.Text);
            if (string.IsNullOrWhiteSpace(picked))
            {
                TextStatus("Encryption cancelled: no recipients selected.", error: true);
                return;
            }
            _txtPrivkeyText.Text = picked;
        }
        if (isPqc) TrySilentKeyLoad(_txtPrivkeyText, DefaultPubKeyNames);
        if (!isPqc && string.IsNullOrEmpty(_txtPasswordText.Text))
        { TextStatus("Enter a password.", error: true); return; }
        if (isPqc && string.IsNullOrWhiteSpace(_txtPrivkeyText.Text))
        { TextStatus("No public key found - use BROWSE or Settings > Generate New Keypair.", error: true); return; }
        List<string>? textRecipientKeys = null;
        if (isPqc)
        {
            textRecipientKeys = ParseRecipientKeyPaths(_txtPrivkeyText.Text);
            if (textRecipientKeys.Count == 0)
            {
                TextStatus("No recipient public key(s) selected.", error: true);
                return;
            }
            if (textRecipientKeys.Any(k => !File.Exists(k)))
            {
                TextStatus("One or more recipient key files were not found.", error: true);
                return;
            }

            // Encrypt should use recipient PUBLIC keys. If a private-key-looking path was
            // entered, try the inferred public counterpart first.
            var normalizedKeys = new List<string>();
            foreach (string k in textRecipientKeys)
            {
                string use = k;
                if (LooksLikePrivateKeyPath(k))
                {
                    string? inferredPub = InferPublicKeyPathFromPrivate(k);
                    if (!string.IsNullOrWhiteSpace(inferredPub) && File.Exists(inferredPub))
                        use = inferredPub;
                }
                normalizedKeys.Add(use);
            }
            textRecipientKeys = normalizedKeys
                .Where(File.Exists)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            if (textRecipientKeys.Count == 0)
            {
                TextStatus("No recipient public key(s) selected.", error: true);
                return;
            }
            _txtPrivkeyText.Text = string.Join("; ", textRecipientKeys);
        }

        var args = new StringBuilder("encrypt --text");
        if (isPqc)
        {
            foreach (string key in textRecipientKeys ?? ParseRecipientKeyPaths(_txtPrivkeyText.Text))
                args.Append($" --pubkey \"{key}\"");
        }
        else       args.Append(" --password-stdin");

        _shimmer.Start();
        TextStatus("Encrypting...", error: false);
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = ExePath, Arguments = args.ToString(),
                RedirectStandardInput = true, RedirectStandardOutput = true,
                RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true,
            };
            using var proc = new Process { StartInfo = psi };
            proc.Start();

            if (!isPqc) await proc.StandardInput.WriteLineAsync(_txtPasswordText.Text);
            await proc.StandardInput.WriteAsync(plaintext);
            proc.StandardInput.Close();

            string b64 = await proc.StandardOutput.ReadToEndAsync();
            string err = await proc.StandardError.ReadToEndAsync();
            await proc.WaitForExitAsync();

            if (proc.ExitCode == 0)
            {
                _txtOutput.Text = b64.Trim();
                TextStatus("Encrypted. Copy output or use COPY OUTPUT.", error: false);
            }
            else
            {
                _txtOutput.Text = string.IsNullOrWhiteSpace(err) ? "(no stderr)" : err.Trim();
                TextStatus($"Encryption failed (exit {proc.ExitCode}).", error: true);
            }
        }
        catch (Exception ex) { TextStatus($"Error: {ex.Message}", error: true); }
        finally { _shimmer.Stop(); }
    }

    private async void BtnTextDecrypt_Click(object? sender, EventArgs e)
    {
        if (!File.Exists(ExePath)) { TextStatus("obsidianq.exe not found.", error: true); return; }
        string b64 = _txtInput.Text.Trim();
        if (string.IsNullOrEmpty(b64)) { TextStatus("Input is empty.", error: true); return; }

        var hint = DetectObsqAccessModeFromBase64(b64);
        if (hint == ContainerAccessModeHint.Pqc)
            _toggleText.SetSelected(SegmentedToggle.Segment.Pqc);
        else if (hint == ContainerAccessModeHint.Password)
            _toggleText.SetSelected(SegmentedToggle.Segment.Password);

        bool isPqc = _toggleText.Selected == SegmentedToggle.Segment.Pqc;
        if (isPqc) TrySilentKeyLoad(_txtPrivkeyText, DefaultPrivKeyNames);
        if (!isPqc && string.IsNullOrEmpty(_txtPasswordText.Text))
        { TextStatus("Enter a password.", error: true); return; }
        if (isPqc && string.IsNullOrWhiteSpace(_txtPrivkeyText.Text))
        { TextStatus("No private key found - use BROWSE or Settings > Generate New Keypair.", error: true); return; }
        if (isPqc)
        {
            var privKeys = ParseRecipientKeyPaths(_txtPrivkeyText.Text);
            if (privKeys.Count == 0) { TextStatus("No private key found.", error: true); return; }
            string selected = privKeys[0];

            // Decrypt should use a PRIVATE key. If a public-key-looking path was entered,
            // attempt local inference to the corresponding private key.
            if (LooksLikePublicKeyPath(selected))
            {
                string? inferredPriv = InferPrivateKeyPathFromPublic(selected);
                if (!string.IsNullOrWhiteSpace(inferredPriv) && File.Exists(inferredPriv))
                {
                    selected = inferredPriv;
                    TextStatus("Using inferred local private key for decrypt.", error: false);
                }
            }

            if (!File.Exists(selected))
            {
                TextStatus("Private key file not found.", error: true);
                return;
            }
            _txtPrivkeyText.Text = selected;
        }

        var args = new StringBuilder("decrypt --text");
        if (isPqc) args.Append($" --privkey \"{_txtPrivkeyText.Text}\"");
        else       args.Append(" --password-stdin");

        _shimmer.Start();
        TextStatus("Decrypting...", error: false);
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = ExePath, Arguments = args.ToString(),
                RedirectStandardInput = true, RedirectStandardOutput = true,
                RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true,
            };
            using var proc = new Process { StartInfo = psi };
            proc.Start();

            if (!isPqc) await proc.StandardInput.WriteLineAsync(_txtPasswordText.Text);
            await proc.StandardInput.WriteAsync(b64);
            proc.StandardInput.Close();

            string plaintext = await proc.StandardOutput.ReadToEndAsync();
            string err       = await proc.StandardError.ReadToEndAsync();
            await proc.WaitForExitAsync();

            if (proc.ExitCode == 0)
            {
                _txtOutput.Text = plaintext;
                TextStatus("Decrypted.", error: false);
            }
            else
            {
                _txtOutput.Text = string.IsNullOrWhiteSpace(err) ? "(no stderr)" : err.Trim();
                if (isPqc && err.Contains("no recipient entry matched provided private key", StringComparison.OrdinalIgnoreCase))
                {
                    TextStatus("Local private key failed for this message. Select the correct private key and retry.", error: true);
                    if (MessageBox.Show(
                        this,
                        "The current private key could not decrypt this text.\n\nSelect another private key now?",
                        "Private Key Mismatch",
                        MessageBoxButtons.YesNo,
                        MessageBoxIcon.Warning) == DialogResult.Yes)
                    {
                        BrowseKeyFile(_txtPrivkeyText);
                        if (!string.IsNullOrWhiteSpace(_txtPrivkeyText.Text))
                            BeginInvoke(new Action(() => BtnTextDecrypt_Click(sender, e)));
                    }
                }
                else
                    TextStatus($"Decryption failed (exit {proc.ExitCode}).", error: true);
            }
        }
        catch (Exception ex) { TextStatus($"Error: {ex.Message}", error: true); }
        finally { _shimmer.Stop(); }
    }

    private void TextStatus(string msg, bool error)
    {
        _lblStatusText.ForeColor = error ? Theme.Error : Theme.Accent;
        _lblStatusText.Text = msg;
    }

    // -----------------------------------------------------------------------
    // VAULT TAB – toggle / mount / unmount handlers
    // -----------------------------------------------------------------------
    private void OnToggleVaultChanged(object? sender, EventArgs e)
    {
        bool isPqc = _toggleVault.Selected == SegmentedToggle.Segment.Pqc;
        _pwPanelVault.Visible  = !isPqc;
        _pqcPanelVault.Visible =  isPqc;

        if (_toggleVault.Parent is TableLayoutPanel outerVault)
            outerVault.RowStyles[4] = new RowStyle(SizeType.Absolute, isPqc ? 26 : 44);

        if (isPqc) TryAutoLoadVaultKeyPath(force: false);
    }

    private static bool IsWinFspInstalled()
    {
        using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\WinFsp");
        if (key != null) return true;
        return File.Exists(@"C:\Program Files (x86)\WinFsp\bin\winfsp-x64.dll")
            || File.Exists(@"C:\Program Files\WinFsp\bin\winfsp-x64.dll");
    }

    private static bool IsNativeVaultPath(string path)
    {
        return path.EndsWith(".vault", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith(".obsqv", StringComparison.OrdinalIgnoreCase);
    }

    private bool VaultCredentialsReadyForList()
    {
        bool isPqc = _toggleVault.Selected == SegmentedToggle.Segment.Pqc;
        return isPqc
            ? TryResolveVaultPrivateKey(out _)
            : !string.IsNullOrEmpty(_txtPasswordVault.Text);
    }

    private bool TryResolveVaultPrivateKey(out string keyPath)
    {
        keyPath = string.Empty;
        var keys = ParseRecipientKeyPaths(_txtPrivkeyVault.Text);
        if (keys.Count == 0) return false;
        foreach (var k in keys)
        {
            if (File.Exists(k) && LooksLikePrivateKeyPath(k))
            {
                keyPath = k;
                return true;
            }
        }
        foreach (var k in keys)
        {
            if (File.Exists(k))
            {
                // Accept unknown naming convention if file exists.
                keyPath = k;
                return true;
            }
            if (LooksLikePublicKeyPath(k))
            {
                string? inferredPriv = InferPrivateKeyPathFromPublic(k);
                if (!string.IsNullOrWhiteSpace(inferredPriv) && File.Exists(inferredPriv))
                {
                    keyPath = inferredPriv;
                    return true;
                }
            }
        }
        return false;
    }

    private bool TryGetVaultPath(out string vaultPath)
    {
        vaultPath = _dropZoneVault.FilePath ?? string.Empty;
        if (string.IsNullOrWhiteSpace(vaultPath) || !IsNativeVaultPath(vaultPath))
        {
            VaultStatusError("Load a .vault vault first (drop or browse).");
            return false;
        }
        if (!File.Exists(vaultPath))
        {
            VaultStatusError("Vault file not found.");
            return false;
        }
        return true;
    }

    private bool TryBuildVaultAuth(out string authArgs, out string? stdinPassword)
    {
        bool isPqc = _toggleVault.Selected == SegmentedToggle.Segment.Pqc;
        if (isPqc)
        {
            if (!TryResolveVaultPrivateKey(out var selectedPriv))
            {
                VaultStatusError("No private key specified — use BROWSE.");
                authArgs = string.Empty;
                stdinPassword = null;
                return false;
            }
            _txtPrivkeyVault.Text = selectedPriv;
            authArgs = $" --privkey \"{selectedPriv}\"";
            stdinPassword = null;
            return true;
        }

        if (string.IsNullOrEmpty(_txtPasswordVault.Text))
        {
            VaultStatusError("Enter the vault password first.");
            authArgs = string.Empty;
            stdinPassword = null;
            return false;
        }

        authArgs = " --password-stdin";
        stdinPassword = _txtPasswordVault.Text;
        return true;
    }

    private async Task<(int ExitCode, string Stdout, string Stderr)> RunVaultCliAsync(string args, string? stdinPassword)
    {
        string[]? lines = stdinPassword == null ? null : [stdinPassword];
        return await RunVaultCliWithInputsAsync(args, lines);
    }

    private async Task<(int ExitCode, string Stdout, string Stderr)> RunVaultCliWithInputsAsync(string args, IEnumerable<string>? stdinLines)
    {
        bool hasInput = stdinLines != null && stdinLines.Any();
        var psi = new ProcessStartInfo
        {
            FileName = ExePath,
            Arguments = args,
            RedirectStandardInput = hasInput,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        using var proc = new Process { StartInfo = psi };
        proc.Start();
        if (hasInput && stdinLines != null)
        {
            foreach (string line in stdinLines)
                await proc.StandardInput.WriteLineAsync(line ?? string.Empty);
            proc.StandardInput.Close();
        }
        string stdout = await proc.StandardOutput.ReadToEndAsync();
        string stderr = await proc.StandardError.ReadToEndAsync();
        await proc.WaitForExitAsync();
        return (proc.ExitCode, stdout, stderr);
    }

    private async Task<T> RunWithBusyDialogAsync<T>(string title, string message, Func<Task<T>> work)
    {
        using var busy = new BusyProgressForm(title, message);
        busy.Show(this);
        busy.BringToFront();
        busy.Update();
        await Task.Yield();
        try
        {
            return await work();
        }
        finally
        {
            if (!busy.IsDisposed) busy.Close();
        }
    }

    private async Task RefreshVaultContentsAsync()
    {
        if (!File.Exists(ExePath)) { VaultStatusError("obsidianq.exe not found."); return; }
        if (!TryGetVaultPath(out var vaultPath)) return;
        if (!TryBuildVaultAuth(out var authArgs, out var stdinPassword)) return;

        _btnLoadVault.Enabled = false;
        try
        {
            string args = $"vault ls --vault \"{vaultPath}\" --recursive{authArgs}";
            var (exitCode, stdout, stderr) = await RunWithBusyDialogAsync(
                "Vault",
                "Loading vault contents...",
                () => RunVaultCliAsync(args, stdinPassword));
            if (!string.IsNullOrWhiteSpace(stderr)) LogVault(stderr.TrimEnd(), Theme.Error);
            if (exitCode != 0)
            {
                VaultStatusError($"vault ls failed (exit {exitCode}).");
                return;
            }

            int loaded = PopulateVaultTreeFromLs(stdout);
            VaultStatusOk($"Loaded {loaded} item(s).");
        }
        catch (Exception ex)
        {
            VaultStatusError($"Failed to load vault contents: {ex.Message}");
        }
        finally
        {
            _btnLoadVault.Enabled = true;
            UpdateVaultUiState();
        }
    }

    private int PopulateVaultTreeFromLs(string lsOutput)
    {
        _tvVaultContents.BeginUpdate();
        _tvVaultContents.Nodes.Clear();

        var lineRe = new Regex(@"^(?<indent>\s*)(?<type>[d-])\s+(?<size>-|\d+)\s+(?<name>.+)$");
        var dirNodeAtDepth = new Dictionary<int, TreeNode>();
        int count = 0;

        foreach (string raw in lsOutput.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries))
        {
            var m = lineRe.Match(raw);
            if (!m.Success) continue;

            string indent = m.Groups["indent"].Value;
            int depth = indent.Length / 2;
            bool isDir = m.Groups["type"].Value == "d";
            string sizeRaw = m.Groups["size"].Value;
            string name = m.Groups["name"].Value.Trim();

            TreeNode? parent = depth > 0 && dirNodeAtDepth.TryGetValue(depth - 1, out var p) ? p : null;
            string parentPath = parent?.Tag is ValueTuple<string, bool, long, string> pt ? pt.Item1 : "/";
            string fullPath = parentPath == "/" ? "/" + name : $"{parentPath}/{name}";
            long sizeBytes = isDir ? 0 : (long.TryParse(sizeRaw, out var s) ? s : 0);
            string text = isDir ? name : $"{name} ({FormatBytes(sizeBytes)})";

            var node = new TreeNode(text)
            {
                ForeColor = isDir ? Theme.AccentDim : Theme.Accent,
                Tag = (fullPath, isDir, sizeBytes, name),
            };

            if (parent == null) _tvVaultContents.Nodes.Add(node);
            else parent.Nodes.Add(node);

            if (isDir) dirNodeAtDepth[depth] = node;
            count++;
        }

        foreach (TreeNode n in _tvVaultContents.Nodes)
            ComputeAndApplyDirectorySizes(n);
        _tvVaultContents.ExpandAll();
        _tvVaultContents.EndUpdate();
        UpdateVaultEmptyHint();
        return count;
    }

    private static long ComputeAndApplyDirectorySizes(TreeNode node)
    {
        if (node.Tag is not ValueTuple<string, bool, long, string> t) return 0;
        var (path, isDir, sizeBytes, name) = t;
        if (!isDir)
        {
            node.Text = $"{name} ({FormatBytes(sizeBytes)})";
            return sizeBytes;
        }

        long sum = 0;
        foreach (TreeNode child in node.Nodes)
            sum += ComputeAndApplyDirectorySizes(child);
        node.Tag = (path, true, sum, name);
        node.Text = $"{name} ({FormatBytes(sum)})";
        return sum;
    }

    private static string FormatBytes(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB", "PB"];
        double size = bytes < 0 ? 0 : bytes;
        int unit = 0;
        while (size >= 1024 && unit < units.Length - 1)
        {
            size /= 1024;
            unit++;
        }
        return unit == 0 ? $"{bytes} {units[unit]}" : $"{size:0.##} {units[unit]}";
    }

    private async Task AddFilesToVaultAsync(IEnumerable<string> sourcePaths)
    {
        if (!File.Exists(ExePath)) { VaultStatusError("obsidianq.exe not found."); return; }
        if (!TryGetVaultPath(out var vaultPath)) return;
        if (!TryBuildVaultAuth(out var authArgs, out var stdinPassword)) return;

        var workItems = BuildAddWorkItems(sourcePaths);
        if (workItems.Count == 0) return;
        var workSizes = workItems
            .Select(w =>
            {
                try { return File.Exists(w.SrcPath) ? new FileInfo(w.SrcPath).Length : 0L; }
                catch { return 0L; }
            })
            .ToList();
        long totalBytes = workSizes.Sum(v => Math.Max(0, v));

        _btnAddToVault.Enabled = false;
        _shimmer.Start();
        try
        {
            int failed = 0;
            int completed = 0;
            bool cancelled = false;
            long bytesProcessed = 0;
            using var progress = new VaultProgressForm("Adding to vault", workItems.Count);
            Enabled = false;
            try
            {
                progress.Show(this);
                progress.UpdateProgress(0, workItems.Count, "-", bytesProcessed, totalBytes);
                await Task.Yield();

                for (int i = 0; i < workItems.Count; i++)
                {
                    if (progress.CancelRequested)
                    {
                        cancelled = true;
                        break;
                    }

                    var w = workItems[i];
                    long itemBytes = Math.Max(0, workSizes[i]);
                    long itemProgressBytes = 0;
                    string itemStage = "processing";
                    progress.UpdateProgress(i, workItems.Count, w.DisplayPath, bytesProcessed, totalBytes, itemStage);

                    bool ok = await ExecuteVaultAddWithProgressAsync(
                        vaultPath,
                        w.SrcPath,
                        w.DestPath,
                        authArgs,
                        stdinPassword,
                        stage =>
                        {
                            itemStage = stage;
                            if (IsDisposed || Disposing) return;
                            BeginInvoke(new Action(() =>
                            {
                                if (progress.IsDisposed) return;
                                progress.UpdateProgress(
                                    i,
                                    workItems.Count,
                                    w.DisplayPath,
                                    bytesProcessed + itemProgressBytes,
                                    totalBytes,
                                    itemStage);
                            }));
                        },
                        (processed, total) =>
                        {
                            long safeProcessed = Math.Max(0, processed);
                            long clampTarget = itemBytes > 0 ? itemBytes : Math.Max(1, total);
                            long clamped = Math.Min(safeProcessed, clampTarget);
                            if (clamped < itemProgressBytes) clamped = itemProgressBytes;
                            itemProgressBytes = clamped;
                            if (IsDisposed || Disposing) return;
                            BeginInvoke(new Action(() =>
                            {
                                if (progress.IsDisposed) return;
                                progress.UpdateProgress(
                                    i,
                                    workItems.Count,
                                    w.DisplayPath,
                                    bytesProcessed + itemProgressBytes,
                                    totalBytes,
                                    itemStage);
                            }));
                        });

                    if (!ok) failed++;
                    bytesProcessed += itemBytes;
                    completed = i + 1;
                    progress.UpdateProgress(completed, workItems.Count, w.DisplayPath, bytesProcessed, totalBytes, itemStage);
                }
            }
            finally
            {
                progress.Close();
                Enabled = true;
                Activate();
            }

            if (cancelled)
                VaultStatusError($"Add cancelled after {completed}/{workItems.Count} item(s).");
            else if (failed == 0)
                VaultStatusOk($"Added {workItems.Count} item(s) to vault.");
            else
                VaultStatusError($"{failed} of {workItems.Count} add operation(s) failed.");
        }
        catch (Exception ex)
        {
            VaultStatusError($"Add failed: {ex.Message}");
            return;
        }
        finally
        {
            _btnAddToVault.Enabled = true;
            _shimmer.Stop();
        }

        await RefreshVaultContentsAsync();
    }

    private bool TryParseProgressNumbers(string line, out long processed, out long total)
    {
        processed = 0;
        total = 0;
        var m = CliProgressRe.Match(line);
        if (!m.Success) return false;
        if (!long.TryParse(m.Groups["processed"].Value, out processed)) return false;
        if (!long.TryParse(m.Groups["total"].Value, out total)) return false;
        return true;
    }

    private async Task<bool> ExecuteVaultAddWithProgressAsync(
        string vaultPath,
        string sourcePath,
        string? destPath,
        string authArgs,
        string? stdinPassword,
        Action<string>? onStage,
        Action<long, long>? onProgress)
    {
        try
        {
            string destArg = string.IsNullOrWhiteSpace(destPath) ? "" : $" --dest \"{destPath}\"";
            string args = $"vault add --vault \"{vaultPath}\" --src \"{sourcePath}\"{destArg}{authArgs}";
            bool hasInput = !string.IsNullOrWhiteSpace(stdinPassword);
            var psi = new ProcessStartInfo
            {
                FileName = ExePath,
                Arguments = args,
                RedirectStandardInput = hasInput,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var proc = new Process { StartInfo = psi };
            proc.Start();
            if (hasInput)
            {
                await proc.StandardInput.WriteLineAsync(stdinPassword!);
                proc.StandardInput.Close();
            }

            async Task ReadStreamAsync(StreamReader reader, Color color)
            {
                string? line;
                while ((line = await reader.ReadLineAsync()) != null)
                {
                    var stageMatch = CliProgressStageRe.Match(line);
                    if (stageMatch.Success)
                    {
                        onStage?.Invoke(NormalizeProgressStage(stageMatch.Groups["stage"].Value));
                        continue;
                    }
                    if (TryParseProgressNumbers(line, out var processed, out var total))
                    {
                        onProgress?.Invoke(processed, total);
                        continue;
                    }
                    LogVault(line, color);
                }
            }

            await Task.WhenAll(
                ReadStreamAsync(proc.StandardOutput, Theme.Accent),
                ReadStreamAsync(proc.StandardError, Theme.Error));
            await proc.WaitForExitAsync();
            if (proc.ExitCode != 0)
            {
                VaultStatusError($"vault add failed for '{sourcePath}' (exit {proc.ExitCode}).");
                return false;
            }
            return true;
        }
        catch (Exception ex)
        {
            VaultStatusError($"Add failed for '{sourcePath}': {ex.Message}");
            return false;
        }
    }

    private async Task<bool> ExecuteVaultAddAsync(
        string vaultPath,
        string sourcePath,
        string? destPath,
        string authArgs,
        string? stdinPassword)
    {
        try
        {
            string destArg = string.IsNullOrWhiteSpace(destPath) ? "" : $" --dest \"{destPath}\"";
            string args = $"vault add --vault \"{vaultPath}\" --src \"{sourcePath}\"{destArg}{authArgs}";
            var (exitCode, stdout, stderr) = await RunVaultCliAsync(args, stdinPassword);
            if (!string.IsNullOrWhiteSpace(stdout)) LogVault(stdout.TrimEnd(), Theme.Accent);
            if (!string.IsNullOrWhiteSpace(stderr)) LogVault(stderr.TrimEnd(), Theme.Error);
            if (exitCode != 0)
            {
                VaultStatusError($"vault add failed for '{sourcePath}' (exit {exitCode}).");
                return false;
            }
            return true;
        }
        catch (Exception ex)
        {
            VaultStatusError($"Add failed for '{sourcePath}': {ex.Message}");
            return false;
        }
    }

    private static string? FindWinFspInstaller()
    {
        return Directory.EnumerateFiles(AppContext.BaseDirectory, "winfsp-*.msi")
                        .OrderByDescending(f => f)
                        .FirstOrDefault();
    }

    private async Task<bool> TryInstallWinFspAsync()
    {
        string? msi = FindWinFspInstaller();
        if (msi == null)
        {
            VaultStatusError("WinFSP installer not found next to ObsidianQ.Launcher.exe.");
            LogVault("[INFO] Download WinFSP from: https://github.com/winfsp/winfsp/releases", Theme.TextDim);
            return false;
        }

        var answer = MessageBox.Show(
            "Virtual drive mounting requires WinFSP to be installed.\n\n" +
            $"Install {Path.GetFileName(msi)} now?\n" +
            "(Windows will prompt for administrator permission.)",
            "Install WinFSP?",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Question,
            MessageBoxDefaultButton.Button1);

        if (answer != DialogResult.Yes) return false;

        LogVault($"[INSTALL] Installing {Path.GetFileName(msi)} silently ...", Theme.TextDim);
        _btnMountVault.Enabled = false;
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName        = "msiexec.exe",
                Arguments       = $"/i \"{msi}\" /quiet /norestart",
                UseShellExecute = true,
                Verb            = "runas",
            };
            using var proc = Process.Start(psi)!;
            await proc.WaitForExitAsync();

            if (proc.ExitCode == 0)
            {
                LogVault("[OK] WinFSP installed successfully.", Theme.Accent);
                return true;
            }
            else
            {
                VaultStatusError($"WinFSP installer returned exit code {proc.ExitCode}.");
                return false;
            }
        }
        catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            LogVault("[CANCELLED] Administrator permission was denied.", Theme.Error);
            return false;
        }
        catch (Exception ex)
        {
            VaultStatusError($"Failed to launch installer: {ex.Message}");
            return false;
        }
        finally
        {
            _btnMountVault.Enabled = true;
        }
    }

    private async void BtnMountVault_Click(object? sender, EventArgs e)
    {
        if (_mountProc != null) { await DoUnmountAsync(); return; }

        if (_dropZoneVault.FilePath == null || !File.Exists(_dropZoneVault.FilePath))
        { VaultStatusError("Drop or browse a .vault file first."); return; }

        if (!IsWinFspInstalled())
        {
            if (!await TryInstallWinFspAsync()) return;
            if (!IsWinFspInstalled())
            {
                VaultStatusError("WinFSP install could not be verified. A reboot may be required.");
                return;
            }
        }

        string dl = _txtDriveLetter.Text.Trim().TrimEnd(':').ToUpperInvariant();
        if (dl.Length != 1 || dl[0] < 'A' || dl[0] > 'Z')
        { VaultStatusError("Invalid drive letter (A-Z only)."); return; }

        if (DriveInfo.GetDrives().Any(d => char.ToUpperInvariant(d.Name[0]) == dl[0]))
        { VaultStatusError($"Drive {dl}: is already in use — choose a different letter."); return; }

        bool isPqc      = _toggleVault.Selected == SegmentedToggle.Segment.Pqc;
        bool isNative   = IsNativeVaultPath(_dropZoneVault.FilePath!);

        var sb = new StringBuilder();
        if (isNative)
        {
            sb.Append("vault mount");
            sb.Append($" --vault \"{_dropZoneVault.FilePath}\"");
        }
        else
        {
            sb.Append("mount");
            sb.Append($" --in \"{_dropZoneVault.FilePath}\"");
        }
        sb.Append($" --drive {dl}:");
        if (isPqc) sb.Append($" --privkey \"{_txtPrivkeyVault.Text}\"");
        else       sb.Append(" --password-stdin");

        string password = isPqc ? "" : _txtPasswordVault.Text;
        LogVault($"[MOUNT] obsidianq {sb}", Theme.TextDim);
        _shimmer.Start();

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName               = ExePath,
                Arguments              = sb.ToString(),
                RedirectStandardInput  = !isPqc,
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                UseShellExecute        = false,
                CreateNoWindow         = true,
            };
            var proc = new Process { StartInfo = psi, EnableRaisingEvents = true };
            proc.OutputDataReceived += (_, ev) => { if (ev.Data != null) LogVault(ev.Data, Theme.Accent); };
            proc.ErrorDataReceived  += (_, ev) => { if (ev.Data != null) LogVault(ev.Data, Theme.Error); };
            proc.Exited += (_, _) =>
            {
                Invoke(() =>
                {
                    _mountProc = null;
                    _btnMountVault.Text = "MOUNT";
                    _shimmer.Stop();
                    VaultStatusOk($"Mount process for {dl}: exited.");
                });
            };
            proc.Start();
            proc.BeginOutputReadLine();
            proc.BeginErrorReadLine();
            if (!isPqc) { proc.StandardInput.WriteLine(password); proc.StandardInput.Close(); }

            _mountProc    = proc;
            _mountedDrive = dl[0];
            _isVaultMount = isNative;
            _btnMountVault.Text = "UNMOUNT";
            VaultStatusOk($"Mount process started for {dl}:.");
        }
        catch (Exception ex)
        {
            _shimmer.Stop();
            VaultStatusError($"Mount failed: {ex.Message}");
        }
    }

    private async Task DoUnmountAsync()
    {
        if (_mountProc == null) return;
        char dl = _mountedDrive;
        LogVault($"[UNMOUNT] Signaling unmount of {dl}:", Theme.TextDim);
        _btnMountVault.Enabled = false;
        try
        {
            string unmountArgs = _isVaultMount
                ? $"vault unmount --drive {dl}:"
                : $"unmount --drive {dl}:";
            var psi = new ProcessStartInfo
            {
                FileName               = ExePath,
                Arguments              = unmountArgs,
                RedirectStandardOutput = true, RedirectStandardError = true,
                UseShellExecute        = false, CreateNoWindow = true,
            };
            using var sig = new Process { StartInfo = psi };
            sig.Start();
            string stdout = await sig.StandardOutput.ReadToEndAsync();
            string stderr = await sig.StandardError.ReadToEndAsync();
            await sig.WaitForExitAsync();
            if (!string.IsNullOrWhiteSpace(stdout)) LogVault(stdout.TrimEnd(), Theme.Accent);
            if (!string.IsNullOrWhiteSpace(stderr)) LogVault(stderr.TrimEnd(), Theme.Error);

            using var exitCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            try { await _mountProc.WaitForExitAsync(exitCts.Token); }
            catch (OperationCanceledException)
            {
                LogVault("[WARN] Mount process did not exit after unmount signal; killing.", Theme.Error);
                try { _mountProc.Kill(); } catch { /* best effort */ }
            }
        }
        catch (Exception ex) { VaultStatusError($"Unmount failed: {ex.Message}"); }
        finally
        {
            _mountProc = null;
            _btnMountVault.Text    = "MOUNT";
            _btnMountVault.Enabled = true;
            _shimmer.Stop();
        }
    }

    private async void BtnCreateVault_Click(object? sender, EventArgs e)
    {
        await StartCreateVaultWizardAsync();
    }

    private async void BtnRekeyVault_Click(object? sender, EventArgs e)
    {
        if (!File.Exists(ExePath)) { VaultStatusError("obsidianq.exe not found."); return; }
        if (!TryGetVaultPath(out var srcVault)) return;
        if (!TryBuildVaultAuth(out var srcAuthArgs, out var srcStdinPassword)) return;

        string dstVault = BuildVaultUpdatedCandidatePath(srcVault);
        using var modePrompt = new VaultAccessModePromptForm();
        if (modePrompt.ShowDialog(this) != DialogResult.OK || modePrompt.Choice == VaultAccessModePromptForm.ModeChoice.Cancel)
            return;

        string dstAuthArgs;
        string? newPassword = null;
        List<string>? newPubKeys = null;

        if (modePrompt.Choice == VaultAccessModePromptForm.ModeChoice.Password)
        {
            using var p1 = new TextPromptForm("Manage Vault Access", "New vault password:", password: true);
            if (p1.ShowDialog(this) != DialogResult.OK) return;
            using var p2 = new TextPromptForm("Manage Vault Access", "Confirm new vault password:", password: true);
            if (p2.ShowDialog(this) != DialogResult.OK) return;
            if (string.IsNullOrWhiteSpace(p1.Value))
            {
                VaultStatusError("New password cannot be empty.");
                return;
            }
            if (!string.Equals(p1.Value, p2.Value, StringComparison.Ordinal))
            {
                VaultStatusError("New passwords do not match.");
                return;
            }
            newPassword = p1.Value;
            dstAuthArgs = " --new-password-stdin";
        }
        else
        {
            string? picked = ShowRecipientsPicker("");
            if (string.IsNullOrWhiteSpace(picked))
            {
                VaultStatusError("No recipient public key(s) selected.");
                return;
            }
            newPubKeys = ParseRecipientKeyPaths(picked)
                .Where(File.Exists)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            if (newPubKeys.Count == 0)
            {
                VaultStatusError("No valid recipient public key(s) selected.");
                return;
            }
            var sbDst = new StringBuilder();
            foreach (var k in newPubKeys) sbDst.Append($" --new-pubkey \"{k}\"");
            dstAuthArgs = sbDst.ToString();
        }

        var args = new StringBuilder("vault rekey");
        args.Append($" --vault \"{srcVault}\"");
        args.Append($" --out \"{dstVault}\"");
        args.Append(srcAuthArgs);
        args.Append(dstAuthArgs);

        var stdinLines = new List<string>();
        if (!string.IsNullOrEmpty(srcStdinPassword)) stdinLines.Add(srcStdinPassword);
        if (!string.IsNullOrEmpty(newPassword)) stdinLines.Add(newPassword);

        _btnRekeyVault.Enabled = false;
        _shimmer.Start();
        VaultStatusOk("Updating vault access...");
        try
        {
            var (exitCode, stdout, stderr) = await RunWithBusyDialogAsync(
                "Manage Vault Access",
                "Applying new vault access settings...",
                () => RunVaultCliWithInputsAsync(args.ToString(), stdinLines.Count > 0 ? stdinLines : null));
            if (exitCode != 0)
            {
                LogVault(string.IsNullOrWhiteSpace(stderr) ? stdout : stderr, Theme.Error);
                VaultStatusError($"vault rekey failed (exit {exitCode}).");
                return;
            }

            string finalVault = dstVault;
            bool replaceOriginal = MessageBox.Show(
                this,
                "Access update completed.\n\nReplace the original vault with this updated vault now?\n" +
                "A backup copy of the original will be kept.",
                "Manage Vault Access",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Question,
                MessageBoxDefaultButton.Button1) == DialogResult.Yes;
            if (replaceOriginal)
            {
                string backup = SwapInRekeyedVault(srcVault, dstVault);
                finalVault = srcVault;
                LogVault($"[BACKUP] Original vault saved to: {backup}", Theme.AccentDim);
            }

            _suppressVaultFileDroppedHandler = true;
            try { _dropZoneVault.SetFile(finalVault); }
            finally { _suppressVaultFileDroppedHandler = false; }
            if (newPassword != null)
            {
                _toggleVault.SetSelected(SegmentedToggle.Segment.Password);
                _txtPasswordVault.Text = newPassword;
            }
            else
            {
                _toggleVault.SetSelected(SegmentedToggle.Segment.Pqc);
                string? firstPub = newPubKeys?.FirstOrDefault();
                string? inferredPriv = InferPrivateKeyPathFromPublic(firstPub);
                if (!string.IsNullOrWhiteSpace(inferredPriv) && File.Exists(inferredPriv))
                    _txtPrivkeyVault.Text = inferredPriv;
            }

            await RefreshVaultContentsAsync();
            VaultStatusOk($"Vault access updated: {Path.GetFileName(finalVault)}");
        }
        catch (Exception ex)
        {
            VaultStatusError($"Rekey failed: {ex.Message}");
        }
        finally
        {
            _btnRekeyVault.Enabled = true;
            _shimmer.Stop();
        }
    }

    private async void BtnAddFiles_Click(object? sender, EventArgs e)
    {
        if (!File.Exists(ExePath)) { VaultStatusError("obsidianq.exe not found."); return; }

        using var open = new OpenFileDialog
        {
            Title       = "Add files to vault",
            Filter      = "All files|*.*",
            Multiselect = true,
        };
        if (open.ShowDialog() != DialogResult.OK || open.FileNames.Length == 0) return;
        await AddFilesToVaultAsync(open.FileNames);
    }

    private async void BtnAddFolder_Click(object? sender, EventArgs e)
    {
        if (!File.Exists(ExePath)) { VaultStatusError("obsidianq.exe not found."); return; }
        using var dlg = new FolderBrowserDialog
        {
            Description = "Select folder to add to vault",
            UseDescriptionForTitle = true,
            ShowNewFolderButton = false,
        };
        if (dlg.ShowDialog() != DialogResult.OK || string.IsNullOrWhiteSpace(dlg.SelectedPath)) return;
        await AddFilesToVaultAsync(new[] { dlg.SelectedPath });
    }

    private async void BtnExtractVaultItem_Click(object? sender, EventArgs e)
    {
        if (!File.Exists(ExePath)) { VaultStatusError("obsidianq.exe not found."); return; }
        var items = GetCheckedOrSelectedVaultItems();
        if (items.Count == 0)
        {
            VaultStatusError("Check or select one or more items to extract.");
            return;
        }

        using var dlg = new FolderBrowserDialog
        {
            Description = "Select destination folder for extracted files",
            UseDescriptionForTitle = true,
            ShowNewFolderButton = true,
        };
        if (dlg.ShowDialog() != DialogResult.OK || string.IsNullOrWhiteSpace(dlg.SelectedPath)) return;

        var nodeMap = BuildVaultNodeMap();
        var extractFiles = new List<string>();
        foreach (var item in items)
        {
            if (!item.IsDir)
            {
                extractFiles.Add(item.Path);
                continue;
            }
            if (!nodeMap.TryGetValue(item.Path, out var node))
            {
                extractFiles.Add(item.Path);
                continue;
            }
            extractFiles.AddRange(
                CollectVaultSubtreeItems(node)
                    .Where(x => !x.IsDir)
                    .Select(x => x.Path));
        }
        extractFiles = extractFiles.Distinct(StringComparer.Ordinal).ToList();
        if (extractFiles.Count == 0)
        {
            VaultStatusError("No files found to extract.");
            return;
        }
        var sizeByPath = new Dictionary<string, long>(StringComparer.Ordinal);
        foreach (string p in extractFiles)
        {
            if (nodeMap.TryGetValue(p, out var n) && n.Tag is ValueTuple<string, bool, long, string> t)
                sizeByPath[p] = Math.Max(0, t.Item3);
        }

        int failed = 0;
        int completed = 0;
        bool cancelled = false;
        long bytesProcessed = 0;
        long totalBytes = extractFiles.Sum(p => Math.Max(0, sizeByPath.TryGetValue(p, out var s) ? s : 0L));
        using (var progress = new VaultProgressForm("Extracting from vault", extractFiles.Count))
        {
            Enabled = false;
            try
            {
                progress.Show(this);
                progress.UpdateProgress(0, extractFiles.Count, "-", bytesProcessed, totalBytes);
                await Task.Yield();

                for (int i = 0; i < extractFiles.Count; i++)
                {
                    if (progress.CancelRequested)
                    {
                        cancelled = true;
                        break;
                    }

                    string path = extractFiles[i];
                    string subdir = GetVaultParentLocalSubdir(path);
                    string outDir = string.IsNullOrWhiteSpace(subdir) ? dlg.SelectedPath : Path.Combine(dlg.SelectedPath, subdir);
                    Directory.CreateDirectory(outDir);

                    long itemBytes = Math.Max(0, sizeByPath.TryGetValue(path, out var s) ? s : 0L);
                    long itemProgressBytes = 0;
                    string itemStage = "processing";
                    progress.UpdateProgress(i, extractFiles.Count, path, bytesProcessed, totalBytes, itemStage);

                    bool ok = await ExecuteVaultExtractWithProgressAsync(
                        path,
                        outDir,
                        stage =>
                        {
                            itemStage = stage;
                            if (IsDisposed || Disposing) return;
                            BeginInvoke(new Action(() =>
                            {
                                if (progress.IsDisposed) return;
                                progress.UpdateProgress(
                                    i,
                                    extractFiles.Count,
                                    path,
                                    bytesProcessed + itemProgressBytes,
                                    totalBytes,
                                    itemStage);
                            }));
                        },
                        (processed, total) =>
                        {
                            long safeProcessed = Math.Max(0, processed);
                            long clampTarget = itemBytes > 0 ? itemBytes : Math.Max(1, total);
                            long clamped = Math.Min(safeProcessed, clampTarget);
                            if (clamped < itemProgressBytes) clamped = itemProgressBytes;
                            itemProgressBytes = clamped;
                            if (IsDisposed || Disposing) return;
                            BeginInvoke(new Action(() =>
                            {
                                if (progress.IsDisposed) return;
                                progress.UpdateProgress(
                                    i,
                                    extractFiles.Count,
                                    path,
                                    bytesProcessed + itemProgressBytes,
                                    totalBytes,
                                    itemStage);
                            }));
                        });

                    if (!ok) failed++;
                    bytesProcessed += itemBytes;
                    completed = i + 1;
                    progress.UpdateProgress(completed, extractFiles.Count, path, bytesProcessed, totalBytes, itemStage);
                }
            }
            finally
            {
                progress.Close();
                Enabled = true;
                Activate();
            }
        }
        if (cancelled)
            VaultStatusError($"Extract cancelled after {completed}/{extractFiles.Count} item(s).");
        else if (failed == 0)
            VaultStatusOk($"Extracted {extractFiles.Count} file(s) to {dlg.SelectedPath}");
        else
            VaultStatusError($"{failed} of {extractFiles.Count} extract operation(s) failed.");
    }

    private async void BtnRemoveVaultItem_Click(object? sender, EventArgs e)
    {
        if (!File.Exists(ExePath)) { VaultStatusError("obsidianq.exe not found."); return; }
        var items = GetCheckedOrSelectedVaultItems();
        if (items.Count == 0)
        {
            VaultStatusError("Check or select one or more items to delete.");
            return;
        }

        bool containsDir = items.Any(i => i.IsDir);
        bool recursiveForDirs = false;
        if (containsDir)
        {
            var folderAnswer = MessageBox.Show(
                "Delete selected folder(s) recursively?\n\n" +
                "Yes = recursive delete for folders\n" +
                "No = delete only if empty\n" +
                "Cancel = abort",
                "Confirm delete",
                MessageBoxButtons.YesNoCancel,
                MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button3);
            if (folderAnswer == DialogResult.Cancel) return;
            recursiveForDirs = folderAnswer == DialogResult.Yes;
        }

        var answer = MessageBox.Show(
            $"Delete {items.Count} selected item(s) from vault?",
            "Confirm delete",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Warning,
            MessageBoxDefaultButton.Button2);
        if (answer != DialogResult.Yes) return;

        var nodeMap = BuildVaultNodeMap();
        List<(string Path, bool IsDir)> plan;
        if (containsDir && recursiveForDirs)
        {
            var expanded = new List<(string Path, bool IsDir)>();
            foreach (var item in items)
            {
                if (!item.IsDir)
                {
                    expanded.Add(item);
                    continue;
                }
                if (nodeMap.TryGetValue(item.Path, out var node))
                    expanded.AddRange(CollectVaultSubtreeItems(node));
                else
                    expanded.Add(item);
            }
            plan = expanded
                .DistinctBy(x => x.Path)
                .OrderByDescending(i => i.Path.Count(c => c == '/'))
                .ToList();
        }
        else
        {
            plan = items.OrderByDescending(i => i.Path.Count(c => c == '/')).ToList();
        }

        var (failed, cancelled, completed) = await RunVaultBatchWithProgressAsync(
            "Deleting from vault",
            plan,
            async item => await ExecuteVaultRemoveAsync(item.Path, false));

        if (cancelled)
            VaultStatusError($"Delete cancelled after {completed}/{plan.Count} item(s).");
        else if (failed == 0)
            VaultStatusOk($"Deleted {plan.Count} item(s).");
        else
            VaultStatusError($"{failed} of {plan.Count} delete operation(s) failed.");
        await RefreshVaultContentsAsync();
    }

    private async Task<(int Failed, bool Cancelled, int Completed)> RunVaultBatchWithProgressAsync(
        string title,
        List<(string Path, bool IsDir)> items,
        Func<(string Path, bool IsDir), Task<bool>> operation,
        Func<(string Path, bool IsDir), long>? bytesResolver = null)
    {
        int failed = 0;
        int completed = 0;
        bool cancelled = false;
        long bytesProcessed = 0;
        long totalBytes = 0;
        if (bytesResolver != null)
        {
            foreach (var item in items)
                totalBytes += Math.Max(0, bytesResolver(item));
        }
        using var progress = new VaultProgressForm(title, items.Count);
        Enabled = false;
        try
        {
            progress.Show(this);
            progress.UpdateProgress(0, items.Count, "-", bytesProcessed, totalBytes);
            await Task.Yield();

            for (int i = 0; i < items.Count; i++)
            {
                if (progress.CancelRequested)
                {
                    cancelled = true;
                    break;
                }
                var item = items[i];
                long itemBytes = Math.Max(0, bytesResolver?.Invoke(item) ?? 0);
                progress.UpdateProgress(i, items.Count, item.Path, bytesProcessed, totalBytes);
                bool ok = await operation(item);
                if (!ok) failed++;
                bytesProcessed += itemBytes;
                completed = i + 1;
                progress.UpdateProgress(completed, items.Count, item.Path, bytesProcessed, totalBytes);
            }
        }
        finally
        {
            progress.Close();
            Enabled = true;
            Activate();
        }
        return (failed, cancelled, completed);
    }

    private async Task RemoveVaultPathAsync(string vaultItemPath, bool isDir)
    {
        if (!File.Exists(ExePath)) { VaultStatusError("obsidianq.exe not found."); return; }

        bool recursive = false;
        if (isDir)
        {
            var folderAnswer = MessageBox.Show(
                $"Remove folder '{vaultItemPath}' and all of its contents?\n\n" +
                "Yes = recursive remove\n" +
                "No = remove only if empty\n" +
                "Cancel = abort",
                "Confirm folder remove",
                MessageBoxButtons.YesNoCancel,
                MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button3);
            if (folderAnswer == DialogResult.Cancel) return;
            recursive = folderAnswer == DialogResult.Yes;
        }
        else
        {
            var answer = MessageBox.Show(
                $"Remove file '{vaultItemPath}' from vault?",
                "Confirm remove",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button2);
            if (answer != DialogResult.Yes) return;
        }

        bool ok = await ExecuteVaultRemoveAsync(vaultItemPath, recursive);
        if (ok)
        {
            VaultStatusOk($"Removed {vaultItemPath}");
            await RefreshVaultContentsAsync();
        }
    }

    private async Task<bool> ExecuteVaultRemoveAsync(string vaultItemPath, bool recursive)
    {
        if (!TryGetVaultPath(out var vaultPath)) return false;
        if (!TryBuildVaultAuth(out var authArgs, out var stdinPassword)) return false;
        try
        {
            string args = $"vault remove --vault \"{vaultPath}\" --path \"{vaultItemPath}\"{(recursive ? " --recursive" : "")}{authArgs}";
            var (exitCode, stdout, stderr) = await RunVaultCliAsync(args, stdinPassword);
            if (!string.IsNullOrWhiteSpace(stdout)) LogVault(stdout.TrimEnd(), Theme.Accent);
            if (!string.IsNullOrWhiteSpace(stderr)) LogVault(stderr.TrimEnd(), Theme.Error);
            if (exitCode != 0)
            {
                VaultStatusError($"vault remove failed for '{vaultItemPath}' (exit {exitCode}).");
                return false;
            }
            return true;
        }
        catch (Exception ex)
        {
            VaultStatusError($"Remove failed for '{vaultItemPath}': {ex.Message}");
            return false;
        }
    }

    private async Task<bool> ExecuteVaultExtractAsync(string vaultItemPath, string destinationDir)
    {
        return await ExecuteVaultExtractWithProgressAsync(vaultItemPath, destinationDir, null, null);
    }

    private async Task<bool> ExecuteVaultExtractWithProgressAsync(
        string vaultItemPath,
        string destinationDir,
        Action<string>? onStage,
        Action<long, long>? onProgress)
    {
        if (!TryGetVaultPath(out var vaultPath)) return false;
        if (!TryBuildVaultAuth(out var authArgs, out var stdinPassword)) return false;
        try
        {
            string args = $"vault extract --vault \"{vaultPath}\" --path \"{vaultItemPath}\" --dest \"{destinationDir}\"{authArgs}";
            bool hasInput = !string.IsNullOrWhiteSpace(stdinPassword);
            var psi = new ProcessStartInfo
            {
                FileName = ExePath,
                Arguments = args,
                RedirectStandardInput = hasInput,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var proc = new Process { StartInfo = psi };
            proc.Start();
            if (hasInput)
            {
                await proc.StandardInput.WriteLineAsync(stdinPassword!);
                proc.StandardInput.Close();
            }

            async Task ReadStreamAsync(StreamReader reader, Color color)
            {
                string? line;
                while ((line = await reader.ReadLineAsync()) != null)
                {
                    var stageMatch = CliProgressStageRe.Match(line);
                    if (stageMatch.Success)
                    {
                        onStage?.Invoke(NormalizeProgressStage(stageMatch.Groups["stage"].Value));
                        continue;
                    }
                    if (TryParseProgressNumbers(line, out var processed, out var total))
                    {
                        onProgress?.Invoke(processed, total);
                        continue;
                    }
                    LogVault(line, color);
                }
            }

            await Task.WhenAll(
                ReadStreamAsync(proc.StandardOutput, Theme.Accent),
                ReadStreamAsync(proc.StandardError, Theme.Error));
            await proc.WaitForExitAsync();
            if (proc.ExitCode != 0)
            {
                VaultStatusError($"vault extract failed for '{vaultItemPath}' (exit {proc.ExitCode}).");
                return false;
            }
            return true;
        }
        catch (Exception ex)
        {
            VaultStatusError($"Extract failed for '{vaultItemPath}': {ex.Message}");
            return false;
        }
    }

    private async Task OpenVaultItemSecureAsync(string vaultItemPath)
    {
        if (!TryGetVaultPath(out _)) return;
        if (!TryBuildVaultAuth(out _, out _)) return;

        string tempRoot = Path.Combine(Path.GetTempPath(), "ObsidianQ", "preview", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempRoot);
        try
        {
            string? extracted = await ExtractVaultItemToTempAsync(vaultItemPath, tempRoot);
            if (extracted == null) return;

            byte[] data = await File.ReadAllBytesAsync(extracted);
            using var preview = new VaultPreviewForm(vaultItemPath, data);
            preview.ShowDialog(this);
        }
        catch (Exception ex)
        {
            VaultStatusError($"Open failed: {ex.Message}");
        }
        finally
        {
            try { if (Directory.Exists(tempRoot)) Directory.Delete(tempRoot, true); } catch { /* best effort */ }
        }
    }

    private async Task OpenVaultItemExternalAsync(string vaultItemPath)
    {
        if (!TryGetVaultPath(out var vaultPath)) return;
        if (!TryBuildVaultAuth(out var authArgs, out var stdinPassword)) return;

        var answer = MessageBox.Show(
            "Open externally will decrypt to a temporary file so an associated app can open it.\n\n" +
            "If you save changes, ObsidianQ can write them back to the vault after the app closes.\n" +
            "ObsidianQ will attempt best-effort cleanup after the session ends.\n" +
            "Proceed?",
            "Open externally",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Warning,
            MessageBoxDefaultButton.Button2);
        if (answer != DialogResult.Yes) return;

        string sessionDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "ObsidianQ", "open_sessions", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(sessionDir);
        _externalOpenSessionDirs.Add(sessionDir);

        try
        {
            string? extracted = await ExtractVaultItemToTempAsync(vaultItemPath, sessionDir);
            if (extracted == null) return;
            var fi = new FileInfo(extracted);
            var session = new ExternalOpenSession
            {
                SessionDir = sessionDir,
                VaultPath = vaultPath,
                VaultItemPath = vaultItemPath,
                ExtractedPath = extracted,
                AuthArgs = authArgs,
                StdinPassword = stdinPassword,
                OriginalLength = fi.Exists ? fi.Length : 0,
                OriginalWriteUtc = fi.Exists ? fi.LastWriteTimeUtc : DateTime.MinValue,
            };

            var psi = new ProcessStartInfo
            {
                FileName = extracted,
                UseShellExecute = true,
                Verb = "open",
            };
            var proc = Process.Start(psi);
            VaultStatusOk($"Opened '{vaultItemPath}' externally (temporary session).");
            _ = Task.Run(async () => await HandleExternalOpenSessionAsync(session, proc));
        }
        catch (Exception ex)
        {
            VaultStatusError($"External open failed: {ex.Message}");
            CleanupExternalOpenSession(sessionDir);
        }
    }

    private async Task HandleExternalOpenSessionAsync(ExternalOpenSession session, Process? proc)
    {
        bool shouldCleanup = true;
        try
        {
            if (proc != null)
            {
                try { await proc.WaitForExitAsync(); } catch { /* ignored */ }
            }
            else
            {
                await Task.Delay(TimeSpan.FromMinutes(20));
            }

            if (!HasExternalOpenFileChanged(session))
                return;

            bool commitRequested = PromptCommitExternalChanges(session.VaultItemPath);
            if (!commitRequested)
                return;

            bool committed = await CommitExternalOpenSessionAsync(session);
            if (!committed)
            {
                shouldCleanup = false;
                UiNotice(
                    "Failed to commit edited file back to vault. Temporary session was kept for recovery:\n" +
                    session.SessionDir,
                    "Commit failed");
            }
        }
        finally
        {
            if (shouldCleanup)
                CleanupExternalOpenSession(session.SessionDir);
            else
                _externalOpenSessionDirs.Remove(session.SessionDir);
        }
    }

    private bool HasExternalOpenFileChanged(ExternalOpenSession session)
    {
        try
        {
            var fi = new FileInfo(session.ExtractedPath);
            if (!fi.Exists) return false;
            return fi.Length != session.OriginalLength || fi.LastWriteTimeUtc != session.OriginalWriteUtc;
        }
        catch
        {
            return false;
        }
    }

    private bool PromptCommitExternalChanges(string vaultItemPath)
    {
        if (IsDisposed || Disposing) return false;
        if (InvokeRequired)
        {
            try
            {
                return (bool)Invoke(new Func<bool>(() => PromptCommitExternalChanges(vaultItemPath)));
            }
            catch
            {
                return false;
            }
        }

        var answer = MessageBox.Show(
            this,
            $"Changes were detected for '{vaultItemPath}'.\n\nSave changes back into the vault?",
            "Commit edited file",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Question,
            MessageBoxDefaultButton.Button1);
        return answer == DialogResult.Yes;
    }

    private async Task<bool> CommitExternalOpenSessionAsync(ExternalOpenSession session)
    {
        try
        {
            bool ok = await ExecuteVaultAddWithProgressAsync(
                session.VaultPath,
                session.ExtractedPath,
                session.VaultItemPath,
                session.AuthArgs,
                session.StdinPassword,
                null,
                null);
            if (!ok)
            {
                VaultStatusError($"Commit failed for '{session.VaultItemPath}'.");
                return false;
            }

            VaultStatusOk($"Committed changes for '{session.VaultItemPath}'.");
            if (string.Equals(_dropZoneVault.FilePath, session.VaultPath, StringComparison.OrdinalIgnoreCase))
            {
                if (InvokeRequired) BeginInvoke(new Action(() => _ = RefreshVaultContentsAsync()));
                else _ = RefreshVaultContentsAsync();
            }
            return true;
        }
        catch (Exception ex)
        {
            VaultStatusError($"Commit failed for '{session.VaultItemPath}': {ex.Message}");
            return false;
        }
    }

    private void UiNotice(string message, string title)
    {
        if (IsDisposed || Disposing) return;
        if (InvokeRequired)
        {
            try { BeginInvoke(new Action(() => UiNotice(message, title))); } catch { /* ignore */ }
            return;
        }
        MessageBox.Show(this, message, title, MessageBoxButtons.OK, MessageBoxIcon.Warning);
    }

    private async Task<string?> ExtractVaultItemToTempAsync(string vaultItemPath, string tempRoot)
    {
        bool ok = await ExecuteVaultExtractAsync(vaultItemPath, tempRoot);
        if (!ok) return null;

        string rel = vaultItemPath.TrimStart('/').Replace('/', Path.DirectorySeparatorChar);
        string extracted = Path.Combine(tempRoot, rel);
        if (!File.Exists(extracted))
        {
            var first = Directory.EnumerateFiles(tempRoot, "*", SearchOption.AllDirectories).FirstOrDefault();
            if (first == null)
            {
                VaultStatusError($"Open failed: extracted file not found for '{vaultItemPath}'.");
                return null;
            }
            extracted = first;
        }
        return extracted;
    }

    private void CleanupExternalOpenSession(string sessionDir)
    {
        try
        {
            if (!Directory.Exists(sessionDir)) return;
            foreach (var file in Directory.EnumerateFiles(sessionDir, "*", SearchOption.AllDirectories))
            {
                try { SecureDeleteFileBestEffort(file); } catch { /* best effort */ }
            }
            foreach (var dir in Directory.EnumerateDirectories(sessionDir, "*", SearchOption.AllDirectories)
                .OrderByDescending(d => d.Length))
            {
                try { Directory.Delete(dir, false); } catch { /* best effort */ }
            }
            try { Directory.Delete(sessionDir, false); } catch { /* best effort */ }
        }
        finally
        {
            _externalOpenSessionDirs.Remove(sessionDir);
        }
    }

    private static void SecureDeleteFileBestEffort(string filePath)
    {
        var fi = new FileInfo(filePath);
        if (!fi.Exists) return;
        if (fi.IsReadOnly) fi.IsReadOnly = false;

        long len = fi.Length;
        if (len > 0)
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Write, FileShare.None);
            byte[] zeros = new byte[64 * 1024];
            long remaining = len;
            while (remaining > 0)
            {
                int n = (int)Math.Min(zeros.Length, remaining);
                fs.Write(zeros, 0, n);
                remaining -= n;
            }
            fs.Flush(true);
        }
        File.Delete(filePath);
    }

    private void CleanupStaleExternalOpenSessions()
    {
        try
        {
            string root = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "ObsidianQ", "open_sessions");
            if (!Directory.Exists(root)) return;
            foreach (var dir in Directory.EnumerateDirectories(root))
            {
                try
                {
                    var age = DateTime.UtcNow - Directory.GetLastWriteTimeUtc(dir);
                    if (age > TimeSpan.FromHours(12))
                        CleanupExternalOpenSession(dir);
                }
                catch { /* best effort */ }
            }
        }
        catch { /* best effort */ }
    }

    // -----------------------------------------------------------------------
    // FILE TAB – RUN operation
    // -----------------------------------------------------------------------
    private async void BtnRun_Click(object? sender, EventArgs e)
    {
        if (_busy) { CancelOperation(); return; }
        if (!EnsureFileRecipientsForPqcEncrypt()) return;
        if (!ValidateInputs(out string? errMsg)) { StatusError(errMsg!); return; }
        await RunOperationAsync();
    }

    private bool EnsureFileRecipientsForPqcEncrypt()
    {
        if (_toggle.Selected != SegmentedToggle.Segment.Pqc) return true;
        string? filePath = _dropZone.FilePath;
        if (string.IsNullOrWhiteSpace(filePath)) return true;

        bool isEncrypt = !filePath.EndsWith(".obsq", StringComparison.OrdinalIgnoreCase);
        if (!isEncrypt) return true; // decrypt path is private-key based

        string? picked = ShowRecipientsPicker(_txtPrivkey.Text);
        if (string.IsNullOrWhiteSpace(picked))
        {
            StatusError("Encryption cancelled: no recipients selected.");
            return false;
        }

        _txtPrivkey.Text = picked;
        return true;
    }

    private bool ValidateInputs(out string? err)
    {
        err = null;
        if (_dropZone.FilePath == null)                                           { err = "Drop or browse an input file first."; return false; }
        if (!File.Exists(_dropZone.FilePath))                                     { err = "Input file not found."; return false; }
        if (string.IsNullOrWhiteSpace(_lblOutPath.Text) || _lblOutPath.Text == "-") { err = "Output path is not set."; return false; }

        bool isPqc = _toggle.Selected == SegmentedToggle.Segment.Pqc;
        if (!isPqc)
        {
            if (string.IsNullOrEmpty(_txtPassword.Text)) { err = "Enter a password."; return false; }
            bool isEncrypt = !_dropZone.FilePath.EndsWith(".obsq", StringComparison.OrdinalIgnoreCase);
            if (isEncrypt && _txtPassword.Text != _txtConfirm.Text) { err = "Passwords do not match."; return false; }
        }
        else
        {
            if (string.IsNullOrWhiteSpace(_txtPrivkey.Text)) { err = "Specify key file path."; return false; }
            bool isEncrypt = !_dropZone.FilePath.EndsWith(".obsq", StringComparison.OrdinalIgnoreCase);
            if (isEncrypt)
            {
                var keys = ParseRecipientKeyPaths(_txtPrivkey.Text);
                if (keys.Count == 0) { err = "No valid recipient key path(s) found."; return false; }
                if (keys.Any(k => !File.Exists(k))) { err = "One or more recipient key files were not found."; return false; }
            }
            else
            {
                var keys = ParseRecipientKeyPaths(_txtPrivkey.Text);
                if (keys.Count == 0 || !File.Exists(keys[0])) { err = "Key file not found."; return false; }
            }
        }

        if (!File.Exists(ExePath)) { err = $"obsidianq.exe not found at:\n{ExePath}"; return false; }
        return true;
    }

    private async Task RunOperationAsync()
    {
        SetBusy(true);
        _rtbLog.Clear();

        bool isEncrypt = !(_dropZone.FilePath ?? "").EndsWith(".obsq", StringComparison.OrdinalIgnoreCase);
        bool isPqc     = _toggle.Selected == SegmentedToggle.Segment.Pqc;
        string suite   = _cmbSuite.SelectedIndex == 0 ? "xchacha20" : "aesgcm";
        if (!isEncrypt && isPqc)
        {
            var keys = ParseRecipientKeyPaths(_txtPrivkey.Text);
            if (keys.Count > 0) _txtPrivkey.Text = keys[0];
        }
        List<string>? encryptRecipientKeys = null;
        if (isEncrypt && isPqc)
        {
            encryptRecipientKeys = ParseRecipientKeyPaths(_txtPrivkey.Text);
            if (encryptRecipientKeys.Count == 0)
            {
                StatusError("No recipient public key(s) selected.");
                SetBusy(false);
                return;
            }
            _txtPrivkey.Text = string.Join("; ", encryptRecipientKeys);
        }

        var sb = new StringBuilder();
        if (isEncrypt)
        {
            sb.Append("encrypt");
            sb.Append($" --in \"{_dropZone.FilePath}\"");
            sb.Append($" --out \"{_lblOutPath.Text}\"");
            sb.Append($" --suite {suite}");
            if (_chkCompress.Checked) sb.Append(" --compress");
            if (isPqc)
            {
                foreach (string key in encryptRecipientKeys ?? ParseRecipientKeyPaths(_txtPrivkey.Text))
                    sb.Append($" --pubkey \"{key}\"");
            }
            else       sb.Append(" --password-stdin");
        }
        else
        {
            sb.Append("decrypt");
            sb.Append($" --in \"{_dropZone.FilePath}\"");
            sb.Append($" --out \"{_lblOutPath.Text}\"");
            if (isPqc) sb.Append($" --privkey \"{_txtPrivkey.Text}\"");
            else       sb.Append(" --password-stdin");
        }

        Log($"[CMD] obsidianq {sb}", Theme.TextDim);
        Log("", Theme.TextDim);

        _cts = new CancellationTokenSource();
        var token = _cts.Token;
        string password = isPqc ? "" : _txtPassword.Text;
        long inputBytes = 0;
        try { inputBytes = new FileInfo(_dropZone.FilePath!).Length; } catch { }
        var sw = Stopwatch.StartNew();

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = ExePath, Arguments = sb.ToString(),
                RedirectStandardInput  = !isPqc, RedirectStandardOutput = true,
                RedirectStandardError  = true, UseShellExecute = false, CreateNoWindow = true,
            };
            var proc = new Process { StartInfo = psi, EnableRaisingEvents = true };
            proc.Start();

            if (!isPqc) { await proc.StandardInput.WriteLineAsync(password); proc.StandardInput.Close(); }

            var stdoutTask = StreamOutputAsync(proc.StandardOutput, Theme.Accent, token);
            var stderrTask = StreamOutputAsync(proc.StandardError,  Theme.Error,  token);
            await Task.WhenAll(stdoutTask, stderrTask);
            await proc.WaitForExitAsync(token);
            sw.Stop();

            if (proc.ExitCode == 0)
            {
                _fileProgressStage = "done";
                _fileProgressBar.Style = ProgressBarStyle.Continuous;
                _fileProgressBar.Value = 100;
                StatusOk(isEncrypt ? "Encryption complete." : "Decryption complete.");
                double sec = Math.Max(0.001, sw.Elapsed.TotalSeconds);
                long throughputBytes = inputBytes;
                try
                {
                    if (File.Exists(_lblOutPath.Text))
                    {
                        long outBytes = new FileInfo(_lblOutPath.Text).Length;
                        if (outBytes > throughputBytes) throughputBytes = outBytes;
                    }
                }
                catch { /* best effort */ }
                if (throughputBytes > 0)
                {
                    double mbps = (throughputBytes / 1_048_576.0) / sec;
                    Log($"[THROUGHPUT] {(isEncrypt ? "Encrypt" : "Decrypt")} avg {mbps:0.##} MB/s ({FormatBytes(throughputBytes)} in {sec:0.##}s)", Theme.AccentDim);
                }
            }
            else                    StatusError($"Process exited with code {proc.ExitCode}.");
        }
        catch (OperationCanceledException) { StatusError("Cancelled."); }
        catch (Exception ex)               { Log($"[ERROR] {ex.Message}", Theme.Error); StatusError("Operation failed."); }
        finally                            { SetBusy(false); _cts?.Dispose(); _cts = null; }
    }

    private static List<string> ParseRecipientKeyPaths(string raw)
    {
        var keys = new List<string>();
        if (string.IsNullOrWhiteSpace(raw)) return keys;
        foreach (string part in raw.Split(new[] { ';', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries))
        {
            string p = part.Trim().Trim('"');
            if (!string.IsNullOrWhiteSpace(p))
                keys.Add(p);
        }
        return keys.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private sealed class RecipientPickerItem
    {
        public string Label { get; init; } = string.Empty;
        public string KeyPath { get; init; } = string.Empty;
        public override string ToString() => Label;
    }

    private string? ShowRecipientsPicker(string currentRaw)
    {
        var current = ParseRecipientKeyPaths(currentRaw);
        var options = new List<RecipientPickerItem>();

        string? myDefaultPub = FindLatestKeyPath(wantPublic: true, LocalKeysDir, BundleKeysDir);
        if (!string.IsNullOrWhiteSpace(myDefaultPub) && File.Exists(myDefaultPub))
        {
            options.Add(new RecipientPickerItem
            {
                Label = $"Me (default) - {Path.GetFileName(myDefaultPub)}",
                KeyPath = myDefaultPub,
            });
        }

        string recipientsPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "ObsidianQ",
            "trusted_recipients_v1.tsv");
        string contactsDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "ObsidianQ",
            "contacts_pubkeys");
        Directory.CreateDirectory(contactsDir);

        if (File.Exists(recipientsPath))
        {
            foreach (string line in File.ReadAllLines(recipientsPath))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                string[] parts = line.Split('\t');
                if (parts.Length < 5) continue;
                string name = parts[0].Trim();
                string fp = parts[1].Trim();
                string b64 = parts[4].Trim();
                if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(b64)) continue;

                byte[] raw;
                try { raw = Convert.FromBase64String(b64); }
                catch { continue; }

                string shortFp = fp.Length > 8 ? fp[..8] : fp;
                string safeName = Regex.Replace(name, @"[^A-Za-z0-9_\-]+", "_");
                if (string.IsNullOrWhiteSpace(safeName)) safeName = "recipient";
                string keyPath = Path.Combine(contactsDir, $"{safeName}_{shortFp}.bin");
                try
                {
                    if (!File.Exists(keyPath) || !File.ReadAllBytes(keyPath).SequenceEqual(raw))
                        File.WriteAllBytes(keyPath, raw);
                }
                catch { continue; }

                options.Add(new RecipientPickerItem
                {
                    Label = $"{name} ({shortFp})",
                    KeyPath = keyPath,
                });
            }
        }

        if (options.Count == 0)
        {
            MessageBox.Show(
                this,
                "No recipient keys found.\n\nAdd recipients in Key Exchange first.",
                "Recipients",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            return null;
        }

        using var dlg = new Form
        {
            Text = "Select Recipients",
            StartPosition = FormStartPosition.CenterParent,
            FormBorderStyle = FormBorderStyle.FixedDialog,
            MaximizeBox = false,
            MinimizeBox = false,
            ShowInTaskbar = false,
            ClientSize = new Size(540, 360),
            BackColor = Theme.Bg,
            ForeColor = Theme.TextMain,
            Font = Theme.SafeMono(9f),
        };
        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 3,
            Padding = new Padding(14),
            BackColor = Theme.Bg,
        };
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 24));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 36));
        var lbl = MakeLabel("SELECT ONE OR MORE RECIPIENTS", 8.5f, bold: true);
        lbl.Dock = DockStyle.Fill;
        lbl.TextAlign = ContentAlignment.MiddleLeft;
        lbl.ForeColor = Theme.Accent;
        var clb = new CheckedListBox
        {
            Dock = DockStyle.Fill,
            BackColor = Theme.Surface,
            ForeColor = Theme.TextMain,
            BorderStyle = BorderStyle.FixedSingle,
            CheckOnClick = true,
            Font = Theme.SafeMono(9f),
        };
        clb.HandleCreated += (_, _) => SetWindowTheme(clb.Handle, "DarkMode_Explorer", null);
        foreach (var opt in options)
        {
            bool isChecked = current.Contains(opt.KeyPath, StringComparer.OrdinalIgnoreCase)
                || (current.Count == 0 && myDefaultPub != null && string.Equals(opt.KeyPath, myDefaultPub, StringComparison.OrdinalIgnoreCase));
            clb.Items.Add(opt, isChecked);
        }

        var btns = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, BackColor = Theme.Bg };
        btns.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        btns.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        var btnCancel = new NeonButton { Text = "CANCEL", Dock = DockStyle.Fill, Margin = new Padding(0, 0, 4, 0) };
        var btnApply = new NeonButton { Text = "APPLY", Dock = DockStyle.Fill, Margin = new Padding(4, 0, 0, 0) };
        btnCancel.Click += (_, _) => { dlg.DialogResult = DialogResult.Cancel; dlg.Close(); };
        btnApply.Click += (_, _) => { dlg.DialogResult = DialogResult.OK; dlg.Close(); };
        btns.Controls.Add(btnCancel, 0, 0);
        btns.Controls.Add(btnApply, 1, 0);
        root.Controls.Add(lbl, 0, 0);
        root.Controls.Add(clb, 0, 1);
        root.Controls.Add(btns, 0, 2);
        dlg.Controls.Add(root);

        if (dlg.ShowDialog(this) != DialogResult.OK) return null;
        var selected = clb.CheckedItems.Cast<RecipientPickerItem>().Select(i => i.KeyPath).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (selected.Count == 0) return null;
        return string.Join("; ", selected);
    }

    private static string BuildRecipientOutputPath(string baseOut, string keyPath, int index)
    {
        string dir = Path.GetDirectoryName(baseOut) ?? Environment.CurrentDirectory;
        string stem = Path.GetFileNameWithoutExtension(baseOut);
        string ext = Path.GetExtension(baseOut);
        if (string.IsNullOrWhiteSpace(ext)) ext = ".obsq";
        string keyStem = Path.GetFileNameWithoutExtension(keyPath);
        string safe = Regex.Replace(keyStem, @"[^A-Za-z0-9_\-]+", "_");
        if (string.IsNullOrWhiteSpace(safe)) safe = $"recipient_{index}";
        return Path.Combine(dir, $"{stem}__{safe}{ext}");
    }

    private async Task StreamOutputAsync(System.IO.TextReader reader, Color color, CancellationToken ct)
    {
        string? line;
        while ((line = await reader.ReadLineAsync(ct)) != null)
        {
            if (TryHandleCliProgressStageLine(line)) continue;
            if (TryHandleCliProgressLine(line)) continue;
            Log(line, color);
        }
    }

    private bool TryHandleCliProgressStageLine(string line)
    {
        var m = CliProgressStageRe.Match(line);
        if (!m.Success) return false;
        string stage = m.Groups["stage"].Value;
        _fileProgressStage = NormalizeProgressStage(stage);
        return true;
    }

    private static string NormalizeProgressStage(string stage)
    {
        return stage switch
        {
            "preparing" => "preparing",
            "encrypting" => "encrypting",
            "decrypting" => "decrypting",
            "finalizing" => "finalizing",
            _ => "processing",
        };
    }

    private bool TryHandleCliProgressLine(string line)
    {
        var m = CliProgressRe.Match(line);
        if (!m.Success) return false;
        if (!long.TryParse(m.Groups["processed"].Value, out var processed)) return false;
        if (!long.TryParse(m.Groups["total"].Value, out var total)) return false;
        UpdateFileProgress(processed, total);
        return true;
    }

    private void UpdateFileProgress(long processed, long total)
    {
        if (InvokeRequired) { Invoke(() => UpdateFileProgress(processed, total)); return; }
        long safeTotal = Math.Max(1, total);
        long clamped = Math.Max(0, Math.Min(processed, safeTotal));
        int pct = (int)Math.Max(0, Math.Min(100, (clamped * 100) / safeTotal));
        if (_busy && pct >= 100) pct = 99; // keep 100% for process completion only
        _fileProgressBar.Style = ProgressBarStyle.Continuous;
        _fileProgressBar.Value = pct;

        double elapsedSec = Math.Max(0.001, (DateTime.UtcNow - _fileProgressStartUtc).TotalSeconds);
        double mbps = (clamped / 1_048_576.0) / elapsedSec;
        string eta = "-";
        if (clamped > 0 && clamped < safeTotal)
        {
            double remaining = safeTotal - clamped;
            double bps = clamped / elapsedSec;
            if (bps > 0)
            {
                int etaSec = (int)Math.Ceiling(remaining / bps);
                int mm = etaSec / 60;
                int ss = etaSec % 60;
                eta = $"{mm:D2}:{ss:D2}";
            }
        }
        _lblStatus.Text = $"{_fileProgressStage} {pct}% | {FormatBytes(clamped)} / {FormatBytes(safeTotal)} | {mbps:0.##} MB/s | ETA {eta}";
    }

    private void CancelOperation()
    {
        _cts?.Cancel();
        Log("[CANCELLED]", Theme.Error);
    }

    // -----------------------------------------------------------------------
    // UI state helpers
    // -----------------------------------------------------------------------
    private void SetBusy(bool busy)
    {
        _busy = busy;
        _btnRun.Text = busy ? "CANCEL" : "RUN";
        if (busy)
        {
            _fileProgressStartUtc = DateTime.UtcNow;
            _fileProgressStage = "processing";
            _fileProgressBar.Style = ProgressBarStyle.Marquee;
            _fileProgressBar.MarqueeAnimationSpeed = 24;
            _fileProgressBar.Value = 0;
        }
        else
        {
            _fileProgressBar.Style = ProgressBarStyle.Continuous;
        }
        if (busy) _shimmer.Start(); else _shimmer.Stop();
    }

    private void StatusOk(string msg)
    {
        _lblStatus.ForeColor = Theme.Accent;
        _lblStatus.Text = msg;
        Log($"\n[OK] {msg}", Theme.Accent);
    }

    private void StatusError(string msg)
    {
        _lblStatus.ForeColor = Theme.Error;
        _lblStatus.Text = msg;
        Log($"\n[ERR] {msg}", Theme.Error);
    }

    private void VaultStatusOk(string msg)
    {
        if (InvokeRequired) { Invoke(() => VaultStatusOk(msg)); return; }
        _lblStatusVault.ForeColor = Theme.Accent;
        _lblStatusVault.Text = msg;
    }

    private void VaultStatusError(string msg)
    {
        if (InvokeRequired) { Invoke(() => VaultStatusError(msg)); return; }
        _lblStatusVault.ForeColor = Theme.Error;
        _lblStatusVault.Text = msg;
        LogVault($"[ERR] {msg}", Theme.Error);
    }

    private void Log(string text, Color color)
    {
        if (InvokeRequired) { Invoke(() => Log(text, color)); return; }
        _rtbLog.SelectionStart = _rtbLog.TextLength;
        _rtbLog.SelectionLength = 0;
        _rtbLog.SelectionColor = color;
        _rtbLog.AppendText(text + "\n");
        _rtbLog.ScrollToCaret();
    }

    private void LogVault(string text, Color color)
    {
        if (InvokeRequired) { Invoke(() => LogVault(text, color)); return; }
        _rtbLogVault.SelectionStart = _rtbLogVault.TextLength;
        _rtbLogVault.SelectionLength = 0;
        _rtbLogVault.SelectionColor = color;
        _rtbLogVault.AppendText(text + "\n");
        _rtbLogVault.ScrollToCaret();
    }

    // -----------------------------------------------------------------------
    // Locate obsidianq.exe
    // -----------------------------------------------------------------------
    private static string ResolveExePath()
    {
        string self = AppContext.BaseDirectory;
        string candidate = Path.Combine(self, "obsidianq.exe");
        if (File.Exists(candidate)) return candidate;

        string repoRoot = Path.GetFullPath(Path.Combine(self, "..", ".."));
        candidate = Path.Combine(repoRoot, "target", "release", "obsidianq.exe");
        if (File.Exists(candidate)) return candidate;

        candidate = Path.Combine(repoRoot, "target", "debug", "obsidianq.exe");
        if (File.Exists(candidate)) return candidate;

        string? embedded = TryExtractEmbeddedCli();
        if (!string.IsNullOrWhiteSpace(embedded) && File.Exists(embedded))
            return embedded;

        return Path.Combine(self, "obsidianq.exe");
    }

    private static string ResolveExtractorStubPath()
    {
        string? native = TryExtractEmbeddedNativeBootstrapper();
        if (!string.IsNullOrWhiteSpace(native) && File.Exists(native))
            return native;

        string? embedded = TryExtractEmbeddedExtractorStub();
        if (!string.IsNullOrWhiteSpace(embedded) && File.Exists(embedded))
            return embedded;

        string self = AppContext.BaseDirectory;
        string nativeCandidate = Path.Combine(self, "ObsidianQ.Bootstrapper.exe");
        if (File.Exists(nativeCandidate)) return nativeCandidate;

        string candidate = Path.Combine(self, "ObsidianQ.Extractor.exe");
        if (File.Exists(candidate)) return candidate;

        string repoRoot = Path.GetFullPath(Path.Combine(self, "..", ".."));
        string[] candidates =
        [
            Path.Combine(repoRoot, "target", "release", "obsidianq-bootstrapper.exe"),
            Path.Combine(repoRoot, "target", "debug", "obsidianq-bootstrapper.exe"),
            Path.Combine(repoRoot, "tools", "windows-extractor", "bin", "Debug", "net8.0-windows", "win-x64", "ObsidianQ.Extractor.exe"),
            Path.Combine(repoRoot, "tools", "windows-extractor", "bin", "Release", "net8.0-windows", "win-x64", "ObsidianQ.Extractor.exe"),
            Path.Combine(repoRoot, "tools", "windows-extractor", "bin", "Debug", "net8.0-windows", "ObsidianQ.Extractor.exe"),
            Path.Combine(repoRoot, "tools", "windows-extractor", "bin", "Release", "net8.0-windows", "ObsidianQ.Extractor.exe"),
        ];
        foreach (var c in candidates)
            if (File.Exists(c)) return c;

        return candidate;
    }

    private static string? TryExtractEmbeddedNativeBootstrapper()
    {
        const string resourceName = "ObsidianQ.Launcher.Embedded.ObsidianQ.Bootstrapper.exe";
        try
        {
            var asm = Assembly.GetExecutingAssembly();
            using var stream = asm.GetManifestResourceStream(resourceName);
            if (stream == null) return null;

            using var ms = new MemoryStream();
            stream.CopyTo(ms);
            byte[] bytes = ms.ToArray();
            return WriteEmbeddedBinaryWithHash("ObsidianQ.Bootstrapper.embedded", bytes);
        }
        catch
        {
            return null;
        }
    }

    private static string? TryExtractEmbeddedExtractorStub()
    {
        const string resourceName = "ObsidianQ.Launcher.Embedded.ObsidianQ.Extractor.exe";
        try
        {
            var asm = Assembly.GetExecutingAssembly();
            using var stream = asm.GetManifestResourceStream(resourceName);
            if (stream == null) return null;

            using var ms = new MemoryStream();
            stream.CopyTo(ms);
            byte[] bytes = ms.ToArray();
            return WriteEmbeddedBinaryWithHash("ObsidianQ.Extractor.embedded", bytes);
        }
        catch
        {
            return null;
        }
    }

    private static string? TryExtractEmbeddedCli()
    {
        const string resourceName = "ObsidianQ.Launcher.Embedded.obsidianq.exe";
        try
        {
            var asm = Assembly.GetExecutingAssembly();
            using var stream = asm.GetManifestResourceStream(resourceName);
            if (stream == null) return null;

            using var ms = new MemoryStream();
            stream.CopyTo(ms);
            byte[] bytes = ms.ToArray();
            return WriteEmbeddedBinaryWithHash("obsidianq.embedded", bytes);
        }
        catch
        {
            return null;
        }
    }

    private static string WriteEmbeddedBinaryWithHash(string logicalBaseName, byte[] bytes)
    {
        string cacheDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "ObsidianQ",
            "embedded");
        Directory.CreateDirectory(cacheDir);

        string hashHex;
        using (var sha = SHA256.Create())
        {
            byte[] hash = sha.ComputeHash(bytes);
            hashHex = Convert.ToHexString(hash).ToLowerInvariant()[..12];
        }

        string outPath = Path.Combine(cacheDir, $"{logicalBaseName}.{hashHex}.exe");
        if (!File.Exists(outPath))
            File.WriteAllBytes(outPath, bytes);

        return outPath;
    }

    // -----------------------------------------------------------------------
    // Dark mode: title bar
    // -----------------------------------------------------------------------
    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);

    [DllImport("uxtheme.dll", CharSet = CharSet.Unicode)]
    private static extern int SetWindowTheme(IntPtr hwnd, string? pszSubAppName, string? pszSubIdList);

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        int dark = 1;
        DwmSetWindowAttribute(Handle, 20 /* DWMWA_USE_IMMERSIVE_DARK_MODE */, ref dark, 4);
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        if (_mountProc != null && !_mountProc.HasExited)
        {
            try
            {
                string unmountArgs = _isVaultMount
                    ? $"vault unmount --drive {_mountedDrive}:"
                    : $"unmount --drive {_mountedDrive}:";
                var psi = new ProcessStartInfo
                {
                    FileName        = ExePath,
                    Arguments       = unmountArgs,
                    UseShellExecute = false, CreateNoWindow = true,
                };
                using var sig = Process.Start(psi);
                sig?.WaitForExit(2000);
            }
            catch { /* best effort — don't block the close */ }
        }
        foreach (var dir in _externalOpenSessionDirs.ToArray())
        {
            try { CleanupExternalOpenSession(dir); } catch { /* best effort */ }
        }
        base.OnFormClosing(e);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) { _shimmer.Dispose(); }
        base.Dispose(disposing);
    }
}




