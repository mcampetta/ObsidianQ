using System.Diagnostics;
using System.Text.Json;
using System.Text;

[assembly: System.Runtime.Versioning.SupportedOSPlatform("windows")]

namespace ObsidianQ.Extractor;

static class Program
{
    private const string EmbeddedSfxMagic = "OBSQSFX1";
    private const int EmbeddedSfxTrailerSize = 24; // zipLen(8) + cliLen(8) + magic(8)

    private sealed record EmbeddedSfxInfo(long PackageOffset, long PackageLength, long CliOffset, long CliLength);
    private sealed record PackageSummary(string PackageId, string PackageName, string Sender, string Created, string AppVersion, string RecipientMode, List<string> Files, bool Signed, bool SenderIdentityPresent);

    [STAThread]
    static void Main(string[] args)
    {
        Application.SetHighDpiMode(HighDpiMode.SystemAware);
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);

        string hostExePath = Environment.ProcessPath ?? Application.ExecutablePath;
        if (TryGetEmbeddedSfxInfo(hostExePath, out var sfxInfo))
        {
            RunEmbeddedSfxExtractor(hostExePath, sfxInfo);
            Environment.Exit(0);
            return;
        }

        if (TryResolveExternalBundle(hostExePath, args, out var pkgPath, out var cliPath))
        {
            RunPackageExtractor(hostExePath, cliPath, pkgPath);
            Environment.Exit(0);
            return;
        }

        MessageBox.Show(
            "This viewer could not find an embedded package or a sibling Secure Delivery bundle. Keep Click_Here_to_Decrypt.exe, the packaged ZIP, and obsidianq.exe in the same folder.",
            "ObsidianQ Extractor",
            MessageBoxButtons.OK,
            MessageBoxIcon.Error);
        Environment.Exit(2);
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

    private static bool TryResolveExternalBundle(string hostExePath, string[] args, out string packagePath, out string cliPath)
    {
        packagePath = string.Empty;
        cliPath = string.Empty;

        string baseDir = Path.GetDirectoryName(hostExePath) ?? AppContext.BaseDirectory;
        string cliCandidate = Path.Combine(baseDir, "obsidianq.exe");
        if (!File.Exists(cliCandidate))
            return false;

        string? explicitArg = args.FirstOrDefault(a => File.Exists(a) && string.Equals(Path.GetExtension(a), ".zip", StringComparison.OrdinalIgnoreCase));
        if (!string.IsNullOrWhiteSpace(explicitArg))
        {
            packagePath = explicitArg;
            cliPath = cliCandidate;
            return true;
        }

        string namedBundle = Path.Combine(baseDir, "SecureDeliveryPackage.zip");
        if (File.Exists(namedBundle))
        {
            packagePath = namedBundle;
            cliPath = cliCandidate;
            return true;
        }

        string[] candidatePackages = Directory.GetFiles(baseDir, "*.zip")
            .Where(p => !string.Equals(Path.GetFileName(p), "SecureDeliveryPackage.zip", StringComparison.OrdinalIgnoreCase))
            .Where(p => !string.Equals(Path.GetFileName(p), Path.GetFileName(hostExePath), StringComparison.OrdinalIgnoreCase))
            .ToArray();
        if (candidatePackages.Length == 1)
        {
            packagePath = candidatePackages[0];
            cliPath = cliCandidate;
            return true;
        }

        return false;
    }

    private static string BuildSummaryText(PackageSummary summary)
    {
        var sb = new StringBuilder();
        sb.AppendLine("Secure Delivery Package");
        sb.AppendLine();
        sb.AppendLine($"Package name: {summary.PackageName}");
        sb.AppendLine($"Package ID: {summary.PackageId}");
        sb.AppendLine($"Signing identity: {summary.Sender}");
        sb.AppendLine($"Created: {summary.Created}");
        sb.AppendLine($"Created by version: {summary.AppVersion}");
        sb.AppendLine($"Recipient mode: {summary.RecipientMode}");
        sb.AppendLine();
        sb.AppendLine("Files:");
        if (summary.Files.Count == 0) sb.AppendLine("- (not listed)");
        else
        {
            foreach (string file in summary.Files.Take(12))
                sb.AppendLine($"- {file}");
            if (summary.Files.Count > 12)
                sb.AppendLine($"- ... and {summary.Files.Count - 12} more");
        }
        sb.AppendLine();
        sb.AppendLine("Verification:");
        if (summary.Signed) sb.AppendLine("- Package signature valid");
        if (summary.SenderIdentityPresent) sb.AppendLine("- Signing identity present");
        sb.AppendLine("- Contents match manifest");
        sb.AppendLine("- No tampering detected");
        return sb.ToString();
    }

    private static void ShowPackageSummary(PackageSummary summary)
    {
        using var dlg = new Form
        {
            Text = "Package Information",
            StartPosition = FormStartPosition.CenterParent,
            FormBorderStyle = FormBorderStyle.FixedDialog,
            MaximizeBox = false,
            MinimizeBox = false,
            ShowInTaskbar = false,
            ClientSize = new Size(404, 274),
            BackColor = Theme.Bg,
            ForeColor = Theme.TextMain,
            Font = Theme.SafeMono(9f),
        };
        try
        {
            var ico = Icon.ExtractAssociatedIcon(Environment.ProcessPath ?? Application.ExecutablePath);
            if (ico != null) dlg.Icon = ico;
        }
        catch { }

        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3, Padding = new Padding(12), BackColor = Theme.Bg };
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 22));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 36));

        var lbl = new Label
        {
            Text = "Package Information",
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft,
            BackColor = Theme.Bg,
            ForeColor = Theme.Accent,
            Font = Theme.SafeMono(9f),
        };
        var txt = new ThemedSummaryView
        {
            Dock = DockStyle.Fill,
            BackColor = Theme.Surface,
            ForeColor = Theme.TextMain,
            Font = Theme.SafeMono(8.25f),
            SummaryText = BuildSummaryText(summary),
            Margin = new Padding(6, 6, 6, 4),
        };
        var btnClose = new NeonButton
        {
            Text = "CLOSE",
            Anchor = AnchorStyles.Right | AnchorStyles.Top,
            Size = new Size(96, 28),
            Location = new Point(278, 4),
            Margin = new Padding(0),
        };
        btnClose.Click += (_, _) => dlg.Close();
        var actions = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Bg };
        actions.Controls.Add(btnClose);

        root.Controls.Add(lbl, 0, 0);
        root.Controls.Add(txt, 0, 1);
        root.Controls.Add(actions, 0, 2);
        dlg.Controls.Add(root);
        dlg.ShowDialog();
    }

    private static string? PromptForPassword(PackageSummary? summary = null)
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
        try
        {
            var ico = Icon.ExtractAssociatedIcon(Environment.ProcessPath ?? Application.ExecutablePath);
            if (ico != null) dlg.Icon = ico;
        }
        catch { }

        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 4, Padding = new Padding(12), BackColor = Theme.Bg };
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 20));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 34));

        var lbl = new Label
        {
            Text = "Enter password to decrypt package:",
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft,
            BackColor = Theme.Bg,
            ForeColor = Theme.TextMain,
            Font = Theme.SafeMono(8.75f),
        };
        var txt = new TextBox
        {
            Dock = DockStyle.Fill,
            UseSystemPasswordChar = true,
            BorderStyle = BorderStyle.FixedSingle,
            BackColor = Theme.Surface,
            ForeColor = Theme.Accent,
            Font = Theme.SafeMono(12f),
        };
        int actionColumns = summary == null ? 2 : 3;
        var actions = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = actionColumns, RowCount = 1, BackColor = Theme.Bg };
        for (int i = 0; i < actionColumns; i++)
            actions.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f / actionColumns));

        var btnCancel = new NeonButton { Text = "CANCEL", Dock = DockStyle.Fill, Margin = new Padding(0, 0, 4, 0) };
        var btnInfo = new NeonButton { Text = "INFO", Dock = DockStyle.Fill, Margin = new Padding(2, 0, 2, 0) };
        var btnOk = new NeonButton { Text = "DECRYPT", Dock = DockStyle.Fill, Margin = new Padding(4, 0, 0, 0) };
        btnCancel.Click += (_, _) => { dlg.DialogResult = DialogResult.Cancel; dlg.Close(); };
        btnInfo.Click += (_, _) => { if (summary != null) ShowPackageSummary(summary); };
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
        if (summary != null)
        {
            actions.Controls.Add(btnInfo, 1, 0);
            actions.Controls.Add(btnOk, 2, 0);
        }
        else
        {
            actions.Controls.Add(btnOk, 1, 0);
        }
        root.Controls.Add(lbl, 0, 0);
        root.Controls.Add(txt, 0, 1);
        root.Controls.Add(new Panel { Dock = DockStyle.Fill, BackColor = Theme.Bg }, 0, 2);
        root.Controls.Add(actions, 0, 3);
        dlg.Controls.Add(root);

        return dlg.ShowDialog() == DialogResult.OK ? txt.Text : null;
    }

    private static void RunEmbeddedSfxExtractor(string hostExePath, EmbeddedSfxInfo sfx)
    {
        string tempRoot = Path.Combine(Path.GetTempPath(), $"obsq_sfx_run_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempRoot);
        string pkgPath = Path.Combine(tempRoot, "package.zip");
        string cliPath = Path.Combine(tempRoot, "obsidianq.exe");

        try
        {
            CopyRangeToFile(hostExePath, sfx.PackageOffset, sfx.PackageLength, pkgPath);
            CopyRangeToFile(hostExePath, sfx.CliOffset, sfx.CliLength, cliPath);
            RunPackageExtractor(hostExePath, cliPath, pkgPath);
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

    private static void RunPackageExtractor(string hostExePath, string cliPath, string pkgPath)
    {
        string tempRoot = Path.Combine(Path.GetTempPath(), $"obsq_extract_run_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempRoot);
        string probeOutDir = Path.Combine(tempRoot, "probe_out");

        try
        {
            PackageSummary summary = InspectPackageSummary(cliPath, pkgPath);
            string? password = PromptForPassword(summary);
            if (password == null) return;

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
            if (proc == null) throw new InvalidOperationException("Failed to start delivery extractor.");

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
            string packageStem = string.IsNullOrWhiteSpace(summary.PackageName)
                ? Path.GetFileNameWithoutExtension(hostExePath)
                : summary.PackageName.Trim();
            string defaultOutDir = Path.Combine(baseDir, $"{packageStem}_Extracted");

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
        finally
        {
            try { Directory.Delete(tempRoot, recursive: true); } catch { }
        }
    }

    private static JsonElement RunDeliveryJson(string cliPath, string pkgPath, string subcommand)
    {
        var psi = new ProcessStartInfo
        {
            FileName = cliPath,
            Arguments = $"delivery {subcommand} \"{pkgPath}\" --json",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        using var proc = Process.Start(psi) ?? throw new InvalidOperationException($"Failed to start delivery {subcommand}.");
        string stdout = proc.StandardOutput.ReadToEnd();
        string stderr = proc.StandardError.ReadToEnd();
        proc.WaitForExit();
        if (proc.ExitCode != 0)
        {
            string detail = string.IsNullOrWhiteSpace(stderr) ? stdout.Trim() : stderr.Trim();
            throw new InvalidOperationException(string.IsNullOrWhiteSpace(detail) ? $"delivery {subcommand} failed." : detail);
        }
        using var doc = JsonDocument.Parse(stdout);
        return doc.RootElement.Clone();
    }

    private static PackageSummary InspectPackageSummary(string cliPath, string pkgPath)
    {
        JsonElement inspect = RunDeliveryJson(cliPath, pkgPath, "inspect");
        _ = RunDeliveryJson(cliPath, pkgPath, "verify");
        JsonElement data = inspect.GetProperty("data");

        string packageId = data.TryGetProperty("package_uuid", out var packageIdEl) && !string.IsNullOrWhiteSpace(packageIdEl.GetString())
            ? packageIdEl.GetString()!
            : "-";
        string packageName = data.TryGetProperty("package_name", out var packageNameEl) && !string.IsNullOrWhiteSpace(packageNameEl.GetString())
            ? packageNameEl.GetString()!
            : Path.GetFileNameWithoutExtension(pkgPath);
        string sender = data.TryGetProperty("sender_name", out var senderEl) && !string.IsNullOrWhiteSpace(senderEl.GetString())
            ? senderEl.GetString()!
            : "Unknown Sender";
        string created = data.TryGetProperty("created_utc", out var createdEl)
            ? FormatUtcForDisplay(createdEl.GetString() ?? string.Empty)
            : "-";
        string appVersion = data.TryGetProperty("obsidianq_version", out var appVersionEl) && !string.IsNullOrWhiteSpace(appVersionEl.GetString())
            ? appVersionEl.GetString()!
            : "-";
        string recipientMode = data.TryGetProperty("recipient_mode", out var recipientModeEl) && !string.IsNullOrWhiteSpace(recipientModeEl.GetString())
            ? recipientModeEl.GetString()!
            : "-";
        bool signed = data.TryGetProperty("signed", out var signedEl) && signedEl.ValueKind == JsonValueKind.True;
        bool senderIdentityPresent = data.TryGetProperty("sender_fingerprint", out var fpEl) && !string.IsNullOrWhiteSpace(fpEl.GetString());
        var files = new List<string>();
        if (data.TryGetProperty("files", out var filesEl) && filesEl.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement file in filesEl.EnumerateArray())
            {
                if (file.TryGetProperty("path", out var pathEl) && !string.IsNullOrWhiteSpace(pathEl.GetString()))
                    files.Add(pathEl.GetString()!);
            }
        }
        return new PackageSummary(packageId, packageName, sender, created, appVersion, recipientMode, files, signed, senderIdentityPresent);
    }

    private static string FormatUtcForDisplay(string raw)
    {
        string trimmed = raw.Trim();
        if (trimmed.Length == 0) return "-";
        return trimmed.Replace("T", " ").Replace("+00:00", " UTC").Replace("Z", " UTC");
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
}

static class Theme
{
    public static readonly Color Bg        = Color.FromArgb(0xFF, 0x05, 0x08, 0x07);
    public static readonly Color Surface   = Color.FromArgb(0xFF, 0x0B, 0x12, 0x0F);
    public static readonly Color Border    = Color.FromArgb(0xFF, 0x00, 0x55, 0x30);
    public static readonly Color Accent    = Color.FromArgb(0xFF, 0x00, 0xFF, 0x7A);
    public static readonly Color AccentHot = Color.FromArgb(0xFF, 0x00, 0xFF, 0x9A);
    public static readonly Color AccentDim = Color.FromArgb(0xFF, 0x00, 0xAA, 0x50);
    public static readonly Color TextMain  = Color.FromArgb(0xFF, 0xCC, 0xFF, 0xDD);
    public static readonly Color TextDim   = Color.FromArgb(0xFF, 0x44, 0x77, 0x55);

    public static Font SafeMono(float size)
    {
        foreach (string name in new[] { "Cascadia Mono", "Cascadia Code", "Consolas", "Courier New" })
            if (FontFamily.Families.Any(f => f.Name == name))
                return new Font(name, size, FontStyle.Regular, GraphicsUnit.Point);
        return new Font(FontFamily.GenericMonospace, size, FontStyle.Regular, GraphicsUnit.Point);
    }
}

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
            TextFormatFlags.HorizontalCenter |
            TextFormatFlags.VerticalCenter |
            TextFormatFlags.EndEllipsis |
            TextFormatFlags.NoPrefix);
    }
}

class ThemedSummaryView : Control
{
    private List<string> _lines = new();
    private int _scrollLine;
    private const int PaddingSize = 8;
    private const int ScrollbarWidth = 10;

    public string SummaryText
    {
        get => string.Join(Environment.NewLine, _lines);
        set
        {
            _lines = value.Replace("\r\n", "\n").Split('\n').ToList();
            _scrollLine = 0;
            Invalidate();
        }
    }

    public ThemedSummaryView()
    {
        BackColor = Theme.Surface;
        ForeColor = Theme.TextMain;
        Font = Theme.SafeMono(8.25f);
        TabStop = true;
        SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
    }

    protected override void OnMouseWheel(MouseEventArgs e)
    {
        ScrollBy(e.Delta > 0 ? -3 : 3);
        base.OnMouseWheel(e);
    }

    protected override void OnMouseDown(MouseEventArgs e)
    {
        Focus();
        if (TryHandleScrollbarClick(e.Location))
            return;
        base.OnMouseDown(e);
    }

    protected override bool IsInputKey(Keys keyData)
    {
        return keyData is Keys.Up or Keys.Down or Keys.PageUp or Keys.PageDown or Keys.Home or Keys.End || base.IsInputKey(keyData);
    }

    protected override void OnKeyDown(KeyEventArgs e)
    {
        switch (e.KeyCode)
        {
            case Keys.Up:
                ScrollBy(-1);
                e.Handled = true;
                break;
            case Keys.Down:
                ScrollBy(1);
                e.Handled = true;
                break;
            case Keys.PageUp:
                ScrollBy(-VisibleLineCount());
                e.Handled = true;
                break;
            case Keys.PageDown:
                ScrollBy(VisibleLineCount());
                e.Handled = true;
                break;
            case Keys.Home:
                _scrollLine = 0;
                Invalidate();
                e.Handled = true;
                break;
            case Keys.End:
                _scrollLine = MaxScrollLine();
                Invalidate();
                e.Handled = true;
                break;
        }
        base.OnKeyDown(e);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.Clear(Theme.Bg);

        Rectangle outer = ClientRectangle;
        if (outer.Width <= 2 || outer.Height <= 2)
            return;

        Rectangle panel = new Rectangle(outer.X, outer.Y, outer.Width - 1, outer.Height - 1);
        using (var fill = new SolidBrush(Theme.Surface))
            g.FillRectangle(fill, panel);
        using (var pen = new Pen(Theme.AccentDim, 1f) { Alignment = System.Drawing.Drawing2D.PenAlignment.Inset })
            g.DrawRectangle(pen, panel);

        Rectangle content = Rectangle.Inflate(panel, -PaddingSize, -PaddingSize);
        bool overflow = MaxScrollLine() > 0;
        Rectangle textRect = content;
        Rectangle trackRect = Rectangle.Empty;

        if (overflow)
        {
            trackRect = new Rectangle(content.Right - ScrollbarWidth, content.Top, ScrollbarWidth, content.Height);
            textRect.Width -= ScrollbarWidth + 6;
        }

        TextRenderer.DrawText(
            g,
            VisibleText(),
            Font,
            textRect,
            Theme.TextMain,
            TextFormatFlags.Left | TextFormatFlags.Top | TextFormatFlags.NoPrefix | TextFormatFlags.NoPadding);

        if (overflow)
            DrawScrollbar(g, trackRect);
    }

    private int VisibleLineCount()
    {
        int lineHeight = TextRenderer.MeasureText("Ag", Font, new Size(int.MaxValue, int.MaxValue), TextFormatFlags.NoPadding).Height + 1;
        int available = Math.Max(1, Height - (PaddingSize * 2));
        return Math.Max(1, available / Math.Max(1, lineHeight));
    }

    private int MaxScrollLine() => Math.Max(0, _lines.Count - VisibleLineCount());

    private string VisibleText()
    {
        int visible = VisibleLineCount();
        _scrollLine = Math.Clamp(_scrollLine, 0, MaxScrollLine());
        return string.Join(Environment.NewLine, _lines.Skip(_scrollLine).Take(visible));
    }

    private void ScrollBy(int delta)
    {
        int next = Math.Clamp(_scrollLine + delta, 0, MaxScrollLine());
        if (next == _scrollLine)
            return;
        _scrollLine = next;
        Invalidate();
    }

    private bool TryHandleScrollbarClick(Point location)
    {
        if (MaxScrollLine() <= 0)
            return false;

        Rectangle content = Rectangle.Inflate(ClientRectangle, -PaddingSize, -PaddingSize);
        Rectangle trackRect = new Rectangle(content.Right - ScrollbarWidth, content.Top, ScrollbarWidth, content.Height);
        if (!trackRect.Contains(location))
            return false;

        Rectangle thumb = ThumbRect(trackRect);
        if (location.Y < thumb.Top)
            ScrollBy(-VisibleLineCount());
        else if (location.Y > thumb.Bottom)
            ScrollBy(VisibleLineCount());
        else
        {
            float ratio = (float)(location.Y - trackRect.Top) / Math.Max(1, trackRect.Height);
            _scrollLine = Math.Clamp((int)Math.Round(ratio * MaxScrollLine()), 0, MaxScrollLine());
            Invalidate();
        }
        return true;
    }

    private Rectangle ThumbRect(Rectangle trackRect)
    {
        int visible = VisibleLineCount();
        int total = Math.Max(visible, _lines.Count);
        int thumbHeight = Math.Max(28, (int)Math.Round(trackRect.Height * (visible / (float)total)));
        int maxTravel = Math.Max(1, trackRect.Height - thumbHeight);
        int top = trackRect.Top + (int)Math.Round(maxTravel * (_scrollLine / (float)Math.Max(1, MaxScrollLine())));
        return new Rectangle(trackRect.X, top, trackRect.Width, thumbHeight);
    }

    private void DrawScrollbar(Graphics g, Rectangle trackRect)
    {
        using var trackBrush = new SolidBrush(Theme.Bg);
        using var thumbBrush = new SolidBrush(Theme.Accent);
        using var borderPen = new Pen(Theme.AccentDim, 1f) { Alignment = System.Drawing.Drawing2D.PenAlignment.Inset };
        g.FillRectangle(trackBrush, trackRect);
        g.DrawRectangle(borderPen, trackRect.X, trackRect.Y, trackRect.Width - 1, trackRect.Height - 1);
        Rectangle thumb = ThumbRect(trackRect);
        g.FillRectangle(thumbBrush, thumb);
        using var thumbPen = new Pen(Theme.AccentHot, 1f) { Alignment = System.Drawing.Drawing2D.PenAlignment.Inset };
        g.DrawRectangle(thumbPen, thumb.X, thumb.Y, thumb.Width - 1, thumb.Height - 1);
    }
}
