using System.Diagnostics;
using System.Text;

[assembly: System.Runtime.Versioning.SupportedOSPlatform("windows")]

namespace ObsidianQ.Extractor;

static class Program
{
    private const string EmbeddedSfxMagic = "OBSQSFX1";
    private const int EmbeddedSfxTrailerSize = 24; // zipLen(8) + cliLen(8) + magic(8)

    private sealed record EmbeddedSfxInfo(long PackageOffset, long PackageLength, long CliOffset, long CliLength);

    [STAThread]
    static void Main()
    {
        Application.SetHighDpiMode(HighDpiMode.SystemAware);
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);

        string hostExePath = Environment.ProcessPath ?? Application.ExecutablePath;
        if (!TryGetEmbeddedSfxInfo(hostExePath, out var sfxInfo))
        {
            MessageBox.Show(
                "This executable does not contain an embedded package payload.",
                "ObsidianQ Extractor",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
            Environment.Exit(2);
            return;
        }

        RunEmbeddedSfxExtractor(hostExePath, sfxInfo);
        Environment.Exit(0);
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
            Font = Theme.SafeMono(9f),
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
}

static class Theme
{
    public static readonly Color Bg        = Color.FromArgb(0xFF, 0x05, 0x08, 0x07);
    public static readonly Color Surface   = Color.FromArgb(0xFF, 0x0B, 0x12, 0x0F);
    public static readonly Color Border    = Color.FromArgb(0xFF, 0x00, 0x55, 0x30);
    public static readonly Color Accent    = Color.FromArgb(0xFF, 0x00, 0xFF, 0x7A);
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
