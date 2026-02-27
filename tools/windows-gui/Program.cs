// ObsidianQ Launcher --- WinForms .NET 8 GUI wrapper
// Calls obsidianq.exe via stdin for password; never passes secrets via CLI args.
// Cyberpunk aesthetic: #050807 bg, #00FF7A neon green accent, monospace console.

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;

[assembly: System.Runtime.Versioning.SupportedOSPlatform("windows")]

namespace ObsidianQ.Launcher;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------
static class Program
{
    [STAThread]
    static void Main(string[] args)
    {
        Application.SetHighDpiMode(HighDpiMode.SystemAware);
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);

        // If launched from context menu, the first arg is the file path.
        string? preloadPath = args.Length > 0 && File.Exists(args[0]) ? args[0] : null;
        Application.Run(new MainForm(preloadPath));
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

        // Background
        using var bgBrush = new SolidBrush(_hovered ? Theme.Surface : Theme.Bg);
        g.FillRectangle(bgBrush, rc);

        // Border
        using var pen = new Pen(_hovered ? Theme.Accent : Theme.AccentDim, 1f) { Alignment = System.Drawing.Drawing2D.PenAlignment.Inset };
        g.DrawRectangle(pen, rc.X, rc.Y, rc.Width - 1, rc.Height - 1);

        // Subtle glow when hovered
        if (_hovered)
        {
            using var glowPen = new Pen(Color.FromArgb(40, Theme.Accent), 3f);
            g.DrawRectangle(glowPen, rc.X + 1, rc.Y + 1, rc.Width - 3, rc.Height - 3);
        }

        // Text
        using var sf = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center };
        using var brush = new SolidBrush(Enabled ? (_hovered ? Theme.Accent : Theme.AccentDim) : Theme.TextDim);
        g.DrawString(Text, Font, brush, new RectangleF(rc.X, rc.Y, rc.Width, rc.Height), sf);
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

    private static readonly string[] Labels = ["PASSWORD", "PQC"];

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
        if (clicked != Selected) { Selected = clicked; Invalidate(); SelectionChanged?.Invoke(this, EventArgs.Empty); }
        base.OnMouseClick(e);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.None;
        int half = Width / 2;
        int[] xs = [0, half];
        int[] ws = [half, Width - half];

        for (int i = 0; i < 2; i++)
        {
            bool active = (Segment)i == Selected;
            var rc = new Rectangle(xs[i], 0, ws[i], Height - 1);

            using var bg = new SolidBrush(active ? Color.FromArgb(30, Theme.Accent) : Theme.Bg);
            g.FillRectangle(bg, rc);

            using var border = new Pen(active ? Theme.Accent : Theme.Border, 1f);
            g.DrawRectangle(border, rc);

            using var sf = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center };
            using var textBrush = new SolidBrush(active ? Theme.Accent : Theme.TextDim);
            g.DrawString(Labels[i], Font, textBrush, new RectangleF(rc.X, rc.Y, rc.Width, rc.Height), sf);
        }
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
// Drop zone panel --- prominent file-drop target with click-to-browse
// ---------------------------------------------------------------------------
class DropZonePanel : Panel
{
    private bool _hovering;
    private bool _dragging;
    private string? _filePath;

    public string? FilePath => _filePath;
    public event EventHandler<string>? FileDropped;

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
            using var dlg = new OpenFileDialog
            { Title = "Select input file", Filter = "ObsidianQ containers|*.obsq|All files|*.*" };
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

    protected override void OnPaint(PaintEventArgs e)
    {
        var g  = e.Graphics;
        g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.None;
        var rc = ClientRectangle;
        if (rc.Width <= 1 || rc.Height <= 1) return;

        // Background
        using var bgBrush = new SolidBrush(_dragging ? Color.FromArgb(18, Theme.Accent) : Theme.Surface);
        g.FillRectangle(bgBrush, rc);

        // Border --- accent on drag-over, dim accent on hover, border otherwise
        var borderColor = _dragging ? Theme.Accent : (_hovering ? Theme.AccentDim : Theme.Border);
        using var borderPen = new Pen(borderColor, _dragging ? 2f : 1f) { Alignment = System.Drawing.Drawing2D.PenAlignment.Inset };
        g.DrawRectangle(borderPen, rc.X, rc.Y, rc.Width - 1, rc.Height - 1);

        // Bottom accent underline on drag-over
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
// Main Form
// ---------------------------------------------------------------------------
class MainForm : Form
{
    // Controls
    private readonly SegmentedToggle _toggle;
    private readonly NeonButton _btnRun, _btnCopyLog, _btnMount, _lnkChangeOut;
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
    private readonly NeonButton _btnAdvanced;
    private bool _advancedExpanded;
    private readonly ShimmerStrip _shimmer;
    private readonly TableLayoutPanel _pwPanel, _pqcPanel;

    // State
    private CancellationTokenSource? _cts;
    private bool _busy;

    // Resolved obsidianq.exe path
    private static readonly string ExePath = ResolveExePath();
    private static readonly string LocalKeysDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "ObsidianQ",
        "keys");
    private static readonly string BundleKeysDir = Path.Combine(AppContext.BaseDirectory, "keys");
    private static readonly string[] DefaultPubKeyNames = ["obsidianq_test_pub.bin", "obsidianq_test_pub.pem", "obsidianq_pub.bin", "obsidianq_pub.pem"];
    private static readonly string[] DefaultPrivKeyNames = ["obsidianq_test_priv.bin", "obsidianq_test_priv.pem", "obsidianq_priv.bin", "obsidianq_priv.pem"];

    public MainForm(string? preloadPath)
    {
        Text = "ObsidianQ - Post-Quantum Encryption";
        Size = new Size(800, 680);
        MinimumSize = new Size(680, 580);
        BackColor = Theme.Bg;
        ForeColor = Theme.TextMain;
        FormBorderStyle = FormBorderStyle.Sizable;
        StartPosition = FormStartPosition.CenterScreen;
        Font = Theme.SafeMono(9f);

        // ------ Shimmer strip (top 3 px) ------------------------------------------------------------------------------------------------------------------
        _shimmer = new ShimmerStrip { Dock = DockStyle.Top };
        Controls.Add(_shimmer);

        // ------ Main layout container ---------------------------------------------------------------------------------------------------------------------------
        var outer = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 9,
            Padding = new Padding(16),
            BackColor = Theme.Bg,
        };
        outer.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));  // row 0: header label
        outer.RowStyles.Add(new RowStyle(SizeType.Absolute, 38));  // row 1: toggle
        outer.RowStyles.Add(new RowStyle(SizeType.Absolute, 68));  // row 2: drop zone
        outer.RowStyles.Add(new RowStyle(SizeType.Absolute, 26));  // row 3: output path
        outer.RowStyles.Add(new RowStyle(SizeType.Absolute, 44));  // row 4: mode panel
        outer.RowStyles.Add(new RowStyle(SizeType.Absolute, 22));  // row 5: advanced toggle
        outer.RowStyles.Add(new RowStyle(SizeType.Absolute, 0));   // row 6: options (collapsed)
        outer.RowStyles.Add(new RowStyle(SizeType.Percent, 100));  // row 7: log
        outer.RowStyles.Add(new RowStyle(SizeType.Absolute, 38));  // row 8: status + buttons
        Controls.Add(outer);

        // ------ Header label ---------------------------------------------------------------------------------------------------------------------------------------------------
        var header = MakeLabel("[ OBSIDIANQ // POST-QUANTUM FILE ENCRYPTION ]", 11f, bold: true);
        header.ForeColor = Theme.Accent;
        header.TextAlign = ContentAlignment.MiddleCenter;
        header.Dock = DockStyle.Fill;
        outer.Controls.Add(header, 0, 0);

        // ------ Toggle ------------------------------------------------------------------------------------------------------------------------------------------------------------------------
        _toggle = new SegmentedToggle { Dock = DockStyle.Fill };
        _toggle.SelectionChanged += OnToggleChanged;
        outer.Controls.Add(_toggle, 0, 1);

        // ------ Drop zone (row 2) ------------------------------------------------------------------------------------------------------------------------------------
        _dropZone = new DropZonePanel { Dock = DockStyle.Fill, Margin = new Padding(0, 2, 0, 2) };
        _dropZone.FileDropped += OnFileDropped;
        outer.Controls.Add(_dropZone, 0, 2);

        // ------ Output path row (row 3) ------------------------------------------------------------------------------------------------------------------
        var outRow = new TableLayoutPanel
        {
            Dock = DockStyle.Top, ColumnCount = 3, RowCount = 1,
            BackColor = Theme.Bg, Margin = new Padding(0),
        };
        outRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 36));  // "OUT:" label
        outRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));  // derived path
        outRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 84));  // [Change...]
        outRow.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        var lblOutPrefix = MakeLabel("OUT:", 8f);
        lblOutPrefix.Dock = DockStyle.Fill;
        lblOutPrefix.TextAlign = ContentAlignment.MiddleLeft;

        _lblOutPath = MakeLabel("-", 8f);
        _lblOutPath.Dock = DockStyle.Fill;
        _lblOutPath.TextAlign = ContentAlignment.MiddleLeft;
        _lblOutPath.ForeColor = Theme.AccentDim;

        _lnkChangeOut = new NeonButton { Text = "Change...", Dock = DockStyle.Fill, Margin = new Padding(4,2,0,2) };
        _lnkChangeOut.Click += ChangeOut_Click;

        outRow.Controls.Add(lblOutPrefix, 0, 0);
        outRow.Controls.Add(_lblOutPath,  1, 0);
        outRow.Controls.Add(_lnkChangeOut, 2, 0);
        outer.Controls.Add(outRow, 0, 3);

        // ------ Password panel ---------------------------------------------------------------------------------------------------------------------------------------------
        _pwPanel = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1,
            BackColor = Theme.Bg, Margin = new Padding(0),
        };
        _pwPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        _pwPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        _pwPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 50));
        _pwPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 50));

        _txtPassword = MakeTextBox(password: true); _txtPassword.PlaceholderText = "Password...";
        _txtConfirm  = MakeTextBox(password: true); _txtConfirm.PlaceholderText  = "Confirm password...";
        _pwPanel.Controls.Add(MakeLabeled("PASSWORD", _txtPassword), 0, 0);
        _pwPanel.Controls.Add(MakeLabeled("CONFIRM",  _txtConfirm),  1, 0);

        // ------ PQC panel ------------------------------------------------------------------------------------------------------------------------------------------------------------       
        _pqcPanel = new TableLayoutPanel
        {
            Dock = DockStyle.Top, ColumnCount = 3, RowCount = 1,
            BackColor = Theme.Bg, Margin = new Padding(0), Visible = false,
        };
        int pqcBrowseWidth = Math.Max(86, TextRenderer.MeasureText("BROWSE", Theme.SafeMono(9f)).Width + 16);
        int pqcKeygenWidth = Math.Max(132, TextRenderer.MeasureText("GENERATE KEY", Theme.SafeMono(9f)).Width + 20);
        _pqcPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        _pqcPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, pqcBrowseWidth));
        _pqcPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, pqcKeygenWidth));
        _pqcPanel.RowStyles.Clear();
        _pqcPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 26));
        _pqcPanel.Height = 26;
        _pqcPanel.MinimumSize = new Size(0, 26);
        _pqcPanel.MaximumSize = new Size(int.MaxValue, 26);

        _txtPrivkey = MakeTextBox(); _txtPrivkey.PlaceholderText = "Path to .bin key file (or .pem)";
        _btnBrowsePrivkey = new NeonButton { Text = "BROWSE", Dock = DockStyle.Fill, Margin = new Padding(3,2,0,2) };
        _btnBrowsePrivkey.Click += BrowsePrivkey_Click;
        _btnGenerateKeypair = new NeonButton { Text = "GENERATE KEY", Dock = DockStyle.Fill, Margin = new Padding(3,2,0,2) };
        _btnGenerateKeypair.Click += BtnGenerateKeypair_Click;
        _pqcPanel.Controls.Add(_txtPrivkey,        0, 0);
        _pqcPanel.Controls.Add(_btnBrowsePrivkey,  1, 0);
        _pqcPanel.Controls.Add(_btnGenerateKeypair,2, 0);
        // Stack both panels in a container
        var modeContainer = new Panel { Dock = DockStyle.Fill };
        _pwPanel.Dock = DockStyle.Fill;
        _pqcPanel.Dock = DockStyle.Top;
        modeContainer.Controls.Add(_pwPanel);
        modeContainer.Controls.Add(_pqcPanel);
        outer.Controls.Add(modeContainer, 0, 4);

        // ------ Advanced toggle (row 5) ------------------------------------------------------------------------------------------------------------------
        _btnAdvanced = new NeonButton
        {
            Text = "ADVANCED [>]", Dock = DockStyle.Fill,
            Margin = new Padding(0), Font = Theme.SafeMono(7.5f),
        };
        _btnAdvanced.Click += (_, _) =>
        {
            _advancedExpanded = !_advancedExpanded;
            outer.RowStyles[6] = new RowStyle(SizeType.Absolute, _advancedExpanded ? 44 : 0);
            _btnAdvanced.Text   = _advancedExpanded ? "ADVANCED [v]" : "ADVANCED [>]";
        };
        outer.Controls.Add(_btnAdvanced, 0, 5);

        // ------ Options row (row 6, hidden until Advanced is clicked) ------------------------
        var optRow = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill, FlowDirection = FlowDirection.LeftToRight,
            BackColor = Theme.Bg, WrapContents = false,
        };
        _chkCompress = new CheckBox
        {
            Text = "COMPRESS (zstd)", ForeColor = Theme.TextDim, BackColor = Theme.Bg,
            Checked = false, AutoSize = true, Margin = new Padding(0,8,16,0),
        };
        _cmbSuite = new ComboBox
        {
            DropDownStyle = ComboBoxStyle.DropDownList,
            BackColor = Theme.Surface, ForeColor = Theme.Accent,
            FlatStyle = FlatStyle.Flat, Width = 200, Margin = new Padding(0,6,0,0),
        };
        _cmbSuite.Items.AddRange(["xchacha20 (default)", "aesgcm"]);
        _cmbSuite.SelectedIndex = 0;
        optRow.Controls.Add(MakeLabel("SUITE:", 8.5f));
        optRow.Controls.Add(_cmbSuite);
        optRow.Controls.Add(_chkCompress);
        outer.Controls.Add(optRow, 0, 6);

        // ------ Log console ------------------------------------------------------------------------------------------------------------------------------------------------------
        var logContainer = new Panel { Dock = DockStyle.Fill, BackColor = Theme.LogBg };
        _rtbLog = new RichTextBox
        {
            Dock = DockStyle.Fill, ReadOnly = true, WordWrap = false,
            BackColor = Theme.LogBg, ForeColor = Theme.Accent,
            BorderStyle = BorderStyle.None, ScrollBars = RichTextBoxScrollBars.Both,
            Font = Theme.SafeMono(8.5f),
        };
        logContainer.Controls.Add(_rtbLog);

        // Neon border around log
        logContainer.Paint += (_, pe) =>
        {
            using var pen = new Pen(Theme.Border, 1f);
            pe.Graphics.DrawRectangle(pen, 0, 0, logContainer.Width - 1, logContainer.Height - 1);
        };

        outer.Controls.Add(logContainer, 0, 7);

        // ------ Status bar + action buttons ------------------------------------------------------------------------------------------------------
        var bar = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, ColumnCount = 4, RowCount = 1,
            BackColor = Theme.Bg, Margin = new Padding(0),
        };
        bar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));  // status label
        bar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 98));  // mount
        bar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 94));  // copy log
        bar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 90));  // run

        _lblStatus = MakeLabel("READY", 8.5f);
        _lblStatus.Dock = DockStyle.Fill;
        _lblStatus.TextAlign = ContentAlignment.MiddleLeft;

        _btnCopyLog = new NeonButton { Text = "COPY LOG", Dock = DockStyle.Fill, Margin = new Padding(3,2,0,2) };
        _btnCopyLog.Click += (_, _) => { Clipboard.SetText(_rtbLog.Text); };

        _btnRun = new NeonButton { Text = "RUN", Dock = DockStyle.Fill, Margin = new Padding(3,2,0,2) };
        _btnRun.Font = Theme.SafeMono(10f);
        _btnRun.ForeColor = Theme.Accent;
        _btnRun.Click += BtnRun_Click;

        _btnMount = new NeonButton { Text = "MOUNT", Dock = DockStyle.Fill, Margin = new Padding(3,2,0,2) };
        _btnMount.Click += BtnMount_Click;

        bar.Controls.Add(_lblStatus,  0, 0);
        bar.Controls.Add(_btnMount,   1, 0);
        bar.Controls.Add(_btnCopyLog, 2, 0);
        bar.Controls.Add(_btnRun,     3, 0);
        outer.Controls.Add(bar, 0, 8);

        // ------ Form-level drag-and-drop (delegates to drop zone) ------------------------------------
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

        // ------ Window icon (extracted from exe's embedded application icon) ------
        try
        {
            var exeIcon = Icon.ExtractAssociatedIcon(Environment.ProcessPath ?? Application.ExecutablePath);
            if (exeIcon != null) Icon = exeIcon;
        }
        catch { /* ignore in dev/test scenarios where icon isn't embedded */ }

        // ------ Preload path from context-menu ------------------------------------------------------------------------------------------------
        if (preloadPath != null)
            AutoPopulate(preloadPath);
        else
            TryAutoLoadDefaultKeyPath(force: false);

        // ------ Neon border on form ---------------------------------------------------------------------------------------------------------------------------------
        Paint += FormPaint;

        // ------ Startup: warn immediately if obsidianq.exe is missing ---------------------------
        // Show after the form is first painted so the window is visible first.
        if (!File.Exists(ExePath))
        {
            Load += (_, _) => WarnMissingCli();
        }
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

    private void FormPaint(object? sender, PaintEventArgs e)
    {
        using var pen = new Pen(Theme.Border, 1f);
        e.Graphics.DrawRectangle(pen, 0, 0, Width - 1, Height - 1);
    }

    // -----------------------------------------------------------------------
    // Toggle logic
    // -----------------------------------------------------------------------
    private void OnToggleChanged(object? sender, EventArgs e)
    {
        bool isPqc = _toggle.Selected == SegmentedToggle.Segment.Pqc;
        _pwPanel.Visible  = !isPqc;
        _pqcPanel.Visible =  isPqc;

        // Keep mode row compact per selected mode.
        if (_btnAdvanced.Parent is TableLayoutPanel outer)
            outer.RowStyles[4] = new RowStyle(SizeType.Absolute, isPqc ? 26 : 44);

        UpdateKeyPlaceholder();
        if (isPqc)
            TryAutoLoadDefaultKeyPath(force: false);
    }

    // -----------------------------------------------------------------------
    // Drop zone / output path handlers
    // -----------------------------------------------------------------------
    private void OnFileDropped(object? sender, string path)
    {
        // Auto-derive the output path from the input.
        _lblOutPath.Text = path.EndsWith(".obsq", StringComparison.OrdinalIgnoreCase)
            ? Path.Combine(Path.GetDirectoryName(path)!, Path.GetFileNameWithoutExtension(path))
            : path + ".obsq";
        _lblOutPath.ForeColor = Theme.AccentDim;

        UpdateKeyPlaceholder();
        TryAutoLoadDefaultKeyPath(force: true);
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
            Title = "Select key file",
            Filter = "Key files|*.bin;*.pem|BIN files|*.bin|PEM files|*.pem|All files|*.*"
        };
        if (dlg.ShowDialog() == DialogResult.OK) _txtPrivkey.Text = dlg.FileName;
    }

    private async void BtnGenerateKeypair_Click(object? sender, EventArgs e)
    {
        if (!File.Exists(ExePath))
        {
            StatusError($"obsidianq.exe not found at:\n{ExePath}");
            return;
        }

        string keysDir = EnsureDefaultKeyDir();
        string pubPath = Path.Combine(keysDir, "obsidianq_test_pub.bin");
        string privPath = Path.Combine(keysDir, "obsidianq_test_priv.bin");

        try
        {
            _btnGenerateKeypair.Enabled = false;
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

            if (!string.IsNullOrWhiteSpace(stdout)) Log(stdout.TrimEnd(), Theme.Accent);
            if (!string.IsNullOrWhiteSpace(stderr)) Log(stderr.TrimEnd(), Theme.Error);

            if (proc.ExitCode != 0)
            {
                StatusError($"Key generation failed (exit code {proc.ExitCode}).");
                return;
            }

            _txtPrivkey.Text = SelectDefaultKeyPathForCurrentOperation(pubPath, privPath);
            StatusOk($"Generated keypair in {keysDir}");
        }
        catch (Exception ex)
        {
            StatusError($"Key generation failed: {ex.Message}");
        }
        finally
        {
            _btnGenerateKeypair.Enabled = true;
        }
    }

    // Auto-detect mode from file extension and populate drop zone.
    // OnFileDropped handles output path derivation via the FileDropped event.
    private void AutoPopulate(string path)
    {
        _dropZone.SetFile(path);
        UpdateKeyPlaceholder();
        TryAutoLoadDefaultKeyPath(force: true);
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
    private void TryAutoLoadDefaultKeyPath(bool force)
    {
        if (_toggle.Selected != SegmentedToggle.Segment.Pqc)
            return;
        if (!force && !string.IsNullOrWhiteSpace(_txtPrivkey.Text) && File.Exists(_txtPrivkey.Text))
            return;
        string[] names = IsEncryptMode() ? DefaultPubKeyNames : DefaultPrivKeyNames;
        foreach (string dir in new[] { BundleKeysDir, LocalKeysDir })
        {
            foreach (string name in names)
            {
                string candidate = Path.Combine(dir, name);
                if (File.Exists(candidate))
                {
                    _txtPrivkey.Text = candidate;
                    return;
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // WinFSP detection and on-demand install
    // -----------------------------------------------------------------------
    private static bool IsWinFspInstalled()
    {
        // Primary: registry key written by the WinFSP installer.
        using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\WinFsp");
        if (key != null) return true;

        // Fallback: DLL on disk at the default install locations.
        return File.Exists(@"C:\Program Files (x86)\WinFsp\bin\winfsp-x64.dll")
            || File.Exists(@"C:\Program Files\WinFsp\bin\winfsp-x64.dll");
    }

    private static string? FindWinFspInstaller()
    {
        // Look for winfsp-*.msi next to the launcher exe (placed there by build_bundle.ps1).
        return Directory.EnumerateFiles(AppContext.BaseDirectory, "winfsp-*.msi")
                        .OrderByDescending(f => f)
                        .FirstOrDefault();
    }

    private async Task<bool> TryInstallWinFspAsync()
    {
        string? msi = FindWinFspInstaller();
        if (msi == null)
        {
            StatusError("WinFSP installer not found next to ObsidianQ.Launcher.exe.");
            Log("[INFO] Download WinFSP from: https://github.com/winfsp/winfsp/releases", Theme.TextDim);
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

        Log($"[INSTALL] Installing {Path.GetFileName(msi)} silently ...", Theme.TextDim);
        _btnMount.Enabled = false;
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName        = "msiexec.exe",
                Arguments       = $"/i \"{msi}\" /quiet /norestart",
                UseShellExecute = true,  // required for UAC elevation via Verb
                Verb            = "runas",
            };
            using var proc = Process.Start(psi)!;
            await proc.WaitForExitAsync();

            if (proc.ExitCode == 0)
            {
                Log("[OK] WinFSP installed successfully.", Theme.Accent);
                return true;
            }
            else
            {
                StatusError($"WinFSP installer returned exit code {proc.ExitCode}.");
                return false;
            }
        }
        catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            // ERROR_CANCELLED --- user clicked No on the UAC prompt.
            Log("[CANCELLED] Administrator permission was denied.", Theme.Error);
            return false;
        }
        catch (Exception ex)
        {
            StatusError($"Failed to launch installer: {ex.Message}");
            return false;
        }
        finally
        {
            _btnMount.Enabled = true;
        }
    }

    // -----------------------------------------------------------------------
    // MOUNT AS DRIVE
    // -----------------------------------------------------------------------
    private async void BtnMount_Click(object? sender, EventArgs e)
    {
        if (_dropZone.FilePath == null || !File.Exists(_dropZone.FilePath))
        { StatusError("Drop or browse a .obsq file first."); return; }

        // ------ Ensure WinFSP runtime is installed ------------------------------------------------------------------------------------
        if (!IsWinFspInstalled())
        {
            if (!await TryInstallWinFspAsync()) return;
            if (!IsWinFspInstalled())
            {
                StatusError("WinFSP install could not be verified. A reboot may be required.");
                return;
            }
        }

        // Prompt for drive letter
        string dl = Microsoft.VisualBasic.Interaction.InputBox(
            "Enter drive letter to mount as (e.g. Z):",
            "Mount as Drive", "Z").Trim().TrimEnd(':').ToUpperInvariant();

        if (dl.Length != 1 || dl[0] < 'A' || dl[0] > 'Z')
        { StatusError("Invalid drive letter."); return; }

        bool isPqc = _toggle.Selected == SegmentedToggle.Segment.Pqc;

        // Build the CLI command (password passed via stdin)
        var sb = new System.Text.StringBuilder();
        sb.Append("mount");
        sb.Append($" --in \"{_dropZone.FilePath}\"");
        sb.Append($" --drive {dl}:");
        if (isPqc)
            sb.Append($" --privkey \"{_txtPrivkey.Text}\"");
        else
            sb.Append(" --password-stdin");

        // Launch in background process (mount blocks; user uses unmount or Ctrl+C)
        string password = isPqc ? "" : _txtPassword.Text;
        Log($"[MOUNT] obsidianq {sb}", Theme.TextDim);

        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName               = ResolveExePath(),
                Arguments              = sb.ToString(),
                RedirectStandardInput  = !isPqc,
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                UseShellExecute        = false,
                CreateNoWindow         = false, // show console so user can Ctrl+C
            };
            var proc = new System.Diagnostics.Process { StartInfo = psi, EnableRaisingEvents = true };
            proc.OutputDataReceived += (_, ev) => { if (ev.Data != null) Log(ev.Data, Theme.Accent); };
            proc.ErrorDataReceived  += (_, ev) => { if (ev.Data != null) Log(ev.Data, Theme.Error); };
            proc.Exited += (_, _) =>
            {
                Invoke(() => StatusOk($"Mount process for {dl}: exited."));
            };
            proc.Start();
            proc.BeginOutputReadLine();
            proc.BeginErrorReadLine();
            if (!isPqc)
            {
                proc.StandardInput.WriteLine(password);
                proc.StandardInput.Close();
            }
            StatusOk($"Mount process started for {dl}: (check console window).");
        }
        catch (Exception ex)
        {
            StatusError($"Mount failed: {ex.Message}");
        }
    }

    // -----------------------------------------------------------------------
    // RUN
    // -----------------------------------------------------------------------
    private async void BtnRun_Click(object? sender, EventArgs e)
    {
        if (_busy) { CancelOperation(); return; }
        if (!ValidateInputs(out string? errMsg)) { StatusError(errMsg!); return; }
        await RunOperationAsync();
    }

    private bool ValidateInputs(out string? err)
    {
        err = null;
        if (_dropZone.FilePath == null)                     { err = "Drop or browse an input file first."; return false; }
        if (!File.Exists(_dropZone.FilePath))               { err = "Input file not found."; return false; }
        if (string.IsNullOrWhiteSpace(_lblOutPath.Text) || _lblOutPath.Text == "-")
                                                            { err = "Output path is not set."; return false; }

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
            if (!File.Exists(_txtPrivkey.Text)) { err = "Key file not found."; return false; }
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

        // Build argument list (password NEVER in args)
        var sb = new StringBuilder();
        if (isEncrypt)
        {
            sb.Append("encrypt");
            sb.Append($" --in \"{_dropZone.FilePath}\"");
            sb.Append($" --out \"{_lblOutPath.Text}\"");
            sb.Append($" --suite {suite}");
            if (_chkCompress.Checked) sb.Append(" --compress");
            if (isPqc)
                sb.Append($" --pubkey \"{_txtPrivkey.Text}\"");
            else
                sb.Append(" --password-stdin");
        }
        else
        {
            sb.Append("decrypt");
            sb.Append($" --in \"{_dropZone.FilePath}\"");
            sb.Append($" --out \"{_lblOutPath.Text}\"");
            if (isPqc)
                sb.Append($" --privkey \"{_txtPrivkey.Text}\"");
            else
                sb.Append(" --password-stdin");
        }

        Log($"[CMD] obsidianq {sb}", Theme.TextDim);
        Log("", Theme.TextDim);

        _cts = new CancellationTokenSource();
        var token = _cts.Token;

        // Capture password before leaving UI thread
        string password = isPqc ? "" : _txtPassword.Text;

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = ExePath,
                Arguments = sb.ToString(),
                RedirectStandardInput  = !isPqc,
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                UseShellExecute = false,
                CreateNoWindow  = true,
            };

            var proc = new Process { StartInfo = psi, EnableRaisingEvents = true };
            proc.Start();

            // Write password to stdin and close immediately
            if (!isPqc)
            {
                await proc.StandardInput.WriteLineAsync(password);
                proc.StandardInput.Close();
            }

            // Stream stdout + stderr asynchronously
            var stdoutTask = StreamOutputAsync(proc.StandardOutput, Theme.Accent,  token);
            var stderrTask = StreamOutputAsync(proc.StandardError,  Theme.Error,   token);

            await Task.WhenAll(stdoutTask, stderrTask);
            await proc.WaitForExitAsync(token);

            if (proc.ExitCode == 0)
                StatusOk(isEncrypt ? "Encryption complete." : "Decryption complete.");
            else
                StatusError($"Process exited with code {proc.ExitCode}.");
        }
        catch (OperationCanceledException)
        {
            StatusError("Cancelled.");
        }
        catch (Exception ex)
        {
            Log($"[ERROR] {ex.Message}", Theme.Error);
            StatusError("Operation failed.");
        }
        finally
        {
            SetBusy(false);
            _cts?.Dispose();
            _cts = null;
        }
    }

    private async Task StreamOutputAsync(System.IO.TextReader reader, Color color, CancellationToken ct)
    {
        string? line;
        while ((line = await reader.ReadLineAsync(ct)) != null)
            Log(line, color);
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

    private void Log(string text, Color color)
    {
        if (InvokeRequired) { Invoke(() => Log(text, color)); return; }
        _rtbLog.SelectionStart = _rtbLog.TextLength;
        _rtbLog.SelectionLength = 0;
        _rtbLog.SelectionColor = color;
        _rtbLog.AppendText(text + "\n");
        _rtbLog.ScrollToCaret();
    }

    // -----------------------------------------------------------------------
    // Locate obsidianq.exe
    // -----------------------------------------------------------------------
    private static string ResolveExePath()
    {
        // 1. Same directory as this exe
        string self = AppContext.BaseDirectory;
        string candidate = Path.Combine(self, "obsidianq.exe");
        if (File.Exists(candidate)) return candidate;

        // 2. Two levels up (running from tools/windows-gui alongside target/ in root)
        string repoRoot = Path.GetFullPath(Path.Combine(self, "..", ".."));
        candidate = Path.Combine(repoRoot, "target", "release", "obsidianq.exe");
        if (File.Exists(candidate)) return candidate;

        // 3. Debug build
        candidate = Path.Combine(repoRoot, "target", "debug", "obsidianq.exe");
        if (File.Exists(candidate)) return candidate;

        // Return expected path so the error message is informative
        return Path.Combine(self, "obsidianq.exe");
    }

    // -----------------------------------------------------------------------
    // Dark mode: title bar + scrollbars
    // -----------------------------------------------------------------------

    // Tells DWM to render the non-client area (title bar, borders) in dark mode.
    // Attribute 20 = DWMWA_USE_IMMERSIVE_DARK_MODE (Windows 10 19041+ / Windows 11).
    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);

    // Applies a named visual style to a control --- used here to give the
    // RichTextBox scrollbars the system dark-mode look.
    [DllImport("uxtheme.dll", CharSet = CharSet.Unicode)]
    private static extern int SetWindowTheme(IntPtr hwnd, string? pszSubAppName, string? pszSubIdList);

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);

        // Dark title bar
        int dark = 1;
        DwmSetWindowAttribute(Handle, 20 /* DWMWA_USE_IMMERSIVE_DARK_MODE */, ref dark, 4);

        // Dark scrollbars on the log console
        SetWindowTheme(_rtbLog.Handle, "DarkMode_Explorer", null);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) { _shimmer.Dispose(); }
        base.Dispose(disposing);
    }
}







































