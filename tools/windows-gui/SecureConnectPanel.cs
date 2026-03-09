using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Runtime.InteropServices;
using System.Diagnostics;
using QRCoder;

namespace ObsidianQ.Launcher;

class SecureConnectPanel : Panel
{
    private readonly string _exePath;

    private readonly TextBox _txtRelayUrl;
    private readonly TextBox _txtCodeInput;
    private readonly Label _lblCode;
    private readonly Label _lblStatus;
    private readonly PictureBox _qrBox;
    private readonly RichTextBox _log;
    private readonly Panel _verifyPanel;
    private readonly Label _lblVerifyPhrase;
    private readonly Panel _chatPanel;
    private readonly TextBox _txtMessage;
    private readonly NeonButton _btnSendMessage;
    private readonly NeonButton _btnReceiveConnection;
    private readonly NeonButton _btnSendConnection;
    private readonly NeonButton _btnCancelSession;

    private ClientWebSocket? _ws;
    private CancellationTokenSource? _cts;
    private bool _receiveRole;
    private bool _localVerified;
    private bool _peerVerified;
    private ulong _sendCounter;
    private ulong _recvCounter;

    private string _sessionIdHex = string.Empty;
    private string _pairCode = string.Empty;
    private string _privateKeyB64 = string.Empty;
    private byte[]? _sessionKey;

    public SecureConnectPanel(string exePath)
    {
        _exePath = exePath;
        Dock = DockStyle.Fill;
        BackColor = Theme.Bg;

        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 7,
            BackColor = Theme.Bg,
            Padding = new Padding(16),
        };
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 36));  // relay
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 64));  // cards
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 72));  // code + send
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 140)); // qr + status
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 78));  // verify
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 64));  // chat
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));  // log

        var relayRow = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, BackColor = Theme.Bg };
        relayRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 90));
        relayRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        relayRow.Controls.Add(MakeLabel("RELAY URL", 8.5f), 0, 0);
        _txtRelayUrl = MakeTextBox();
        _txtRelayUrl.Text = "ws://127.0.0.1:8787/ws";
        relayRow.Controls.Add(_txtRelayUrl, 1, 0);
        root.Controls.Add(relayRow, 0, 0);

        var cardRow = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, BackColor = Theme.Bg };
        cardRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        cardRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        _btnReceiveConnection = new NeonButton { Text = "RECEIVE CONNECTION", Dock = DockStyle.Fill, Margin = new Padding(0, 0, 4, 0), Font = Theme.SafeMono(10f) };
        _btnSendConnection = new NeonButton { Text = "SEND CONNECTION", Dock = DockStyle.Fill, Margin = new Padding(4, 0, 0, 0), Font = Theme.SafeMono(10f) };
        _btnReceiveConnection.Click += async (_, _) => await StartReceiveAsync();
        _btnSendConnection.Click += async (_, _) => await StartSendAsync();
        cardRow.Controls.Add(_btnReceiveConnection, 0, 0);
        cardRow.Controls.Add(_btnSendConnection, 1, 0);
        root.Controls.Add(cardRow, 0, 1);

        var codeRow = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 4, RowCount = 1, BackColor = Theme.Bg };
        codeRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 120));
        codeRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        codeRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 110));
        codeRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 100));
        _lblCode = MakeLabel("Code: -", 10f, bold: true);
        _lblCode.Dock = DockStyle.Fill;
        _lblCode.TextAlign = ContentAlignment.MiddleLeft;
        _txtCodeInput = MakeTextBox();
        _txtCodeInput.PlaceholderText = "123-456-789";
        _txtCodeInput.TextChanged += (_, _) => _txtCodeInput.Text = FormatCode(_txtCodeInput.Text);
        var btnCopyCode = new NeonButton { Text = "COPY", Dock = DockStyle.Fill, Margin = new Padding(3, 2, 0, 2) };
        btnCopyCode.Click += (_, _) =>
        {
            if (string.IsNullOrWhiteSpace(_pairCode)) { SetStatus("No active code to copy.", true); return; }
            Clipboard.SetText(_pairCode);
            SetStatus("Copied pairing code.");
        };
        _btnCancelSession = new NeonButton { Text = "CANCEL", Dock = DockStyle.Fill, Margin = new Padding(3, 2, 0, 2) };
        _btnCancelSession.Click += async (_, _) => await CancelSessionAsync();
        codeRow.Controls.Add(_lblCode, 0, 0);
        codeRow.Controls.Add(_txtCodeInput, 1, 0);
        codeRow.Controls.Add(btnCopyCode, 2, 0);
        codeRow.Controls.Add(_btnCancelSession, 3, 0);
        root.Controls.Add(codeRow, 0, 2);

        var statusRow = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, BackColor = Theme.Bg };
        statusRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 140));
        statusRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        _qrBox = new PictureBox { Dock = DockStyle.Fill, SizeMode = PictureBoxSizeMode.Zoom, BackColor = Theme.Surface };
        var statusPanel = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Surface, Padding = new Padding(8) };
        _lblStatus = MakeLabel("Idle", 9f);
        _lblStatus.Dock = DockStyle.Top;
        _lblStatus.Height = 24;
        var hint = MakeLabel("After pairing, compare phrase on both devices and click 'They Match'.", 8f);
        hint.Dock = DockStyle.Fill;
        statusPanel.Controls.Add(hint);
        statusPanel.Controls.Add(_lblStatus);
        statusRow.Controls.Add(_qrBox, 0, 0);
        statusRow.Controls.Add(statusPanel, 1, 0);
        root.Controls.Add(statusRow, 0, 3);

        _verifyPanel = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Surface, Visible = false, Padding = new Padding(8) };
        var verifyLayout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, RowCount = 2, BackColor = Theme.Surface };
        verifyLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        verifyLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 120));
        verifyLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 120));
        verifyLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        verifyLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
        _lblVerifyPhrase = MakeLabel("-", 11f, bold: true);
        _lblVerifyPhrase.Dock = DockStyle.Fill;
        _lblVerifyPhrase.TextAlign = ContentAlignment.MiddleLeft;
        var lblVerifyHint = MakeLabel("Confirm both devices show this phrase:", 8.5f);
        lblVerifyHint.Dock = DockStyle.Top;
        var hintHolder = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Surface };
        hintHolder.Controls.Add(_lblVerifyPhrase);
        hintHolder.Controls.Add(lblVerifyHint);
        var btnMatch = new NeonButton { Text = "THEY MATCH", Dock = DockStyle.Fill, Margin = new Padding(3, 2, 0, 2) };
        var btnCancelVerify = new NeonButton { Text = "CANCEL", Dock = DockStyle.Fill, Margin = new Padding(3, 2, 0, 2) };
        btnMatch.Click += async (_, _) => await ConfirmPhraseMatchAsync();
        btnCancelVerify.Click += async (_, _) => await CancelSessionAsync();
        verifyLayout.Controls.Add(hintHolder, 0, 0);
        verifyLayout.SetColumnSpan(hintHolder, 3);
        verifyLayout.Controls.Add(btnMatch, 1, 1);
        verifyLayout.Controls.Add(btnCancelVerify, 2, 1);
        _verifyPanel.Controls.Add(verifyLayout);
        root.Controls.Add(_verifyPanel, 0, 4);

        _chatPanel = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Bg, Visible = false };
        var chatRow = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, BackColor = Theme.Bg };
        chatRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        chatRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 120));
        _txtMessage = MakeTextBox();
        _txtMessage.PlaceholderText = "Send secure message...";
        _btnSendMessage = new NeonButton { Text = "SEND", Dock = DockStyle.Fill, Margin = new Padding(3, 2, 0, 2) };
        _btnSendMessage.Click += async (_, _) => await SendSecureMessageAsync();
        chatRow.Controls.Add(_txtMessage, 0, 0);
        chatRow.Controls.Add(_btnSendMessage, 1, 0);
        _chatPanel.Controls.Add(chatRow);
        root.Controls.Add(_chatPanel, 0, 5);

        _log = new RichTextBox
        {
            Dock = DockStyle.Fill,
            ReadOnly = true,
            WordWrap = false,
            BackColor = Theme.LogBg,
            ForeColor = Theme.Accent,
            BorderStyle = BorderStyle.None,
            ScrollBars = RichTextBoxScrollBars.Both,
            Font = Theme.SafeMono(8.5f),
        };
        _log.HandleCreated += (_, _) => SetWindowTheme(_log.Handle, "DarkMode_Explorer", null);
        var logWrap = new Panel { Dock = DockStyle.Fill, BackColor = Theme.LogBg };
        logWrap.Controls.Add(_log);
        logWrap.Paint += (_, pe) =>
        {
            using var pen = new Pen(Theme.Border, 1f);
            pe.Graphics.DrawRectangle(pen, 0, 0, logWrap.Width - 1, logWrap.Height - 1);
        };
        root.Controls.Add(logWrap, 0, 6);

        Controls.Add(root);
    }

    private async Task StartReceiveAsync()
    {
        if (!EnsureCliPresent()) return;
        await CancelSessionAsync(clearCode: false);
        _receiveRole = true;
        _localVerified = false;
        _peerVerified = false;
        _chatPanel.Visible = false;

        var values = await RunCliKeyValueAsync("secure-connect new-session");
        if (values == null) return;

        _sessionIdHex = values.TryGetValue("session_id", out var sid) ? sid : string.Empty;
        _pairCode = values.TryGetValue("code", out var code) ? code : string.Empty;
        var pub = values.TryGetValue("public_key", out var p) ? p : string.Empty;
        _privateKeyB64 = values.TryGetValue("private_key", out var sk) ? sk : string.Empty;
        if (string.IsNullOrWhiteSpace(_sessionIdHex) || string.IsNullOrWhiteSpace(_pairCode) || string.IsNullOrWhiteSpace(pub))
        {
            SetStatus("Failed to initialize receive session.", true);
            return;
        }

        _lblCode.Text = $"Code: {_pairCode}";
        GenerateQr(_txtRelayUrl.Text.Trim(), _pairCode);
        SetStatus("Waiting for connection...");
        Log($"[SC] Receive session ready code={_pairCode}", Theme.AccentDim);

        if (!await ConnectWsAsync()) return;
        await SendWsJsonAsync(new
        {
            type = "receive_start",
            code = _pairCode,
            session_id = _sessionIdHex,
            public_key = pub
        });
    }

    private async Task StartSendAsync()
    {
        if (!EnsureCliPresent()) return;
        await CancelSessionAsync(clearCode: false);
        _receiveRole = false;
        _localVerified = false;
        _peerVerified = false;
        _chatPanel.Visible = false;
        _verifyPanel.Visible = false;

        _pairCode = NormalizeCode(_txtCodeInput.Text);
        if (_pairCode.Length != 9)
        {
            SetStatus("Enter a 9-digit code (e.g. 123-456-789).", true);
            return;
        }
        _pairCode = $"{_pairCode[..3]}-{_pairCode.Substring(3, 3)}-{_pairCode.Substring(6, 3)}";
        _lblCode.Text = $"Code: {_pairCode}";
        GenerateQr(_txtRelayUrl.Text.Trim(), _pairCode);

        if (!await ConnectWsAsync()) return;
        SetStatus("Connecting to receive side...");
        await SendWsJsonAsync(new { type = "send_join", code = _pairCode });
    }

    private async Task<bool> ConnectWsAsync()
    {
        try
        {
            _cts?.Cancel();
            _cts = new CancellationTokenSource();
            _ws?.Dispose();
            _ws = new ClientWebSocket();
            var uri = new Uri(_txtRelayUrl.Text.Trim());
            await _ws.ConnectAsync(uri, _cts.Token);
            _ = Task.Run(() => ReceiveLoopAsync(_cts.Token));
            SetStatus("Connected to relay.");
            return true;
        }
        catch (Exception ex)
        {
            SetStatus($"Relay connection failed: {ex.Message}", true);
            return false;
        }
    }

    private async Task ReceiveLoopAsync(CancellationToken ct)
    {
        var buffer = new byte[16 * 1024];
        try
        {
            while (!ct.IsCancellationRequested && _ws != null && _ws.State == WebSocketState.Open)
            {
                var ms = new MemoryStream();
                WebSocketReceiveResult result;
                do
                {
                    result = await _ws.ReceiveAsync(buffer, ct);
                    if (result.MessageType == WebSocketMessageType.Close)
                    {
                        SetStatus("Relay disconnected.", true);
                        return;
                    }
                    ms.Write(buffer, 0, result.Count);
                } while (!result.EndOfMessage);

                var text = Encoding.UTF8.GetString(ms.ToArray());
                HandleServerMessage(text);
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            SetStatus($"Connection error: {ex.Message}", true);
        }
    }

    private void HandleServerMessage(string text)
    {
        try
        {
            using var doc = JsonDocument.Parse(text);
            var root = doc.RootElement;
            if (!root.TryGetProperty("type", out var t)) return;
            var kind = t.GetString() ?? "";
            switch (kind)
            {
                case "receive_ready":
                    SetStatus("Waiting for sender...");
                    break;
                case "peer_connected":
                    SetStatus("Peer connected. Waiting for handshake...");
                    break;
                case "session_info":
                    _ = HandleSessionInfoAsync(root);
                    break;
                case "relay":
                    if (root.TryGetProperty("payload", out var payload))
                        _ = HandleRelayPayloadAsync(payload.GetString() ?? string.Empty);
                    break;
                case "error":
                    var msg = root.TryGetProperty("message", out var m) ? m.GetString() : "relay error";
                    SetStatus(msg ?? "relay error", true);
                    break;
            }
        }
        catch (Exception ex)
        {
            Log($"[SC][ERR] bad relay message: {ex.Message}", Theme.Error);
        }
    }

    private async Task HandleSessionInfoAsync(JsonElement root)
    {
        if (_receiveRole) return;
        if (!root.TryGetProperty("session_id", out var sidEl)) return;
        if (!root.TryGetProperty("public_key", out var pubEl)) return;
        _sessionIdHex = sidEl.GetString() ?? "";
        var peerPub = pubEl.GetString() ?? "";
        if (string.IsNullOrWhiteSpace(_sessionIdHex) || string.IsNullOrWhiteSpace(peerPub))
        {
            SetStatus("Invalid relay session info.", true);
            return;
        }

        var encap = await RunCliKeyValueAsync($"secure-connect encapsulate --peer-pub \"{peerPub}\"");
        if (encap == null) return;
        if (!encap.TryGetValue("ciphertext", out var ciphertext) || !encap.TryGetValue("shared_secret", out var shared))
        {
            SetStatus("Encapsulation failed.", true);
            return;
        }
        await SendRelayPayloadAsync(new { kind = "encap", ciphertext });
        await FinishKeyDerivationAsync(shared);
        SetStatus("Handshake sent. Compare verification phrase.");
    }

    private async Task HandleRelayPayloadAsync(string payloadJson)
    {
        if (string.IsNullOrWhiteSpace(payloadJson)) return;
        using var doc = JsonDocument.Parse(payloadJson);
        var root = doc.RootElement;
        var kind = root.TryGetProperty("kind", out var k) ? k.GetString() ?? "" : "";
        switch (kind)
        {
            case "encap":
                if (!_receiveRole) return;
                if (!root.TryGetProperty("ciphertext", out var ctEl)) return;
                var ct = ctEl.GetString() ?? "";
                var decap = await RunCliKeyValueAsync($"secure-connect decapsulate --private-key \"{_privateKeyB64}\" --ciphertext \"{ct}\"");
                if (decap == null || !decap.TryGetValue("shared_secret", out var shared)) return;
                await FinishKeyDerivationAsync(shared);
                SetStatus("Handshake received. Compare verification phrase.");
                break;
            case "verified":
                _peerVerified = true;
                TryMarkTrusted();
                break;
            case "secure_msg":
                await HandleSecureMessageAsync(root);
                break;
        }
    }

    private async Task FinishKeyDerivationAsync(string sharedSecretB64)
    {
        var derived = await RunCliKeyValueAsync($"secure-connect derive --shared-secret \"{sharedSecretB64}\" --session-id \"{_sessionIdHex}\"");
        if (derived == null) return;
        if (!derived.TryGetValue("session_key", out var keyB64) || !derived.TryGetValue("verify_phrase", out var phrase))
        {
            SetStatus("Key derivation failed.", true);
            return;
        }
        _sessionKey = Convert.FromBase64String(keyB64);
        _lblVerifyPhrase.Text = phrase;
        _verifyPanel.Visible = true;
        Log($"[SC] Verification phrase: {phrase}", Theme.AccentDim);
    }

    private async Task ConfirmPhraseMatchAsync()
    {
        if (_sessionKey == null)
        {
            SetStatus("No session key established.", true);
            return;
        }
        _localVerified = true;
        _verifyPanel.Visible = false;
        await SendRelayPayloadAsync(new { kind = "verified" });
        TryMarkTrusted();
    }

    private void TryMarkTrusted()
    {
        if (!_localVerified || !_peerVerified) return;
        _chatPanel.Visible = true;
        _sendCounter = 0;
        _recvCounter = 0;
        SetStatus("Secure connection established.");
        Log("[SC] Encrypted channel established.", Theme.Accent);
    }

    private async Task SendSecureMessageAsync()
    {
        if (_sessionKey == null || !_chatPanel.Visible)
        {
            SetStatus("Connection is not established.", true);
            return;
        }
        string msg = _txtMessage.Text.Trim();
        if (string.IsNullOrEmpty(msg)) return;

        byte[] nonce = BuildNonce(_sendCounter++, _receiveRole ? 0xA1B2C3D4u : 0xB1C2D3E4u);
        byte[] plain = Encoding.UTF8.GetBytes(msg);
        byte[] aad = HexToBytes(_sessionIdHex);
        byte[] ct = new byte[plain.Length];
        byte[] tag = new byte[16];
        using (var aes = new AesGcm(_sessionKey, 16))
            aes.Encrypt(nonce, plain, ct, tag, aad);

        await SendRelayPayloadAsync(new
        {
            kind = "secure_msg",
            nonce = Convert.ToBase64String(nonce),
            ciphertext = Convert.ToBase64String(ct),
            tag = Convert.ToBase64String(tag),
        });
        Log($"[ME] {msg}", Theme.AccentDim);
        _txtMessage.Clear();
    }

    private async Task HandleSecureMessageAsync(JsonElement root)
    {
        if (_sessionKey == null) return;
        try
        {
            var nonce = Convert.FromBase64String(root.GetProperty("nonce").GetString() ?? "");
            var ct = Convert.FromBase64String(root.GetProperty("ciphertext").GetString() ?? "");
            var tag = Convert.FromBase64String(root.GetProperty("tag").GetString() ?? "");
            if (nonce.Length != 12 || tag.Length != 16)
            {
                SetStatus("Invalid secure message.", true);
                return;
            }
            uint expectedPrefix = _receiveRole ? 0xB1C2D3E4u : 0xA1B2C3D4u;
            uint gotPrefix = BitConverter.ToUInt32(nonce, 0);
            if (gotPrefix != expectedPrefix)
            {
                SetStatus("Invalid message direction/nonce.", true);
                return;
            }
            ulong counter = BitConverter.ToUInt64(nonce, 4);
            if (counter < _recvCounter)
            {
                SetStatus("Replay/old message rejected.", true);
                return;
            }
            _recvCounter = counter + 1;

            byte[] pt = new byte[ct.Length];
            byte[] aad = HexToBytes(_sessionIdHex);
            using (var aes = new AesGcm(_sessionKey, 16))
                aes.Decrypt(nonce, ct, tag, pt, aad);
            var text = Encoding.UTF8.GetString(pt);
            Log($"[PEER] {text}", Theme.Accent);
        }
        catch (Exception ex)
        {
            SetStatus($"Decrypt failed: {ex.Message}", true);
        }
        await Task.CompletedTask;
    }

    private async Task SendRelayPayloadAsync(object payloadObj)
    {
        string payload = JsonSerializer.Serialize(payloadObj);
        await SendWsJsonAsync(new { type = "relay", payload });
    }

    private async Task SendWsJsonAsync(object obj)
    {
        if (_ws == null || _ws.State != WebSocketState.Open) return;
        var data = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(obj));
        await _ws.SendAsync(data, WebSocketMessageType.Text, true, _cts?.Token ?? CancellationToken.None);
    }

    private async Task<Dictionary<string, string>?> RunCliKeyValueAsync(string args)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = _exePath,
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
            if (!string.IsNullOrWhiteSpace(stdout)) Log(stdout.TrimEnd(), Theme.Accent);
            if (!string.IsNullOrWhiteSpace(stderr)) Log(stderr.TrimEnd(), Theme.Error);
            if (proc.ExitCode != 0)
            {
                SetStatus($"Command failed (exit {proc.ExitCode}).", true);
                return null;
            }

            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var raw in stdout.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries))
            {
                int idx = raw.IndexOf('=');
                if (idx <= 0) continue;
                var key = raw[..idx].Trim();
                var val = raw[(idx + 1)..].Trim();
                if (!string.IsNullOrEmpty(key)) map[key] = val;
            }
            return map;
        }
        catch (Exception ex)
        {
            SetStatus($"Command error: {ex.Message}", true);
            return null;
        }
    }

    private async Task CancelSessionAsync(bool clearCode = true)
    {
        try
        {
            _cts?.Cancel();
            _cts?.Dispose();
            _cts = null;
            if (_ws != null)
            {
                if (_ws.State == WebSocketState.Open)
                    await _ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "cancel", CancellationToken.None);
                _ws.Dispose();
                _ws = null;
            }
        }
        catch { /* best effort */ }

        _sessionKey = null;
        _sessionIdHex = string.Empty;
        _privateKeyB64 = string.Empty;
        _localVerified = false;
        _peerVerified = false;
        _verifyPanel.Visible = false;
        _chatPanel.Visible = false;
        if (clearCode)
        {
            _pairCode = string.Empty;
            _lblCode.Text = "Code: -";
            _qrBox.Image = null;
        }
        SetStatus("Idle");
    }

    private static string NormalizeCode(string input) => new(input.Where(char.IsDigit).ToArray());

    private static string FormatCode(string input)
    {
        var digits = NormalizeCode(input);
        if (digits.Length > 9) digits = digits[..9];
        if (digits.Length <= 3) return digits;
        if (digits.Length <= 6) return $"{digits[..3]}-{digits[3..]}";
        return $"{digits[..3]}-{digits.Substring(3, 3)}-{digits[6..]}";
    }

    private void GenerateQr(string relayUrl, string code)
    {
        try
        {
            var payload = JsonSerializer.Serialize(new { relay_url = relayUrl, code });
            using var gen = new QRCodeGenerator();
            using var data = gen.CreateQrCode(payload, QRCodeGenerator.ECCLevel.Q);
            using var qr = new QRCode(data);
            _qrBox.Image?.Dispose();
            _qrBox.Image = new Bitmap(qr.GetGraphic(6, Color.Black, Color.White, drawQuietZones: true));
        }
        catch (Exception ex)
        {
            Log($"[SC][ERR] QR generation failed: {ex.Message}", Theme.Error);
        }
    }

    private bool EnsureCliPresent()
    {
        if (File.Exists(_exePath)) return true;
        SetStatus($"obsidianq.exe not found: {_exePath}", true);
        return false;
    }

    private void Log(string text, Color color)
    {
        if (InvokeRequired) { Invoke(() => Log(text, color)); return; }
        _log.SelectionStart = _log.TextLength;
        _log.SelectionLength = 0;
        _log.SelectionColor = color;
        _log.AppendText(text + Environment.NewLine);
        _log.ScrollToCaret();
    }

    private void SetStatus(string text, bool error = false)
    {
        if (InvokeRequired) { Invoke(() => SetStatus(text, error)); return; }
        _lblStatus.ForeColor = error ? Theme.Error : Theme.Accent;
        _lblStatus.Text = text;
    }

    private static byte[] BuildNonce(ulong counter, uint prefix)
    {
        byte[] nonce = new byte[12];
        BitConverter.GetBytes(prefix).CopyTo(nonce, 0);
        BitConverter.GetBytes(counter).CopyTo(nonce, 4);
        return nonce;
    }

    private static byte[] HexToBytes(string hex)
    {
        if (string.IsNullOrWhiteSpace(hex)) return Array.Empty<byte>();
        int len = hex.Length / 2;
        byte[] outb = new byte[len];
        for (int i = 0; i < len; i++)
            outb[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        return outb;
    }

    private static Label MakeLabel(string text, float size = 9f, bool bold = false) => new()
    {
        Text = text,
        AutoSize = true,
        Font = bold ? Theme.MonoBold(size) : Theme.SafeMono(size),
        ForeColor = Theme.TextDim,
        BackColor = Color.Transparent,
    };

    private static TextBox MakeTextBox() => new()
    {
        Dock = DockStyle.Fill,
        BackColor = Theme.Surface,
        ForeColor = Theme.Accent,
        BorderStyle = BorderStyle.FixedSingle,
        Margin = new Padding(0, 2, 0, 2),
    };

    [DllImport("uxtheme.dll", CharSet = CharSet.Unicode)]
    private static extern int SetWindowTheme(IntPtr hwnd, string? pszSubAppName, string? pszSubIdList);
}
