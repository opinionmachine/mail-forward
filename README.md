# Mail Forwarder

A Python script that runs quietly in the background and forwards system mail from your Unix mail spool file to your email address using OAuth2 authentication.

## Features

- Monitors your Unix mail spool file (`/var/mail/username`) for new messages
- Automatically forwards new mail to your email address
- Uses OAuth2 device code flow for secure authentication
- Runs as a background daemon
- Can be configured to start automatically on login (macOS LaunchAgent)
- Configurable via a dotfile in your home directory
- Logs all activity to `~/.mailforward.log`

## Requirements

- Python 3.6 or higher
- A Microsoft account (Outlook.com, Hotmail.com, or Microsoft 365)
- OAuth2 libraries: `pip3 install msal requests`
- Read access to your Unix mail spool file

## Quick Start

1. **Install dependencies:**
   ```bash
   pip3 install msal requests
   ```

2. **Set up Azure App Registration:**
   - Follow the detailed instructions in [OAUTH2_SETUP.md](OAUTH2_SETUP.md)
   - You'll need to register an app in Azure Portal and get a Client ID

3. **Create your configuration file:**
   ```bash
   cp .mailforwardrc.example ~/.mailforwardrc
   chmod 600 ~/.mailforwardrc
   nano ~/.mailforwardrc
   ```
   
   Set:
   - `oauth2.client_id`: Your Azure App Client ID
   - `oauth2.from_email`: Your email address
   - `mail.forward_to`: Where to forward mail
   - `mail.spool_file`: Path to your mail spool (usually `/var/mail/username`)

4. **Make the script executable:**
   ```bash
   chmod +x mail_forwarder.py
   ```

5. **Run the script to authenticate:**
   ```bash
   python3 mail_forwarder.py
   ```
   
   You'll see a device code authentication message. Follow the instructions to sign in once. The token will be cached for future use.

6. **Run as background daemon:**
   ```bash
   python3 mail_forwarder.py --daemon
   ```

7. **Set up auto-start on login** (optional but recommended):
   ```bash
   cp com.mailforwarder.plist.example ~/Library/LaunchAgents/com.mailforwarder.plist
   nano ~/Library/LaunchAgents/com.mailforwarder.plist  # Update the script path
   launchctl load ~/Library/LaunchAgents/com.mailforwarder.plist
   ```

8. **Verify it's working:**
   ```bash
   # Check if it's running
   ps aux | grep mail_forwarder
   
   # Check the logs
   tail -f ~/.mailforward.log
   
   # Send a test mail
   echo "Test" | mail -s "Test" $USER
   ```

## Configuration

The configuration file is located at `~/.mailforwardrc`. See `.mailforwardrc.example` for the template.

### Key Settings:

- `oauth2.enabled`: Set to `true` to use OAuth2
- `oauth2.client_id`: Your Azure App Registration Client ID
- `oauth2.tenant_id`: Use `common` for personal Microsoft accounts
- `oauth2.from_email`: Email address to send from (must match your Microsoft account)
- `mail.spool_file`: Path to your Unix mail spool (default: `/var/mail/username`)
- `mail.forward_to`: Email address to forward mail to
- `mail.check_interval`: How often to check for new mail (seconds, default: 60)

**Important:** Do NOT set `oauth2.client_secret` for personal Microsoft accounts. Leave it empty or omit it entirely.

## Usage

```bash
# Run in foreground (for testing and initial authentication)
python3 mail_forwarder.py

# Run as background daemon
python3 mail_forwarder.py --daemon

# Stop the daemon
python3 mail_forwarder.py --stop

# Use a custom config file
python3 mail_forwarder.py -c /path/to/config
```

## Files Created

- `~/.mailforwardrc` - Configuration file (you create this)
- `~/.mailforward.log` - Log file
- `~/.mailforward.pid` - PID file (when running as daemon)
- `~/.mailforward_token_cache.json` - OAuth2 token cache (automatically managed)

## Stopping the Daemon

To stop the running daemon:
```bash
python3 mail_forwarder.py --stop
```

Or manually:
```bash
kill $(cat ~/.mailforward.pid)
```

## Troubleshooting

See [OAUTH2_SETUP.md](OAUTH2_SETUP.md) for detailed troubleshooting steps.

Common issues:
- **Mail spool not found**: Check the path in your config file
- **Authentication errors**: Verify your Azure app registration and Client ID
- **"Conditional Access policy blocking"**: Make sure you're using Delegated permissions (not Application) and have no `client_secret` set
- **Permission errors**: Ensure you have read access to the mail spool file
- **No authentication message**: Make sure `oauth2.enabled = true` and `client_secret` is not set

## Security Notes

- The configuration file contains your Client ID - keep it secure (`chmod 600`)
- OAuth2 tokens are cached securely in `~/.mailforward_token_cache.json`
- The script only reads from your mail spool and sends emails - it doesn't modify anything
- You only need to authenticate once - tokens are automatically refreshed

## License

This software is licensed under a Non-Commercial License. See [LICENSE](LICENSE) for details.

**Summary:**
- ✅ Free to download, use, and modify
- ✅ Free to distribute
- ❌ **NOT** allowed for commercial use

For commercial licensing inquiries, please contact the copyright holder.
