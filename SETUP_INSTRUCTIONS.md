# Mail Forwarder Setup Instructions

This guide will walk you through setting up the Mail Forwarder with OAuth2 authentication.

## Prerequisites

1. **Install required Python libraries:**
   ```bash
   pip3 install msal requests
   ```

2. **A Microsoft account** (Outlook.com, Hotmail.com, or Microsoft 365)

## Step 1: Register an Application in Azure Portal

1. **Go to Azure Portal:**
   - Navigate to https://portal.azure.com/
   - Sign in with your Microsoft account (the same one you want to use for sending emails)

2. **Access Azure Active Directory:**
   - In the search bar at the top, type "Microsoft Entra ID" (or "Azure Active Directory")
   - Click on it to open

3. **Create App Registration:**
   - Click on "App registrations" in the left menu
   - Click "New registration" at the top

4. **Configure the App:**
   - **Name**: Give it a name like "Mail Forwarder" or "Unix Mail Script"
   - **Supported account types**: 
     - For personal Microsoft accounts (Outlook.com, Hotmail.com): Select "Accounts in any organizational directory and personal Microsoft accounts"
     - For work/school accounts: Select the appropriate option
   - **Redirect URI**: Leave blank (we're using device code flow)
   - Click "Register"

5. **Note Your Client ID:**
   - After registration, you'll see the "Overview" page
   - **Copy the "Application (client) ID"** - This is your `client_id`
   - Save it for the next step

## Step 2: Configure API Permissions

1. **Go to API permissions:**
   - In the left menu of your app registration, click "API permissions"

2. **Add Microsoft Graph Permission:**
   - Click "Add a permission"
   - Select "Microsoft Graph"
   - **Choose "Delegated permissions"** (NOT Application permissions)
   - Search for and select: **`Mail.Send`**
   - Click "Add permissions"

3. **Verify the permission:**
   - You should see `Mail.Send` listed under "Delegated permissions"
   - The status will show "Not granted" until you authenticate (this is normal)

## Step 3: Configure Your Mail Forwarder

1. **Copy the example configuration file:**
   ```bash
   cp .mailforwardrc.example ~/.mailforwardrc
   ```

2. **Edit the configuration file:**
   ```bash
   nano ~/.mailforwardrc
   ```
   (or use your preferred editor: `vim`, `code`, etc.)

3. **Update the following settings:**
   ```ini
   [mail]
   spool_file = /var/mail/username  # Update with your username
   forward_to = your-email@example.com  # Where to forward mail
   check_interval = 60
   
   [oauth2]
   enabled = true
   client_id = YOUR_CLIENT_ID_FROM_STEP_1  # Paste your Client ID here
   tenant_id = common  # Use "common" for personal accounts
   from_email = your-email@outlook.com  # Your Microsoft account email
   ```
   
   **Important:**
   - Replace `YOUR_CLIENT_ID_FROM_STEP_1` with the Application (client) ID from Step 1
   - Do NOT set `client_secret` - leave it empty or omit it entirely
   - For personal Microsoft accounts, use `tenant_id = common`
   - Set `from_email` to the email address you want to send from (must match your Microsoft account)

4. **Set secure permissions on the config file:**
   ```bash
   chmod 600 ~/.mailforwardrc
   ```
   This ensures only you can read the file.

## Step 4: Initial Authentication

1. **Make the script executable:**
   ```bash
   chmod +x mail_forwarder.py
   ```

2. **Run the script in foreground mode:**
   ```bash
   python3 mail_forwarder.py
   ```

3. **You'll see an authentication message:**
   ```
   ============================================================
   AUTHENTICATION REQUIRED
   ============================================================
   To sign in, open this URL in your browser:
     https://microsoft.com/devicelogin
   
   Enter this code: ABC123XYZ
   
   Waiting for you to complete the sign-in...
   ============================================================
   ```

4. **Complete the authentication:**
   - Open the URL in your browser
   - Enter the code shown
   - Sign in with your Microsoft account
   - Grant permissions when prompted (you'll be asked to allow the app to send mail on your behalf)
   - The script will automatically continue once authenticated

5. **The token will be cached** in `~/.mailforward_token_cache.json` for future use

6. **Stop the script** (Ctrl+C) and run it as a daemon:
   ```bash
   python3 mail_forwarder.py --daemon
   ```

## Step 5: Set Up Auto-Start on Login (macOS)

To make the mail forwarder start automatically every time you log in to your Mac:

1. **Copy the example plist file:**
   ```bash
   cp com.mailforwarder.plist.example ~/Library/LaunchAgents/com.mailforwarder.plist
   ```

2. **Edit the plist file** to update the path to your `mail_forwarder.py` script:
   ```bash
   nano ~/Library/LaunchAgents/com.mailforwarder.plist
   ```
   
   **Important:** Replace `/path/to/mail-forward/mail_forwarder.py` with the actual absolute path where you've placed the script. Also update the log file paths with your actual username.

3. **Load the LaunchAgent:**
   ```bash
   launchctl load ~/Library/LaunchAgents/com.mailforwarder.plist
   ```

4. **Verify it's loaded:**
   ```bash
   launchctl list | grep mailforwarder
   ```

5. **To test immediately (without logging out):**
   ```bash
   launchctl start com.mailforwarder
   ```

The mail forwarder will now start automatically every time you log in to your Mac.

### Managing the LaunchAgent:

- **Unload (stop auto-start):**
  ```bash
  launchctl unload ~/Library/LaunchAgents/com.mailforwarder.plist
  ```

- **Reload (after making changes):**
  ```bash
  launchctl unload ~/Library/LaunchAgents/com.mailforwarder.plist
  launchctl load ~/Library/LaunchAgents/com.mailforwarder.plist
  ```

- **Stop the service:**
  ```bash
  launchctl stop com.mailforwarder
  ```

- **Start the service:**
  ```bash
  launchctl start com.mailforwarder
  ```

## Step 6: Verify It's Working

1. **Check if the daemon is running:**
   ```bash
   ps aux | grep mail_forwarder
   ```

2. **Check the log file:**
   ```bash
   tail -f ~/.mailforward.log
   ```

3. **Test by sending yourself a system mail:**
   ```bash
   echo "Test message" | mail -s "Test" $USER
   ```
   
   You should receive this message forwarded to your email inbox within a minute.

## Troubleshooting

### Mail spool file not found:
- Check if the mail spool exists: `ls -l /var/mail/username` (replace `username` with your actual username)
- If it doesn't exist, you may need to create it or check the correct path
- Some systems use `~/mbox` instead

### "Failed to acquire OAuth2 token" or "Conditional Access policy is blocking"

**Solutions:**
1. Make sure `client_secret` is NOT set in your config file (remove it or leave it empty)
2. Verify you're using **Delegated permissions** (not Application permissions) in Azure Portal
3. Check that `Mail.Send` is listed under "Delegated permissions" in Azure Portal
4. Delete `~/.mailforward_token_cache.json` and re-authenticate
5. Make sure your Azure app registration supports personal Microsoft accounts

### "Graph API error: 403"

**Possible causes:**
- API permissions not granted
- Wrong permission type
- Consent not granted

**Solutions:**
1. Go to Azure Portal → Your App → API permissions
2. Verify `Mail.Send` is listed under **"Delegated permissions"**
3. Complete the device code flow authentication if you haven't already
4. Wait a few minutes for permissions to propagate

### "Graph API error: 400"

**Possible causes:**
- Invalid email address in `from_email`
- Email format issue

**Solutions:**
1. Verify `from_email` matches your Microsoft account email exactly
2. Check that the email address is correct in the config file

### "Graph API error: 401"

**Possible causes:**
- Invalid or expired access token
- Token cache corrupted

**Solutions:**
1. Delete `~/.mailforward_token_cache.json` and re-authenticate
2. Run the script in foreground mode to complete authentication again

### No authentication message appears:

**Solutions:**
1. Verify `oauth2.enabled = true` in your config file
2. Make sure `client_id` is set to your actual Azure Client ID
3. Make sure `client_secret` is NOT set (remove it or leave it empty)
4. Check the log file: `tail -f ~/.mailforward.log`

## Log File

The script logs to `~/.mailforward.log`. Check this file if you encounter any issues:
```bash
tail -f ~/.mailforward.log
```

## Security Notes

- **Keep credentials secure**: The config file contains your Client ID - keep it protected (`chmod 600`)
- **Token cache**: Access tokens are cached in `~/.mailforward_token_cache.json` - this file is automatically managed by the script
- **Token refresh**: Tokens are automatically refreshed when they expire - you don't need to re-authenticate manually
