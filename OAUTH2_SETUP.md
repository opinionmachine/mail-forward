# OAuth2 Setup Instructions

This guide covers setting up OAuth2 authentication using device code flow for personal Microsoft accounts.

## Prerequisites

1. **Install required Python libraries:**
   ```bash
   pip3 install msal requests
   ```

2. **A Microsoft account** (Outlook.com, Hotmail.com, or Microsoft 365 personal account)

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
   - **Supported account types**: Select **"Accounts in any organizational directory and personal Microsoft accounts"**
   - **Redirect URI**: Leave blank (we're using device code flow)
   - Click "Register"

5. **Copy Your Client ID:**
   - After registration, you'll see the "Overview" page
   - **Copy the "Application (client) ID"** - This is your `client_id`
   - Save it for the configuration step

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

1. **Edit your configuration file:**
   ```bash
   nano ~/.mailforwardrc
   ```

2. **Enable OAuth2 and add your Client ID:**
   ```ini
   [oauth2]
   enabled = true
   client_id = YOUR_CLIENT_ID_FROM_STEP_1
   tenant_id = common
   from_email = your-email@outlook.com
   ```

   **Important:**
   - Replace `YOUR_CLIENT_ID_FROM_STEP_1` with the Application (client) ID from Step 1
   - **Do NOT set `client_secret`** - leave it empty or omit it entirely
   - Use `tenant_id = common` for personal Microsoft accounts
   - Set `from_email` to the email address you want to send from (must match your Microsoft account)

3. **Set secure permissions on the config file:**
   ```bash
   chmod 600 ~/.mailforwardrc
   ```

## Step 4: Initial Authentication

1. **Run the script in foreground mode:**
   ```bash
   python3 mail_forwarder.py
   ```

2. **You'll see an authentication message:**
   ```
   ============================================================
   AUTHENTICATION REQUIRED
   ============================================================
   To sign in, open this URL in your browser:
     https://microsoft.com/devicelogin
   
   Enter this code: ABC123XYZ
   
   Waiting for you to complete the sign-in...
   (This may take up to 15 minutes)
   ============================================================
   ```

3. **Complete the authentication:**
   - Open the URL in your browser
   - Enter the code shown
   - Sign in with your Microsoft account
   - Grant permissions when prompted (you'll be asked to allow the app to send mail on your behalf)
   - The script will automatically continue once authenticated

4. **The token will be cached** in `~/.mailforward_token_cache.json` for future use

5. **Stop the script** (Ctrl+C) and run it as a daemon:
   ```bash
   python3 mail_forwarder.py --daemon
   ```

## Step 5: Test the Configuration

1. **Check the logs:**
   ```bash
   tail -f ~/.mailforward.log
   ```

2. **Send a test mail:**
   ```bash
   echo "Test message" | mail -s "Test" $USER
   ```

   You should receive the forwarded email within a minute.

## Troubleshooting

### "Failed to acquire OAuth2 token" or "Conditional Access policy is blocking"

**Solutions:**
1. **Remove `client_secret`** from your config file (or leave it empty)
2. Verify you're using **Delegated permissions** (not Application permissions) in Azure Portal
3. Check that `Mail.Send` is listed under "Delegated permissions"
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

### "Failed to create device flow"

**Possible causes:**
- Invalid Client ID
- Network connectivity issues
- Azure app registration issues

**Solutions:**
1. Verify your `client_id` is correct in the config file
2. Check your internet connection
3. Verify your Azure app registration is set up correctly
4. Make sure you selected "Accounts in any organizational directory and personal Microsoft accounts" during registration

## Security Notes

- **Client ID is not secret**: The Client ID is not sensitive - it's safe to have in your config file
- **No client secret needed**: Personal accounts use device code flow, which doesn't require a client secret
- **Token cache**: Access tokens are cached in `~/.mailforward_token_cache.json` - this file is automatically managed by the script
- **Token refresh**: Tokens are automatically refreshed when they expire - you don't need to re-authenticate manually
- **Keep config secure**: While the Client ID isn't secret, keep your config file protected (`chmod 600`)

## Log File

The script logs to `~/.mailforward.log`. Check this file if you encounter any issues:
```bash
tail -f ~/.mailforward.log
```
