#!/usr/bin/env python3
"""
Mail Forwarder - Forwards system mail from Unix mail spool to email address.
Runs quietly in the background monitoring the mail spool file.
"""

import os
import sys
import time
import smtplib
import email
import email.utils
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
import configparser
import logging
import signal
import atexit
import json
import base64

# Try to import OAuth2 libraries
try:
    import msal
    import requests
    OAUTH2_AVAILABLE = True
except ImportError:
    OAUTH2_AVAILABLE = False

# Configure logging
LOG_FILE = os.path.expanduser("~/.mailforward.log")

def setup_logging(quiet=False):
    """Setup logging handlers."""
    handlers = [logging.FileHandler(LOG_FILE)]
    if not quiet:
        handlers.append(logging.StreamHandler(sys.stderr))
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=handlers,
        force=True
    )

setup_logging()
logger = logging.getLogger(__name__)

CONFIG_FILE = os.path.expanduser("~/.mailforwardrc")
PID_FILE = os.path.expanduser("~/.mailforward.pid")
TOKEN_CACHE_FILE = os.path.expanduser("~/.mailforward_token_cache.json")

class MailForwarder:
    def __init__(self, config_file):
        self.config_file = config_file
        self.config = self.load_config()
        self.mail_spool = self.config.get('mail', 'spool_file', fallback=None)
        self.last_position = 0
        self.running = True
        self.use_oauth2 = self.config.getboolean('oauth2', 'enabled', fallback=False)
        self.delete_after_forward = self.config.getboolean('mail', 'delete_after_forward', fallback=True)
        
        # Validate mail spool exists
        if not self.mail_spool or not os.path.exists(self.mail_spool):
            logger.error(f"Mail spool file not found: {self.mail_spool}")
            sys.exit(1)
        
        # Initialize last position
        self.last_position = os.path.getsize(self.mail_spool)
        
        # Check OAuth2 availability
        if self.use_oauth2 and not OAUTH2_AVAILABLE:
            logger.error("OAuth2 is enabled but required libraries are not installed.")
            logger.error("Please install: pip3 install msal requests")
            sys.exit(1)
        
        # Setup signal handlers
        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGINT, self.signal_handler)
    
    def load_config(self):
        """Load configuration from dotfile."""
        config = configparser.ConfigParser()
        if not os.path.exists(self.config_file):
            logger.error(f"Configuration file not found: {self.config_file}")
            logger.error("Please create the configuration file first.")
            sys.exit(1)
        
        config.read(self.config_file)
        return config
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        logger.info("Received shutdown signal, exiting...")
        self.running = False
    
    def get_oauth2_token(self):
        """Get OAuth2 access token using MSAL with delegated permissions."""
        if not OAUTH2_AVAILABLE:
            logger.error("OAuth2 libraries (msal, requests) are not installed. Run: pip3 install msal requests")
            return None
        
        client_id = self.config.get('oauth2', 'client_id', fallback=None)
        if not client_id or client_id == 'YOUR_CLIENT_ID_HERE':
            logger.error("OAuth2 client_id is not configured in ~/.mailforwardrc")
            return None
        
        client_secret = self.config.get('oauth2', 'client_secret', fallback=None)
        # Strip whitespace and check if it's actually empty or placeholder
        if client_secret:
            client_secret = client_secret.strip()
        if not client_secret or client_secret == '' or client_secret == 'YOUR_CLIENT_SECRET_HERE':
            client_secret = None
        
        tenant_id = self.config.get('oauth2', 'tenant_id', fallback='common')
        authority = f"https://login.microsoftonline.com/{tenant_id}"
        
        # Create token cache
        cache = msal.SerializableTokenCache()
        if os.path.exists(TOKEN_CACHE_FILE):
            try:
                with open(TOKEN_CACHE_FILE, 'r') as f:
                    cache.deserialize(f.read())
            except:
                pass
        
        # Determine which flow to use based on whether we have a client secret
        # For personal accounts, we use PublicClientApplication (no secret needed)
        # For work accounts, we can use ConfidentialClientApplication
        
        use_public_client = client_secret is None
        
        if use_public_client:
            logger.debug("Using public client (device code flow) for personal account")
        else:
            logger.debug("Using confidential client (client credentials flow) for work account")
        
        if use_public_client:
            # Use public client (device code flow) for personal accounts
            app = msal.PublicClientApplication(
                client_id,
                authority=authority,
                token_cache=cache
            )
        else:
            # Use confidential client (client credentials) for work accounts
            app = msal.ConfidentialClientApplication(
                client_id,
                authority=authority,
                client_credential=client_secret,
                token_cache=cache
            )
        
        # Try to get token from cache first
        accounts = app.get_accounts()
        result = None
        
        if accounts:
            # Try silent token acquisition with delegated permissions
            try:
                result = app.acquire_token_silent(
                    scopes=["https://graph.microsoft.com/Mail.Send"],
                    account=accounts[0]
                )
                # Check if we got a valid token
                if result and "access_token" in result:
                    logger.debug("Using cached access token")
            except Exception as e:
                logger.debug(f"Silent token acquisition failed: {e}")
                result = None
        
        # If silent acquisition failed or returned no token, try different flows
        if not result or "access_token" not in result:
            if use_public_client:
                # Use device code flow for personal accounts
                logger.info("No valid token found. Starting device code authentication...")
                try:
                    flow = app.initiate_device_flow(scopes=["https://graph.microsoft.com/Mail.Send"])
                    if "user_code" not in flow:
                        error_msg = flow.get("error_description", flow.get("error", "Unknown error"))
                        logger.error(f"Failed to create device flow: {error_msg}")
                        return None
                    
                    logger.info("=" * 60)
                    logger.info("AUTHENTICATION REQUIRED")
                    logger.info("=" * 60)
                    logger.info(f"To sign in, open this URL in your browser:")
                    logger.info(f"  {flow['verification_uri']}")
                    logger.info(f"")
                    logger.info(f"Enter this code: {flow['user_code']}")
                    logger.info("")
                    logger.info("Waiting for you to complete the sign-in...")
                    logger.info("(This may take up to 15 minutes)")
                    logger.info("=" * 60)
                    
                    result = app.acquire_token_by_device_flow(flow)
                except Exception as e:
                    logger.error(f"Device code flow failed: {e}")
                    return None
            else:
                # Try client credentials flow for work accounts
                try:
                    result = app.acquire_token_for_client(
                        scopes=["https://graph.microsoft.com/.default"]
                    )
                except Exception as e:
                    error_msg = str(e)
                    logger.error(f"Client credentials flow failed: {error_msg}")
                    if "AADSTS53003" in error_msg or "Conditional Access" in error_msg:
                        logger.error("=" * 60)
                        logger.error("CONDITIONAL ACCESS POLICY BLOCKING AUTHENTICATION")
                        logger.error("=" * 60)
                        logger.error("For personal Microsoft accounts (Outlook.com, Hotmail.com):")
                        logger.error("1. Remove or comment out 'client_secret' in ~/.mailforwardrc")
                        logger.error("2. Make sure you're using 'Delegated permissions' (not Application)")
                        logger.error("3. The script will use device code flow instead")
                        logger.error("=" * 60)
                    else:
                        logger.error("For personal Microsoft accounts, remove client_secret and use device code flow")
                    return None
        
        # Save token cache
        if cache.has_state_changed:
            try:
                with open(TOKEN_CACHE_FILE, 'w') as f:
                    f.write(cache.serialize())
            except Exception as e:
                logger.warning(f"Failed to save token cache: {e}")
        
        if "access_token" in result:
            return result["access_token"]
        else:
            error = result.get("error_description", result.get("error", "Unknown error"))
            logger.error(f"Failed to acquire OAuth2 token: {error}")
            if "AADSTS53003" in error or "Conditional Access" in error:
                logger.error("Conditional Access policy is blocking authentication.")
                logger.error("For personal accounts, use delegated permissions with device code flow.")
                logger.error("Remove client_secret from config and use device code flow instead.")
            return None
    
    def send_via_graph_api(self, forward_msg, original_from):
        """Send email via Microsoft Graph API using OAuth2."""
        access_token = self.get_oauth2_token()
        if not access_token:
            return False
        
        # Get email address to send from
        from_email = self.config.get('oauth2', 'from_email', fallback=self.config.get('mail', 'forward_to'))
        to_email = self.config.get('mail', 'forward_to')
        
        # Extract message body
        if forward_msg.is_multipart():
            body_content = ""
            for part in forward_msg.walk():
                if part.get_content_type() == "text/plain":
                    body_content = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    break
        else:
            body_content = forward_msg.get_payload(decode=True).decode('utf-8', errors='ignore') if forward_msg.get_payload() else ""
        
        # Prepare email message for Graph API
        email_message = {
            "message": {
                "subject": forward_msg['Subject'],
                "body": {
                    "contentType": "Text",
                    "content": body_content
                },
                "toRecipients": [
                    {
                        "emailAddress": {
                            "address": to_email
                        }
                    }
                ]
            }
        }
        
        # Send via Graph API
        endpoint = f"https://graph.microsoft.com/v1.0/users/{from_email}/sendMail"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
        
        try:
            response = requests.post(endpoint, headers=headers, json=email_message, timeout=30)
            if response.status_code == 202:
                logger.info(f"Successfully forwarded message from {original_from} via Graph API")
                return True
            else:
                logger.error(f"Graph API error: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            logger.error(f"Error sending via Graph API: {e}")
            return False
    
    def parse_mail_messages(self, new_content):
        """Parse new mail messages from the Unix mail spool format."""
        messages = []
        current_message = []
        
        # Unix mail spool format: messages start with "From " line
        for line in new_content.split('\n'):
            # Check if this is a new message delimiter (starts with "From " and has email-like format)
            if line.startswith('From ') and '@' in line and len(line.split()) >= 2:
                if current_message:
                    messages.append('\n'.join(current_message))
                current_message = [line]
            else:
                if current_message or line.strip():  # Include content even if no From line yet
                    current_message.append(line)
        
        if current_message:
            messages.append('\n'.join(current_message))
        
        return messages
    
    def forward_message(self, message_content):
        """Forward a single mail message via SMTP."""
        try:
            # Parse the Unix mail spool message
            # Format: "From sender@domain date" followed by headers and body
            lines = message_content.split('\n')
            if not lines:
                return False
            
            # Extract From line (first line)
            from_line = lines[0] if lines[0].startswith('From ') else ''
            original_from = from_line.split()[1] if len(from_line.split()) > 1 else 'Unknown'
            
            # Try to parse as email message (may have headers)
            try:
                msg = email.message_from_string('\n'.join(lines[1:]) if len(lines) > 1 else message_content)
                subject = msg.get('Subject', 'No Subject')
                date = msg.get('Date', 'Unknown')
                to = msg.get('To', 'Unknown')
                
                # Get body
                if msg.is_multipart():
                    body = ""
                    for part in msg.walk():
                        if part.get_content_type() == "text/plain":
                            body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                            break
                else:
                    body = msg.get_payload(decode=True).decode('utf-8', errors='ignore') if msg.get_payload() else '\n'.join(lines[1:])
            except:
                # Fallback: treat as plain text
                subject = 'System Mail'
                date = 'Unknown'
                to = 'Unknown'
                body = '\n'.join(lines[1:]) if len(lines) > 1 else message_content
            
            # Create message content
            original_text = f"Original From: {original_from}\n"
            original_text += f"Original To: {to}\n"
            original_text += f"Original Date: {date}\n"
            original_text += f"\n--- Original Message ---\n\n"
            original_text += body
            
            # Use OAuth2/Graph API if enabled, otherwise use SMTP
            if self.use_oauth2:
                # Send via Microsoft Graph API
                forward_msg = MIMEMultipart()
                forward_msg['Subject'] = f"[Forwarded] {subject}"
                forward_msg.attach(MIMEText(original_text, 'plain'))
                return self.send_via_graph_api(forward_msg, original_from)
            
            # Send via SMTP (legacy method)
            forward_msg = MIMEMultipart()
            forward_msg['From'] = self.config.get('smtp', 'from_email')
            forward_msg['To'] = self.config.get('mail', 'forward_to')
            forward_msg['Subject'] = f"[Forwarded] {subject}"
            forward_msg.attach(MIMEText(original_text, 'plain'))
            
            # Send via SMTP (only reached if OAuth2 is not enabled)
            smtp_server = self.config.get('smtp', 'server')
            smtp_port = self.config.getint('smtp', 'port')
            smtp_user = self.config.get('smtp', 'username')
            smtp_password = self.config.get('smtp', 'password', fallback='').strip()  # Remove any whitespace
            use_tls = self.config.getboolean('smtp', 'use_tls', fallback=True)
            
            # Validate password is set (only check if not using OAuth2)
            if not smtp_password or smtp_password == 'YOUR_APP_PASSWORD_HERE':
                logger.error("SMTP password not configured. Please set your app password in ~/.mailforwardrc")
                logger.error("Alternatively, enable OAuth2 authentication (see OAUTH2_SETUP.md)")
                return False
            
            # Connect to SMTP server
            server = smtplib.SMTP(smtp_server, smtp_port, timeout=30)
            server.set_debuglevel(0)  # Set to 1 for debugging
            
            try:
                # Send EHLO and start TLS if needed
                server.ehlo()
                if use_tls:
                    server.starttls()
                    server.ehlo()  # Re-identify after TLS
                
                # Authenticate
                server.login(smtp_user, smtp_password)
                
                # Send message
                server.send_message(forward_msg)
                
                logger.info(f"Successfully forwarded message from {original_from}")
                return True
                
            except smtplib.SMTPAuthenticationError as e:
                error_msg = str(e)
                logger.error(f"SMTP Authentication failed: {error_msg}")
                logger.error("Please verify:")
                logger.error("  1. Your app password is correct (no spaces)")
                logger.error("  2. Two-factor authentication is enabled on your account")
                logger.error("  3. You're using an app password, not your regular password")
                return False
            except smtplib.SMTPException as e:
                logger.error(f"SMTP error: {e}")
                return False
            finally:
                try:
                    server.quit()
                except:
                    pass
            
        except Exception as e:
            logger.error(f"Error forwarding message: {e}")
            logger.error(f"Error type: {type(e).__name__}")
            return False
    
    def delete_from_spool(self, message_content):
        """Remove a message from the mail spool file."""
        try:
            # Read the entire spool file
            with open(self.mail_spool, 'r') as f:
                spool_content = f.read()
            
            # Parse all messages from the spool
            all_messages = self.parse_mail_messages(spool_content)
            
            # Find and remove the message that matches
            # We'll match by the "From " line which should be unique
            lines = message_content.split('\n')
            if not lines or not lines[0].startswith('From '):
                logger.warning("Invalid message format for deletion")
                return False
            
            target_from_line = lines[0]
            
            # Find the message to remove
            filtered_messages = []
            found = False
            for msg in all_messages:
                msg_lines = msg.split('\n')
                if msg_lines and msg_lines[0] == target_from_line:
                    # This is the message to delete - skip it
                    found = True
                    logger.debug("Found message to delete in spool")
                else:
                    # Keep this message
                    filtered_messages.append(msg)
            
            if not found:
                logger.warning("Message not found in spool file for deletion")
                return False
            
            # Reconstruct the spool file with remaining messages
            new_spool_content = '\n'.join(filtered_messages)
            if new_spool_content and not new_spool_content.endswith('\n'):
                new_spool_content += '\n'
            
            # Write back the modified spool file
            with open(self.mail_spool, 'w') as f:
                f.write(new_spool_content)
            
            logger.debug("Successfully removed message from spool file")
            return True
            
        except Exception as e:
            logger.error(f"Error deleting message from spool: {e}")
            return False
    
    def check_and_forward(self):
        """Check for new mail and forward it."""
        try:
            current_size = os.path.getsize(self.mail_spool)
            
            if current_size > self.last_position:
                # New mail detected
                with open(self.mail_spool, 'r') as f:
                    f.seek(self.last_position)
                    new_content = f.read()
                
                messages = self.parse_mail_messages(new_content)
                
                for message in messages:
                    if message.strip():
                        # Forward the message
                        success = self.forward_message(message)
                        if success:
                            # Delete from spool after successful forwarding (if enabled)
                            if self.delete_after_forward:
                                delete_success = self.delete_from_spool(message)
                                if delete_success:
                                    logger.info("Message forwarded and removed from spool")
                                else:
                                    logger.warning("Message forwarded but could not be removed from spool")
                            else:
                                logger.info("Message forwarded (keeping in spool as configured)")
                        else:
                            logger.warning("Message forwarding failed, keeping in spool")
                
                # Update last position to current size (may have changed due to deletions)
                self.last_position = os.path.getsize(self.mail_spool)
            elif current_size < self.last_position:
                # Spool file got smaller (messages were deleted externally)
                logger.info("Spool file size decreased, resetting position")
                self.last_position = current_size
                
        except Exception as e:
            logger.error(f"Error checking mail: {e}")
    
    def run(self):
        """Main loop - monitor mail spool and forward new messages."""
        check_interval = self.config.getint('mail', 'check_interval', fallback=60)
        
        logger.info(f"Starting mail forwarder, monitoring {self.mail_spool}")
        logger.info(f"Forwarding to: {self.config.get('mail', 'forward_to')}")
        logger.info(f"Check interval: {check_interval} seconds")
        
        # If using OAuth2, validate configuration and test authentication
        if self.use_oauth2:
            logger.info("OAuth2 authentication enabled")
            # Check if client_secret is set (should be empty for personal accounts)
            client_secret = self.config.get('oauth2', 'client_secret', fallback=None)
            if client_secret and client_secret.strip() and client_secret.strip() != 'YOUR_CLIENT_SECRET_HERE':
                logger.warning("client_secret is set - this will use client credentials flow")
                logger.warning("For personal accounts, remove client_secret to use device code flow")
            # Try to get a token to validate configuration
            token = self.get_oauth2_token()
            if token:
                logger.info("OAuth2 authentication successful")
            else:
                logger.warning("OAuth2 authentication failed - will retry when forwarding mail")
        
        while self.running:
            try:
                self.check_and_forward()
                # Sleep in smaller increments to be more responsive to signals
                for _ in range(check_interval):
                    if not self.running:
                        break
                    time.sleep(1)
            except KeyboardInterrupt:
                logger.info("Interrupted by user")
                self.running = False
                break
            except Exception as e:
                logger.error(f"Unexpected error: {e}")
                # Sleep in smaller increments
                for _ in range(min(check_interval, 10)):
                    if not self.running:
                        break
                    time.sleep(1)
        
        logger.info("Mail forwarder stopped")

def daemonize():
    """Fork the process to run as a daemon."""
    try:
        pid = os.fork()
        if pid > 0:
            # Parent process - exit
            sys.exit(0)
    except OSError as e:
        logger.error(f"Fork failed: {e}")
        sys.exit(1)
    
    # Decouple from parent environment
    os.chdir("/")
    os.setsid()
    os.umask(0)
    
    # Second fork
    try:
        pid = os.fork()
        if pid > 0:
            # Parent process - exit
            sys.exit(0)
    except OSError as e:
        logger.error(f"Second fork failed: {e}")
        sys.exit(1)
    
    # Write PID file
    with open(PID_FILE, 'w') as f:
        f.write(str(os.getpid()))
    
    # Redirect standard file descriptors
    sys.stdout.flush()
    sys.stderr.flush()
    si = open(os.devnull, 'r')
    so = open(os.devnull, 'a+')
    se = open(os.devnull, 'a+')
    os.dup2(si.fileno(), sys.stdin.fileno())
    os.dup2(so.fileno(), sys.stdout.fileno())
    os.dup2(se.fileno(), sys.stderr.fileno())
    
    # Register cleanup function
    def cleanup():
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)
    
    atexit.register(cleanup)

def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Forward system mail to email address')
    parser.add_argument('-d', '--daemon', action='store_true', 
                       help='Run as background daemon')
    parser.add_argument('-c', '--config', default=CONFIG_FILE,
                       help=f'Configuration file (default: {CONFIG_FILE})')
    parser.add_argument('--stop', action='store_true',
                       help='Stop the running daemon')
    
    args = parser.parse_args()
    
    # Handle stop command
    if args.stop:
        # Use module-level logger
        stop_logger = logging.getLogger(__name__)
        if os.path.exists(PID_FILE):
            with open(PID_FILE, 'r') as f:
                pid = int(f.read().strip())
            try:
                os.kill(pid, signal.SIGTERM)
                stop_logger.info(f"Stopped daemon (PID: {pid})")
                time.sleep(1)  # Give it time to cleanup
                if os.path.exists(PID_FILE):
                    os.remove(PID_FILE)
            except ProcessLookupError:
                stop_logger.error("Daemon not running")
                if os.path.exists(PID_FILE):
                    os.remove(PID_FILE)
        else:
            stop_logger.error("No PID file found. Daemon may not be running.")
        return
    
    if args.daemon:
        # Validate config before daemonizing
        forwarder = MailForwarder(args.config)
        # Run as daemon
        daemonize()
        # Reconfigure logging to be quiet (file only) after daemonizing
        setup_logging(quiet=True)
        # Recreate logger after reconfiguring
        logger = logging.getLogger(__name__)
        # Recreate forwarder to get fresh logger
        forwarder = MailForwarder(args.config)
        forwarder.run()
    else:
        # Run in foreground
        forwarder = MailForwarder(args.config)
        forwarder.run()

if __name__ == '__main__':
    main()

