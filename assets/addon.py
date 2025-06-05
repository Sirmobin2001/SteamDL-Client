from mitmproxy import ctx
from time import time
import os
import appdirs # New import

# --- Start of App Configuration for User Data ---
APP_NAME = "SteamDL"      # Must match main.py
APP_AUTHOR = "LostAct"  # Must match main.py
user_data_dir = appdirs.user_data_dir(APP_NAME, APP_AUTHOR)
RX_FILE_PATH = os.path.join(user_data_dir, 'rx.txt')
# --- End of App Configuration for User Data ---

class SteamDL:
    def load(self, loader):
        loader.add_option(name="token",typespec=str,default="",help="User Token")
        mode_string = ctx.options.mode[0] # Assuming mode is always set and is a list/tuple
        domain_start = mode_string.find("//") + 2
        self.cache_domain = mode_string[domain_start:].split("@")[0]
        self.last_update_time = 0
        self.rx_bytes = 0
        
        try:
            # Ensure user_data_dir exists before trying to read from it
            if not os.path.exists(user_data_dir):
                os.makedirs(user_data_dir, exist_ok=True)
                ctx.log.info(f"Created user data directory for addon: {user_data_dir}")

            if os.path.isfile(RX_FILE_PATH):
                with open(RX_FILE_PATH, 'r', encoding='utf-8') as rx_file:
                    rx_str = rx_file.read().strip()
                    if rx_str: # Check if string is not empty
                        self.rx_bytes = int(rx_str)
            else:
                ctx.log.info(f"rx.txt not found at {RX_FILE_PATH}. Starting count from 0.")
        except ValueError:
            ctx.log.warn(f"Could not parse integer from {RX_FILE_PATH}. Resetting rx_bytes to 0.")
            self.rx_bytes = 0
        except Exception as e: # Catch other errors like permission issues
            ctx.log.error(f"Error loading rx_bytes from {RX_FILE_PATH}: {e}")
            self.rx_bytes = 0 # Default to 0 on error
        
    def requestheaders(self, flow):
        # Only act on HTTP/HTTPS flows, not TCP/UDP flows if they are ever passed through
        if flow.request.scheme in ["http", "https"]:
            # Ensure flow.request.host_header is not None
            if flow.request.host_header:
                 flow.request.headers["Real-Host"] = flow.request.host_header
            flow.request.headers["Host"] = self.cache_domain    
            if ctx.options.token: # Ensure token is not empty
                flow.request.headers["Auth-Token"] = ctx.options.token

    def responseheaders(self,flow):
        # Check if the flow has a response and it's an HTTP response
        if flow.response and flow.response.headers:
            if 200 <= flow.response.status_code < 300 and flow.request.headers.get("User-Agent") != "GamingServices":
                try:
                    content_length = int(flow.response.headers.get("Content-Length", 0))
                    self.rx_bytes += content_length
                except ValueError:
                    ctx.log.warn("Invalid Content-Length received, cannot update rx_bytes.")

            current_time = time()
            if current_time - self.last_update_time > 2: # Update every 2 seconds
                self.last_update_time = current_time
                try:
                    with open(RX_FILE_PATH, "w", encoding='utf-8') as rx_file:
                        rx_file.write(str(self.rx_bytes))
                except IOError as e:
                    ctx.log.error(f"Could not write rx_bytes to {RX_FILE_PATH}: {e}")

addons = [SteamDL()]
