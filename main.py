import sys, os, requests, json, re, subprocess, threading, multiprocessing, socket, webview, logging, time, dns.resolver, tempfile
from mitmproxy.tools.main import mitmdump

# New imports
import appdirs 
import keyring

# --- Start of App Configuration for User Data ---
APP_NAME = "SteamDL"
APP_AUTHOR = "LostAct" # Or your developer/company name
user_data_dir = appdirs.user_data_dir(APP_NAME, APP_AUTHOR)

if not os.path.exists(user_data_dir):
    os.makedirs(user_data_dir, exist_ok=True) # Ensure directory exists

KEYRING_SERVICE_NAME = "SteamDL_Client_Token" # For keyring
# --- End of App Configuration for User Data ---

# log uncaught exceptions
def log_uncaught_exceptions(exctype, value, tb):
    logging.error("Uncaught exception", exc_info=(exctype, value, tb))
sys.excepthook = log_uncaught_exceptions

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

CURRENT_VERSION = "2.2.11"
WINDOW_TITLE = f"SteamDL v{CURRENT_VERSION}"
REPO_PATH = "lostact/SteamDL-Client"

CACHE_DOMAIN = "dl.steamdl.ir"
API_DOMAIN = "api.steamdl.ir"
FILES_DOMAIN = "files.steamdl.ir"

PROXY_EXEC_PATH = resource_path('assets\\http_proxy.exe')
PROXY_ADDON_PATH = resource_path('assets\\addon.py')
INDEX_PATH = resource_path('assets\\web\\index.html')
FORM_PATH = resource_path('assets\\web\\form.html')
UPDATE_PATH = resource_path('assets\\web\\update.html')

# Updated paths for user-specific data
PREFERENCES_PATH = os.path.join(user_data_dir, 'preferences.json')
ACCOUNT_FILE_PATH = os.path.join(user_data_dir, 'account.txt') # Kept for potential migration, but keyring is preferred
RX_FILE_PATH = os.path.join(user_data_dir, 'rx.txt')


SEARCH_IP_BYTES = socket.inet_aton("127.0.0.1")
ANTI_SANCTION_TEST_DOMAIN = "www.epicgames.com"
ANTI_SANCTION_TEST_PATH = "/id/api/authenticate"

CREATE_NO_WINDOW = 0x08000000 # Constant for subprocess

def run_cmd(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True, close_fds=True, creationflags=CREATE_NO_WINDOW)
        if result.returncode != 0:
            # Log command as a string, careful with sensitive info if command contains it
            cmd_str = ' '.join(command) if isinstance(command, list) else command
            logging.error(f"Command \"{cmd_str}\" failed with code {result.returncode}. stderr: {result.stderr.strip() if result.stderr else '[empty]'}. stdout: {result.stdout.strip() if result.stdout else '[empty]'}")
    except FileNotFoundError:
        logging.error(f"Command not found: {command[0] if isinstance(command, list) else command.split()[0]}")
        return subprocess.CompletedProcess(command, -1, stdout="", stderr="Command not found.")
    except Exception as e:
        logging.error(f"Exception running command {' '.join(command) if isinstance(command, list) else command}: {e}")
        return subprocess.CompletedProcess(command, -1, stdout="", stderr=str(e))
    return result

def find_programs_listening_on_ports():
    results = []
    for port_number in [80,443]:
        # PowerShell command, ensure it's secure if port_number could be manipulated (here it's hardcoded)
        ps_command = ["powershell", "-NoProfile", "-Command", f"Get-Process -Id (Get-NetTCPConnection -LocalPort {port_number}).OwningProcess -ErrorAction SilentlyContinue"]
        result = run_cmd(ps_command)
        if result.returncode == 0 and result.stdout:
            results.append(result.stdout)
    programs = []
    for res_stdout in results:
        lines = res_stdout.splitlines()
        for line in lines:
            values = line.split()
            if len(values) >= 8: # Check based on expected output structure
                # Example expected structure: Handles SI CPU(s) WS(K) VM(M) NPM(K) Path ProcessName
                # We're interested in ProcessName, typically the last part.
                # This parsing might need adjustment based on actual PowerShell output format.
                # A more robust parsing would use specific column headers or PowerShell objects if possible.
                if values[5].isnumeric() and values[5] != "0": # Heuristic: check if 6th column is numeric (CPU or similar)
                     programs.append(values[-1]) # Assume process name is the last significant token
    return list(set(programs)) # Return unique program names

def get_active_adapter():
    disconnected_interfaces = []
    # Get disconnected interfaces
    result = run_cmd(["netsh", "interface", "show", "interface"])
    if result.returncode != 0:
        logging.error("Failed to get interface status list.")
    else:
        interface_pattern = r'\s*Enabled\s+Disconnected\s+\S+\s+(.+)'
        # Iterate over lines as finditer might be complex with multiline regex
        for line in result.stdout.splitlines():
            match = re.search(interface_pattern, line)
            if match:
                disconnected_interfaces.append(match.group(1).strip())

    # Get network configuration
    result = run_cmd(["netsh", "interface", "ipv4", "show", "config"])
    if result.returncode != 0:
        logging.error("Failed to get network configuration.")
        return None  # Explicitly return None

    interface_pattern = r"Configuration for interface \"([^\"]+)\"\s*\n(?:[^\n]*\n)*?\s*Default Gateway:\s+([\d\.]+)\s*\n(?:[^\n]*\n)*?\s*Gateway Metric:\s+(\d+)"
    interfaces = re.finditer(interface_pattern, result.stdout, re.MULTILINE)
    
    active_adapter = None
    minimum_metric = float('inf') # Use float('inf') for minimum comparison

    for interface_match in interfaces: # Renamed 'interface' to 'interface_match' to avoid conflict
        adapter_name = interface_match.group(1).strip()
        gateway = interface_match.group(2).strip()
        metric_str = interface_match.group(3).strip()
        
        if gateway and gateway != "0.0.0.0" and adapter_name not in disconnected_interfaces:
            try:
                metric = int(metric_str)
                if metric < minimum_metric:
                    active_adapter = adapter_name
                    minimum_metric = metric
            except ValueError:
                logging.warning(f"Could not parse metric '{metric_str}' for adapter {adapter_name}")

    if active_adapter:
        return active_adapter
    else:
        logging.error("No active adapter with an internet connection found.")
        return None


def get_dns_settings(adapter_name):
    if not adapter_name:
        return []
    dns_servers = []
    try:
        result = run_cmd(["netsh", "interface", "ipv4", "show", "dnsservers", adapter_name])
        if result.returncode != 0:
            logging.error(f"Failed to get DNS settings for adapter: {adapter_name}. Output: {result.stderr}")
            return [] # Return empty list on failure
        
        # Look for statically configured DNS servers
        # This pattern might need adjustment based on localization of netsh output
        dns_pattern = r"Statically Configured DNS Servers:\s*\n\s*(\d+\.\d+\.\d+\.\d+)(?:\s*\n\s*(\d+\.\d+\.\d+\.\d+))?"
        match = re.search(dns_pattern, result.stdout, re.MULTILINE)
        if match:
            dns_servers.append(match.group(1))
            if match.group(2): # If secondary DNS is present
                dns_servers.append(match.group(2))
        elif "DNS servers configured through DHCP" in result.stdout or "none" in result.stdout.lower(): # Check if DHCP or none
             logging.info(f"DNS for adapter {adapter_name} is configured via DHCP or not set.")
        else: # Fallback for unexpected output, try to find any IP
            dns_pattern_fallback = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
            found_ips = re.findall(dns_pattern_fallback, result.stdout)
            # Filter out common non-DNS IPs if necessary, or just take the first ones that look like DNS
            if found_ips:
                dns_servers = found_ips[:2] # Take at most two
                logging.warning(f"Used fallback DNS parsing for adapter {adapter_name}. Found: {dns_servers}")


    except Exception as e: # Catch any exception during the process
        logging.error(f"Exception getting DNS settings for adapter {adapter_name}: {e}")
        
    return dns_servers


def set_dns_settings(adapter_name, dns_servers):
    if not adapter_name:
        logging.error("No adapter name provided to set_dns_settings.")
        return False # Indicate failure

    if not dns_servers: # Set to DHCP / Automatic
        result = run_cmd(["netsh", "interface", "ipv4", "set", "dnsservers", adapter_name, "dhcp"])
        if result.returncode != 0:
            logging.error(f"Failed to set DNS to DHCP for {adapter_name}. Error: {result.stderr}")
            return False
    else: # Set to static DNS
        result = run_cmd(["netsh", "interface", "ipv4", "set", "dnsservers", adapter_name, "static", dns_servers[0], "primary"])
        if result.returncode != 0:
            logging.error(f"Failed to set primary DNS {dns_servers[0]} for {adapter_name}. Error: {result.stderr}")
            return False
        if len(dns_servers) > 1:
            result = run_cmd(["netsh", "interface", "ipv4", "add", "dnsservers", adapter_name, dns_servers[1], "index=2"])
            if result.returncode != 0:
                logging.warning(f"Failed to set secondary DNS {dns_servers[1]} for {adapter_name}. Error: {result.stderr}")
                # Continue even if secondary fails, primary might be enough

    flush_result = run_cmd(["ipconfig", "/flushdns"])
    if flush_result.returncode != 0:
        logging.warning(f"ipconfig /flushdns failed. Error: {flush_result.stderr}")
    return True # Indicate success


def cleanup_temp_folders():
    temp_dir = os.environ.get('TEMP')
    if temp_dir and os.path.isdir(temp_dir): # Check if temp_dir exists
        for folder_name in os.listdir(temp_dir):
            folder_path = os.path.join(temp_dir, folder_name)
            # Check if 'EBWebView' is a subdirectory within folder_path
            # This needs more robust checking. The original code checked if 'EBWebView' was IN os.listdir(folder_path)
            # Assuming the intent was to find folders like "some_guid.tmp" which contain an "EBWebView" subfolder.
            if os.path.isdir(folder_path):
                try:
                    # A more direct check might be for folders created by Edge WebView2
                    # Example: if folder_name.startswith("msedgewebview2.") or "EBWebView" in folder_name for broader match
                    # The original check: "EBWebView" in os.listdir(folder_path) - this is slow and error-prone if folder_path is not accessible.
                    # Let's assume folders named like Score* or msedgewebview* are candidates.
                    if folder_name.startswith("ScopedWebView") or "EBWebView" in folder_name or "msedgewebview" in folder_name.lower():
                        # More robust: check if folder_path + "\\EBWebView" exists
                        ebwebview_subdir = os.path.join(folder_path, "EBWebView")
                        if os.path.isdir(ebwebview_subdir):
                            logging.info(f"Attempting to remove WebView temp folder: {folder_path}")
                            # Using PowerShell's Remove-Item for robustness with locked files
                            run_cmd(["powershell", "-NoProfile", "-Command", f"Remove-Item -Recurse -Force '{folder_path}' -ErrorAction SilentlyContinue"])
                except Exception as e: # Catch PermissionError or other OS errors
                    logging.info(f"Failed to inspect or remove webview temp files in {folder_path}: {e}")


def start_proxy(mitm_args):
    # Configure logging specifically for the proxy process if needed,
    # or ensure the main process's logging is used.
    # For multiprocessing, each process might need its own logging setup if not handled by a queue.
    # The existing main process logging might not capture this directly.
    # Simpler: mitmdump might log to console or its own files based on its args.
    # The current logging setup in main() is for the main app log.
    # Proxy logs are set to 'proxy.log' inside start_proxy.
    proxy_log_path = os.path.join(user_data_dir, 'proxy.log') # Use user_data_dir
    logging.basicConfig(
        level=logging.WARN,
        format='%(asctime)s %(levelname)s %(message)s',
        handlers=[
            logging.FileHandler(proxy_log_path)
        ]
    )
    try:
        mitmdump(args=mitm_args)
    except Exception as e:
        logging.error(f"mitmdump encountered an error: {e}")


def check_for_update(beta=False):
    try:
        url = f"https://api.github.com/repos/{REPO_PATH}/releases"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        releases = response.json()
        
        latest_release_info = None

        for release in releases:
            if not release["prerelease"] or beta: # If beta is true, accept prereleases; otherwise only stable
                if beta and release["prerelease"]: # Explicitly take the latest beta if beta is true
                     latest_release_info = release
                     break
                elif not release["prerelease"]: # Take the latest stable
                     latest_release_info = release
                     break
        
        if not latest_release_info and beta and releases: # Fallback for beta: if no explicit prerelease found, take latest overall
            latest_release_info = releases[0]


        if latest_release_info:
            latest_version = latest_release_info["tag_name"]
            download_url = None
            for asset in latest_release_info["assets"]:
                if asset["name"].endswith(".msi"): # Assuming installer is .msi
                    download_url = asset["browser_download_url"]
                    break
            
            if download_url:
                # Compare versions (e.g., using packaging.version)
                try:
                    from packaging.version import parse as parse_version
                    is_newer = parse_version(latest_version) > parse_version(CURRENT_VERSION)
                except ImportError: # Fallback to tuple comparison if packaging is not available
                    logging.warning("Python 'packaging' module not found, using tuple comparison for versions.")
                    current_tuple = tuple(map(int, (CURRENT_VERSION.split("."))))
                    latest_tuple = tuple(map(int, (latest_version.split("."))))
                    is_newer = latest_tuple > current_tuple

                logging.info(f"Current version: {CURRENT_VERSION} - Latest version found: {latest_version} (URL: {download_url})")
                if is_newer:
                    return True, download_url
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to check for update (network error): {e}")
    except Exception as e:
        logging.error(f"Failed to check for update (general error): {e}")
    return False, None


def apply_update(download_url, progress_callback):
    installer_name = "steamdl_installer.msi"
    temp_path = tempfile.gettempdir() # Use system temp for downloads
    installer_path = os.path.join(temp_path, installer_name)
    
    try:
        logging.info(f"Downloading update from {download_url} to {installer_path}")
        response = requests.get(download_url, allow_redirects=True, stream=True, timeout=30) # Added timeout
        response.raise_for_status()
        total_size = response.headers.get('content-length')
        
        downloaded_size = 0
        if total_size:
            total_size = int(total_size)
            with open(installer_path, "wb") as installer_file:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk: # filter out keep-alive new chunks
                        downloaded_size += len(chunk)
                        installer_file.write(chunk)
                        if total_size > 0: # Avoid division by zero if content-length is missing/zero
                            done_percent = int(100 * downloaded_size / total_size)
                            progress_callback(done_percent)
        else: # If no content-length, we can't show progress accurately
            logging.warning("Content-Length header missing, cannot show download progress accurately.")
            with open(installer_path, "wb") as installer_file:
                installer_file.write(response.content)
            progress_callback(100) # Assume 100% if no size

        logging.info("Update downloaded successfully.")
        # Ensure installer_path is quoted if it can contain spaces, though Popen with list args handles it.
        subprocess.Popen(["msiexec", "/i", installer_path, "/qb", "REINSTALL=ALL", "REINSTALLMODE=vomus"], # Added common MSI flags for upgrade
                         close_fds=True, creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP)
        logging.info("Update process launched. Exiting application.")
        os._exit(0) # Exit current app to allow update
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to download update: {e}")
    except IOError as e:
        logging.error(f"Failed to write installer file: {e}")
    except Exception as e:
        logging.error(f"Failed to apply update: {e}")
    return None # Explicitly return None on failure


class Api:
    def __init__(self):
        self._window = None
        self._token = None
        self._user_data = None # To store user details from token
        self._user_username_for_keyring = "user_token" # Generic default
        self._anti_sanction_data = None

        self._cache_ip = None
        self._local_ip = None
        self._local_ip_bytes = None
        self._anti_sanction_ip = None

        self._proxy_process = None
        self._dns_running = None # For the DNS server thread
        self._running = None # For the main service (proxy + DNS system changes)
        self._health_check_thread = None
        self._dns_thread = None
        self._optimized_epicgames = None # Tri-state: None (not checked), True (optimized), False (checked, not found/failed)
        self._active_adapter_name = None
        self._dns_backup = []
        self._preferences = {"auto_connect": False, "dns_server": "automatic", "update": "latest"}
        self.load_preferences()

    def load_preferences(self):
        if os.path.isfile(PREFERENCES_PATH):
            try:
                with open(PREFERENCES_PATH, 'r', encoding='utf-8') as file:
                    new_preferences = json.load(file)
                    # Merge, ensuring all keys from default self._preferences are present
                    for key in self._preferences:
                        if key not in new_preferences:
                            new_preferences[key] = self._preferences[key] # Add missing keys with default values
                    self._preferences = new_preferences
            except json.JSONDecodeError as e:
                logging.error(f"Error decoding preferences JSON from {PREFERENCES_PATH}: {e}")
                # Optionally, backup corrupted file and start with defaults
            except Exception as e:
                logging.error(f"Error loading preferences from {PREFERENCES_PATH}: {e}")
        else:
            logging.info(f"Preferences file not found at {PREFERENCES_PATH}. Using defaults and attempting to save.")
            self.save_preferences() # Save defaults if file doesn't exist

    def get_preferences(self):
        return self._preferences

    def save_preferences(self):
        try:
            with open(PREFERENCES_PATH, 'w', encoding='utf-8') as file:
                json.dump(self._preferences, file, indent=4)
        except IOError as e:
            logging.error(f"Error saving preferences to {PREFERENCES_PATH} (IOError): {e}")
        except Exception as e:
            logging.error(f"Error saving preferences to {PREFERENCES_PATH}: {e}")

    def is_in_startup(self):
        try:
            # Querying the task. /FO LIST provides more parsable output.
            result = run_cmd(["schtasks", "/Query", "/TN", "steamdl", "/FO", "LIST"])
            # A successful query for an existing task returns 0.
            # Check if stdout contains task information, not just empty.
            if result.returncode == 0 and "TaskName:" in result.stdout:
                return True
            # If task not found, schtasks might return 1 and specific error in stderr/stdout.
            elif result.returncode == 1 and ("not found" in result.stderr.lower() or "not found" in result.stdout.lower()):
                 return False
            else: # Other errors
                logging.warning(f"schtasks /Query returned code {result.returncode}. Assuming not in startup. stderr: {result.stderr}")
                return False
        except Exception as e:
            logging.error(f"Error checking startup status: {e}")
            return False

    def add_to_startup(self):
        try:
            executable_path = sys.executable
            working_dir = os.path.dirname(executable_path)
            
            template_path = resource_path('assets/startup_template.xml')
            if not os.path.exists(template_path):
                logging.error(f"Startup template not found at {template_path}")
                return False

            with open(template_path, 'r', encoding='utf-8') as f:
                template_content = f.read()
            
            concrete_xml_content = template_content.replace('%EXECUTABLE_PATH%', executable_path)
            concrete_xml_content = concrete_xml_content.replace('%WORKING_DIRECTORY%', working_dir)
            
            # Use a temporary file in user_data_dir for schtasks XML
            temp_xml_path = os.path.join(user_data_dir, "steamdl_task_temp.xml")
            with open(temp_xml_path, 'w', encoding='utf-16') as tmp_xml_file: # schtasks often prefers UTF-16 for /XML
                tmp_xml_file.write(concrete_xml_content)
            
            # Delete existing task first to ensure clean creation or update
            run_cmd(["schtasks", "/Delete", "/TN", "steamdl", "/F"]) # /F to suppress confirmation if not found
            
            result = run_cmd(["schtasks", "/Create", "/TN", "steamdl", "/XML", temp_xml_path, "/F"])
            
            if os.path.exists(temp_xml_path): # Clean up temp file
                try:
                    os.remove(temp_xml_path)
                except OSError as e:
                    logging.warning(f"Could not remove temporary startup XML {temp_xml_path}: {e}")

            if result.returncode == 0:
                logging.info("Successfully added to startup.")
                return True
            else:
                logging.error(f"Failed to add to startup. schtasks /Create output: {result.stdout} {result.stderr}")
                return False
        except Exception as e:
            logging.error(f"Exception adding to startup: {e}")
            return False

    def remove_from_startup(self):
        try:
            result = run_cmd(["schtasks", "/Delete", "/TN", "steamdl", "/F"])
            if result.returncode == 0:
                logging.info("Successfully removed from startup.")
                return True
            # Check if "task does not exist" type of error, which is also a success for removal
            elif result.returncode == 1 and ("not found" in result.stderr.lower() or "did not exist" in result.stderr.lower()):
                logging.info("Task was not in startup, removal successful (no action needed).")
                return True
            else:
                logging.error(f"Failed to remove from startup. schtasks /Delete code: {result.returncode}, stderr: {result.stderr}")
                return False
        except Exception as e: # Catch any other exception
            logging.error(f"Error removing from startup: {e}")
            return False


    def show_port_in_use_warning(self):
        try:
            programs = find_programs_listening_on_ports()
            if programs:
                programs_list_str = "\\n".join(programs) # For JS alert
                # Ensure text is properly escaped for JS eval if it contains special chars
                text = f"The following programs may conflict with SteamDL on ports 80/443:\\n\\n{programs_list_str}\\n\\nPlease close them and try again."
                text_js_escaped = json.dumps(text) # Use json.dumps for safe JS string escaping
                if self._window:
                     self._window.evaluate_js(f"alert({text_js_escaped})")
        except Exception as e:
            logging.error(f"Error showing port in use warning: {e}")


    def optimize_epicgames(self):
        if self._optimized_epicgames is not None and self._optimized_epicgames: # Already optimized or checked
            return

        engine_file_dir = os.path.join(os.environ.get('LOCALAPPDATA', ''), "EpicGamesLauncher", "Saved", "Config", "Windows")
        if os.path.isdir(engine_file_dir):
            engine_text = "[HTTP]\nHttpTimeout=10\nHttpConnectionTimeout=10\nHttpReceiveTimeout=10\nHttpSendTimeout=10\n[Portal.BuildPatch]\nChunkDownloads=16\nChunkRetries=20\nRetryTime=0.5"
            engine_file_path = os.path.join(engine_file_dir, "Engine.ini")
            try:
                with open(engine_file_path, 'w', encoding='utf-8') as file:
                    file.write(engine_text)
                logging.info(f"Epic Games Engine.ini optimized at {engine_file_path}")
                self._optimized_epicgames = True
            except IOError as e:
                logging.error(f"Failed to write optimized Epic Games Engine.ini: {e}")
                self._optimized_epicgames = False # Mark as checked but failed
        else:
            logging.info("Epic Games Launcher installation not found, skipping optimization.")
            self._optimized_epicgames = False # Mark as checked, not found

    def get_default_interface_ip(self):
        if not self._cache_ip: # Ensure _cache_ip is set (from user data after token submission)
            logging.warning("Cache IP not set, cannot determine default interface IP this way.")
            return None
        try:
            # This method relies on the OS routing choosing the correct interface to reach _cache_ip
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(2) # Add a timeout
                s.connect((self._cache_ip, 53)) # Connect to DNS port on cache server
                ip_address = s.getsockname()[0]
            return ip_address
        except socket.timeout:
            logging.error(f"Timeout obtaining default interface IP (connecting to {self._cache_ip}:53).")
            return None
        except OSError as e: # Catch socket errors like "Network is unreachable"
            logging.error(f"OSError obtaining default interface IP (connecting to {self._cache_ip}:53): {e}")
            return None
        except Exception as e:
            logging.error(f"Generic error obtaining default interface IP: {e}")
            return None

    def get_anti_sanction_data(self):
        try:
            response = requests.get(f"https://{FILES_DOMAIN}/anti_sanction_dns.json", timeout=10)
            response.raise_for_status()
            self._anti_sanction_data = response.json() # Use response.json()
            if self._anti_sanction_data and isinstance(self._anti_sanction_data, list) and len(self._anti_sanction_data) > 0:
                 # Set default anti_sanction_ip to the first one if not set by preference later
                self._anti_sanction_ip = self._anti_sanction_data[0].get('ip')
            return self._anti_sanction_data
        except requests.exceptions.RequestException as e:
            logging.error(f"Failed to get anti-sanction data (network error): {e}")
        except json.JSONDecodeError as e:
            logging.error(f"Failed to decode anti-sanction data JSON: {e}")
        except Exception as e: # Catch other potential errors
            logging.error(f"Failed to get anti-sanction data (general error): {e}")
        return None # Return None on failure

    def change_anti_sanction(self, anti_sanction_name):
        if not self._anti_sanction_data: # Ensure data is loaded
            logging.warning("Anti-sanction data not loaded, cannot change.")
            if not self.get_anti_sanction_data(): # Attempt to load it
                 logging.error("Failed to load anti-sanction data on demand.")
                 return

        if anti_sanction_name and self._anti_sanction_data:
            found = False
            for anti_sanction_dns in self._anti_sanction_data:
                if anti_sanction_dns.get("name") == anti_sanction_name:
                    new_ip = anti_sanction_dns.get("ip")
                    if new_ip:
                        self._anti_sanction_ip = new_ip
                        self._preferences['dns_server'] = anti_sanction_name
                        self.save_preferences()
                        logging.info(f"Anti-sanction DNS changed to: {anti_sanction_name} ({self._anti_sanction_ip})")
                        found = True
                        break
                    else:
                        logging.warning(f"No IP found for anti-sanction DNS name {anti_sanction_name}")
            if not found:
                 logging.warning(f"Anti-sanction DNS name '{anti_sanction_name}' not found in data.")
        elif not anti_sanction_name and self._anti_sanction_data: # Handle case where name is cleared (e.g. "automatic" if it means fallback)
            # Decide behavior for empty anti_sanction_name, perhaps fallback to first or a default.
            # Current logic implies if name is provided, it must match.
            # If "automatic" means let test_anti_sanction decide, this function might not need to do much for "automatic".
            logging.info(f"Anti-sanction name '{anti_sanction_name}' provided; specific IP selection deferred or invalid.")


    def change_update_option(self, update_option):
        if update_option in ["off", "latest", "beta"]:
            self._preferences["update"] = update_option
            self.save_preferences()
            logging.info(f"Update option changed to: {update_option}")
        else:
            logging.warning(f"Invalid update option: {update_option}")


    def test_anti_sanction(self):
        if not self._anti_sanction_data:
            logging.warning("Anti-sanction data not loaded for testing.")
            if not self.get_anti_sanction_data():
                 logging.error("Failed to load anti-sanction data for testing.")
                 return False # Indicate failure

        custom_resolver = dns.resolver.Resolver()
        custom_resolver.timeout = 2 # Set timeout for DNS queries
        custom_resolver.lifetime = 2 # Total time for query

        successful_dns_name = None
        successful_dns_ip = None

        for anti_sanction_dns in self._anti_sanction_data:
            dns_ip = anti_sanction_dns.get("ip")
            dns_name = anti_sanction_dns.get("name")
            if not dns_ip or not dns_name:
                logging.warning(f"Skipping anti-sanction entry with missing IP or name: {anti_sanction_dns}")
                continue

            custom_resolver.nameservers = [dns_ip]
            logging.info(f"Testing DNS server: {dns_name} ({dns_ip}) for {ANTI_SANCTION_TEST_DOMAIN}")
            try:
                answers = custom_resolver.resolve(ANTI_SANCTION_TEST_DOMAIN, 'A')
                if not answers:
                    logging.warning(f"DNS server {dns_name} returned no A records for {ANTI_SANCTION_TEST_DOMAIN}.")
                    continue
                destination_ip = str(answers[0])
                
                # Test connectivity with curl
                # Ensure ANTI_SANCTION_TEST_DOMAIN and ANTI_SANCTION_TEST_PATH are safe
                url = f"https://{ANTI_SANCTION_TEST_DOMAIN}{ANTI_SANCTION_TEST_PATH}"
                # Using a list of args for run_cmd is safer
                curl_command = [
                    "curl", 
                    "--resolve", f"{ANTI_SANCTION_TEST_DOMAIN}:443:{destination_ip}",
                    url,
                    "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
                    "-f", # Fail silently (no output at all) on HTTP errors
                    "-s", # Silent or quiet mode
                    "-o", "nul" if os.name == 'nt' else "/dev/null", # Output to null
                    "--connect-timeout", "5", # Connection timeout
                    "-m", "10" # Max time
                ]
                process = run_cmd(curl_command)
                
                if process.returncode == 0:
                    logging.info(f"Successfully connected to Epic Games via {destination_ip} (resolved by {dns_name} at {dns_ip}).")
                    successful_dns_name = dns_name
                    successful_dns_ip = dns_ip # Store the successful IP
                    break # Found a working DNS
                else:
                    logging.warning(f"curl command failed for {dns_name} (IP: {destination_ip}). Code: {process.returncode}. Stderr: {process.stderr}")

            except dns.resolver.NXDOMAIN:
                logging.warning(f"DNS server {dns_name} ({dns_ip}): {ANTI_SANCTION_TEST_DOMAIN} not found (NXDOMAIN).")
            except dns.resolver.Timeout:
                logging.warning(f"DNS server {dns_name} ({dns_ip}): Timeout resolving {ANTI_SANCTION_TEST_DOMAIN}.")
            except Exception as e:
                logging.error(f"Error testing DNS server {dns_name} ({dns_ip}): {e}")
        
        if successful_dns_name:
            self.change_anti_sanction(successful_dns_name) # This will also save the preference
            # self._anti_sanction_ip is set by change_anti_sanction
            if self._window:
                self._window.evaluate_js(f"document.getElementById('dns_select').value=\"{successful_dns_name}\";")
                self._window.evaluate_js("adjustWidth(document.getElementById('dns_select'));")
            return True
        else:
            logging.error("None of the anti-sanction DNS servers worked. Falling back to the first one if available.")
            if self._anti_sanction_data and len(self._anti_sanction_data) > 0:
                fallback_dns_name = self._anti_sanction_data[0].get("name")
                if fallback_dns_name:
                    self.change_anti_sanction(fallback_dns_name)
                    if self._window:
                         self._window.evaluate_js(f"document.getElementById('dns_select').value=\"{fallback_dns_name}\";")
                         self._window.evaluate_js("adjustWidth(document.getElementById('dns_select'));")
            return False


    def process_dns_request(self, data, client_address, dns_socket):
        # This function runs in a thread, be careful with shared state access if any
        # Currently, it mainly reads self._cache_ip, self._local_ip_bytes, self._anti_sanction_ip
        try:
            # Forward to primary cache DNS
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream_socket:
                upstream_socket.settimeout(2) # Timeout for upstream DNS
                upstream_socket.sendto(data, (self._cache_ip, 53))
                response_data_bytes, _ = upstream_socket.recvfrom(1024) # Increased buffer for larger DNS responses
                response_data = bytearray(response_data_bytes)
                
                # Check if the response contains the IP to be replaced
                # Ensure SEARCH_IP_BYTES and self._local_ip_bytes are valid
                if self._local_ip_bytes and SEARCH_IP_BYTES:
                    start_index = -1
                    try: # bytearray.find can raise TypeError if item is not int or bytes-like
                        start_index = response_data.find(SEARCH_IP_BYTES)
                    except TypeError:
                        logging.warning("TypeError in response_data.find(SEARCH_IP_BYTES). Ensure SEARCH_IP_BYTES is bytes.")

                    if start_index != -1:
                        response_data[start_index : start_index + len(SEARCH_IP_BYTES)] = self._local_ip_bytes
                        response_data_bytes = bytes(response_data)
                        logging.debug(f"DNS response modified for {client_address}")
                    # If not found, and anti_sanction_ip is different, try forwarding to anti-sanction DNS
                    elif self._anti_sanction_ip and self._anti_sanction_ip != self._cache_ip:
                        logging.debug(f"Primary DNS did not contain search IP. Trying anti-sanction DNS {self._anti_sanction_ip} for {client_address}")
                        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream_socket_second:
                            upstream_socket_second.settimeout(2)
                            upstream_socket_second.sendto(data, (self._anti_sanction_ip, 53))
                            response_data_bytes, _ = upstream_socket_second.recvfrom(1024)
                else:
                    logging.warning("Local IP bytes or Search IP bytes not set, cannot modify DNS response.")
                
                dns_socket.sendto(response_data_bytes, client_address)

        except socket.timeout:
            logging.warning(f"Timeout processing DNS request for {client_address} from upstream DNS.")
        except OSError as e: # Catch specific socket errors
            logging.error(f"OSError processing DNS request for {client_address}: {e}")
        except Exception as e:
            logging.error(f"Error processing DNS request for {client_address}: {e}")


    def start_dns(self):
        if not self._local_ip:
            logging.error("Local IP not set. Cannot start DNS server.")
            self._dns_running = False # Ensure it's marked as not running
            return

        try:
            dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            dns_socket.bind((self._local_ip, 53))
            dns_socket.settimeout(1) # Socket timeout for recvfrom
        except OSError as e:
            logging.error(f"Failed to bind DNS server to {self._local_ip}:53. Error: {e}. Another DNS server might be running or permission denied.")
            self.show_port_in_use_warning() # Show warning if port 53 is in use
            self._dns_running = False
            return
        
        self._dns_running = True
        logging.info(f"DNS server listening on {self._local_ip}:53")
        
        while self._dns_running:
            try:
                data, client_address = dns_socket.recvfrom(512) # Max DNS UDP packet size
                # Create a new thread for each DNS request to handle multiple clients
                client_thread = threading.Thread(target=self.process_dns_request, args=(data, client_address, dns_socket), daemon=True)
                client_thread.start()
            except socket.timeout:
                continue # Normal, allows checking self._dns_running loop condition
            except OSError as e: # Catch errors like "socket closed" if self._dns_running becomes false mid-loop
                 if self._dns_running: # Log only if we weren't expecting to stop
                    logging.error(f"DNS server socket error: {e}")
                 break # Exit loop on critical socket error
            except Exception as e:
                logging.error(f"Unexpected DNS server error: {e}")
        
        dns_socket.close()
        self._dns_running = False # Explicitly set before logging stop
        logging.info("DNS server stopped.")


    def set_window(self, window):
        self._window = window

    def submit_token(self, token, change_window=True):
        self._token = token
        success = False
        response_json = {} # Initialize to avoid UnboundLocalError

        try:
            response = requests.get(f"https://{API_DOMAIN}/get_user?token=" + self._token, timeout=10)
            response.raise_for_status() # Check for HTTP errors
            response_json = response.json()
            success = True # Assume success if no exception and we get JSON
            
            # Store user details
            self._user_data = response_json
            self._cache_ip = response.headers.get('X-Server-IP') # Get cache IP from headers
            
            # Use username for keyring service if available, otherwise a generic key
            self._user_username_for_keyring = self._user_data.get('username', 'user_token')

            try:
                keyring.set_password(KEYRING_SERVICE_NAME, self._user_username_for_keyring, self._token)
                logging.info(f"Token for '{self._user_username_for_keyring}' stored securely.")
            except Exception as e_keyring: # Catch keyring specific errors
                logging.error(f"Failed to store token securely with keyring: {e_keyring}")
                # Fallback to account.txt if keyring fails? Or just log and continue?
                # For now, just log. If this is critical, handle it.
                # As a fallback (not recommended for production if keyring is a hard dep):
                # with open(ACCOUNT_FILE_PATH, "w") as account_file:
                #     account_file.write(self._token)
                # logging.warning("Keyring failed, token saved to local file (less secure).")


        except requests.exceptions.HTTPError as http_err:
            logging.error(f"HTTP error validating token: {http_err}")
            try:
                response_json = http_err.response.json() if http_err.response else {}
            except json.JSONDecodeError:
                response_json = {"error_description": http_err.response.text if http_err.response else "Unknown HTTP error"}
        except requests.exceptions.RequestException as req_err: # Covers ConnectionError, Timeout, etc.
            logging.error(f"Network error validating token: {req_err}")
            response_json = {"error_description": "Network error, please check your connection."}
        except json.JSONDecodeError as json_err:
            logging.error(f"Failed to decode token validation response: {json_err}")
            success = False # Explicitly mark as not successful
            response_json = {"error_description": "Invalid response from server."}
        except Exception as e: # Catch-all for other unexpected errors
            logging.error(f"Unexpected error validating token: {e}")
            success = False
            response_json = {"error_description": "An unexpected error occurred."}


        if not success or not self._user_data or not self._cache_ip: # Ensure user_data and cache_ip are set
            if self._window:
                error_message_js = "document.getElementById('error').style.display = 'block';"
                if response_json.get('status') == 'inactive':
                    subscription_id = response_json.get("subscription_id", "#") # Default to # if no ID
                    self._window.evaluate_js(f"document.getElementById('renew-link').setAttribute('href', 'https://steamdl.ir/my-account/view-subscription/{subscription_id}/');")
                    error_message_js = "document.getElementById('expired').style.display = 'block';"
                elif 'error_description' in response_json:
                     # Escape the error message for JS
                    js_error_desc = json.dumps(f"Error: {response_json['error_description']}")
                    self._window.evaluate_js(f"document.getElementById('error').innerText = {js_error_desc}; {error_message_js}")
                self._window.evaluate_js(error_message_js)
            return

        # If successful:
        if change_window and self._window:
            self._window.load_url(INDEX_PATH)

    def toggle_autoconnect(self):
        self._preferences["auto_connect"] = not self._preferences["auto_connect"]
        self.save_preferences()
        logging.info(f"Autoconnect toggled to: {self._preferences['auto_connect']}")


    def toggle_proxy(self):
        if self._running: # If service is running, stop it
            logging.info("Attempting to stop service...")
            self._running = False # Signal all loops to stop

            # Stop Mitmproxy process
            if self._proxy_process and self._proxy_process.is_alive():
                logging.info("Terminating Mitmproxy process...")
                try:
                    self._proxy_process.terminate()
                    self._proxy_process.join(timeout=5) # Wait for termination
                    if self._proxy_process.is_alive():
                        logging.warning("Mitmproxy process did not terminate, attempting kill.")
                        self._proxy_process.kill() # Force kill if terminate fails
                        self._proxy_process.join(timeout=2)
                except Exception as e:
                    logging.error(f"Error stopping Mitmproxy process: {e}")
            self._proxy_process = None

            # Stop DNS server thread
            if self._dns_thread and self._dns_thread.is_alive():
                logging.info("Stopping DNS server thread...")
                self._dns_running = False # Signal DNS loop to stop
                self._dns_thread.join(timeout=5) # Wait for thread to finish
                if self._dns_thread.is_alive():
                    logging.warning("DNS server thread did not stop gracefully.")
            self._dns_thread = None
            self._dns_running = False # Ensure it's false

            # Restore system DNS settings
            if self._active_adapter_name and self._dns_backup:
                logging.info(f"Restoring DNS settings for adapter '{self._active_adapter_name}' to: {self._dns_backup}")
                if not set_dns_settings(self._active_adapter_name, self._dns_backup):
                    logging.error("Failed to restore system DNS servers fully.")
            else:
                logging.warning("No active adapter or DNS backup to restore.")

            # Re-enable IPv6 (if it was disabled)
            if self._active_adapter_name:
                logging.info(f"Attempting to enable IPv6 for adapter '{self._active_adapter_name}'...")
                run_cmd(["powershell", "-NoProfile", "-Command", f"Enable-NetAdapterBinding -Name '{self._active_adapter_name}' -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue"])
            
            logging.info("Service stopped.")
            return None # Indicate service is off, no local_ip

        else: # If service is not running, start it
            logging.info("Attempting to start service...")
            
            if not self._token or not self._cache_ip:
                logging.error("Token or Cache IP not available. Cannot start service.")
                if self._window: self._window.evaluate_js("alert('Token or server information is missing. Please submit your token again.');")
                return None

            # Get local IP for proxy and DNS binding
            self._local_ip = self.get_default_interface_ip()
            if not self._local_ip:
                logging.error("Failed to obtain local IP address. Cannot start service.")
                if self._window: self._window.evaluate_js("alert('Could not determine local IP address. Check network connection.');")
                return None
            try:
                self._local_ip_bytes = socket.inet_aton(self._local_ip)
            except OSError:
                logging.error(f"Invalid local IP address obtained: {self._local_ip}")
                return None

            # Prepare Mitmproxy arguments
            mitm_args_list = [
                '--mode', f"reverse:http://{CACHE_DOMAIN}@{self._local_ip}:80",
                '--mode', f"reverse:tcp://{self._cache_ip}:443@{self._local_ip}:443",
                '-s', PROXY_ADDON_PATH, # Corrected: No extra quotes
                '--set', f"allow_hosts={CACHE_DOMAIN}",
                '--set', f"token={self._token}",
                '--set', "keep_host_header=true",
                '--set', 'termlog_verbosity=warn', # Mitmproxy logs verbosity
                '--set', 'flow_detail=0', # Minimal flow detail
                '--set', 'stream_large_bodies=100k', # Stream large bodies
                '--set', f"spoof_source_address={self._local_ip}" # Optional: help mitmproxy bind correctly if multiple IPs
            ]
            
            # Start Mitmproxy process
            try:
                logging.info(f"Starting Mitmproxy with args: {mitm_args_list}")
                self._proxy_process = multiprocessing.Process(target=start_proxy, args=(mitm_args_list,), daemon=True)
                self._proxy_process.start()
                time.sleep(1) # Give proxy a moment to start before checking
                if not self._proxy_process.is_alive():
                    logging.error("Mitmproxy process failed to start or exited immediately.")
                    self.show_port_in_use_warning() # Check if ports 80/443 are an issue
                    return None
            except Exception as e:
                logging.error(f"Failed to start Mitmproxy process: {e}")
                self.show_port_in_use_warning()
                return None

            # Start DNS reverse proxy thread
            if not (self._dns_thread and self._dns_thread.is_alive()): # Start only if not already running
                logging.info("Starting DNS server thread...")
                self._dns_thread = threading.Thread(target=self.start_dns, daemon=True)
                self._dns_thread.start()
                time.sleep(0.5) # Give DNS a moment
                if not self._dns_running: # Check if start_dns failed to set self._dns_running
                    logging.error("DNS server thread failed to start or initialize.")
                    if self._proxy_process and self._proxy_process.is_alive(): self._proxy_process.terminate()
                    return None
            
            # Change system DNS servers
            logging.info("Configuring system DNS servers...")
            self._active_adapter_name = get_active_adapter()
            if not self._active_adapter_name:
                logging.error("No active network adapter found to configure DNS.")
                if self._proxy_process and self._proxy_process.is_alive(): self._proxy_process.terminate()
                if self._dns_thread and self._dns_thread.is_alive(): self._dns_running = False; self._dns_thread.join()
                return None
            
            self._dns_backup = get_dns_settings(self._active_adapter_name) # Backup current DNS
            logging.info(f"Original DNS for adapter '{self._active_adapter_name}': {self._dns_backup}")
            
            # Set DNS to local IP, with a public fallback (e.g., Cloudflare or Google)
            # The secondary DNS is important if your local DNS proxy goes down or can't resolve something.
            public_fallback_dns = "1.1.1.1" # Example: Cloudflare
            if not set_dns_settings(self._active_adapter_name, [self._local_ip, public_fallback_dns]):
                logging.error("Failed to change system DNS servers.")
                # Attempt to revert DNS if backup exists
                if self._dns_backup: set_dns_settings(self._active_adapter_name, self._dns_backup)
                if self._proxy_process and self._proxy_process.is_alive(): self._proxy_process.terminate()
                if self._dns_thread and self._dns_thread.is_alive(): self._dns_running = False; self._dns_thread.join()
                return None

            # Disable IPv6 (optional, but sometimes helps with DNS/proxying consistency on Windows)
            logging.info(f"Attempting to disable IPv6 for adapter '{self._active_adapter_name}' to ensure IPv4 DNS priority...")
            run_cmd(["powershell", "-NoProfile", "-Command", f"Disable-NetAdapterBinding -Name '{self._active_adapter_name}' -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue"])

            # Optimize Epic Games (if not already checked/done)
            if self._optimized_epicgames is None: # Only run once unless reset
                self.optimize_epicgames()

            self._running = True # Service is now considered running
            
            # Start health check thread if not already running
            if not (self._health_check_thread and self._health_check_thread.is_alive()):
                self._health_check_thread = threading.Thread(target=self.health_check, daemon=True)
                self._health_check_thread.start()

            logging.info(f"Service started successfully. Local IP: {self._local_ip}")
            return self._local_ip


    def health_check(self):
        logging.info("Health check thread started.")
        while True: # Loop indefinitely, rely on self._running to eventually stop it if main service stops
            if not self._running: # If main service was stopped externally
                logging.info("Health check: Main service is not marked as running. Exiting health check.")
                break 
            
            time.sleep(5) # Check interval
            if not self._running: continue # Re-check after sleep, before doing checks

            service_ok = True
            # Check Mitmproxy process
            if not (self._proxy_process and self._proxy_process.is_alive()):
                logging.warning("Health check: Mitmproxy process is not running.")
                if self._running: self.show_port_in_use_warning() # Show warning only if we expected it to be running
                service_ok = False
            
            # Check DNS server thread/status
            if not self._dns_running: # Check the flag set by start_dns/stop_dns
                logging.warning("Health check: DNS server is not marked as running.")
                service_ok = False
            
            # Check if local IP has changed (e.g., network switch)
            current_local_ip = self.get_default_interface_ip()
            if self._local_ip != current_local_ip:
                logging.warning(f"Health check: Default interface IP has changed. Old: {self._local_ip}, New: {current_local_ip}. This might disrupt service.")
                # This scenario often requires a full service restart to re-bind.
                service_ok = False

            if not service_ok and self._running: # If any check failed AND service was supposed to be running
                logging.error("Health check failed. Attempting to stop and potentially restart service.")
                if self._window: self._window.evaluate_js("$('#power_button').addClass('disabled')")
                
                # Call toggle_proxy to stop the service. toggle_proxy now handles the full stop.
                self.toggle_proxy() # This will set self._running to False.
                
                if self._window: self._window.evaluate_js("$('#power_button').removeClass('on')")

                # If auto_connect is enabled, try to restart the service
                if self._preferences.get("auto_connect", False):
                    logging.info("Health check: Autoconnect is enabled. Attempting to restart service...")
                    time.sleep(2) # Brief pause before restarting
                    restarted_ip = self.toggle_proxy() # This will attempt to start it again
                    if restarted_ip and self._window:
                        self._window.evaluate_js("$('#power_button').addClass('on')")
                        self._window.evaluate_js(f"$('#local_ip').text('{restarted_ip}');")
                        if self._preferences['dns_server'] == "automatic":
                            self.test_anti_sanction()
                    elif self._window: # If restart failed
                         self._window.evaluate_js("alert('Service failed health check and could not be restarted automatically.');")
                
                if self._window: self._window.evaluate_js("$('#power_button').removeClass('disabled')")
                # If not auto-connecting, the service remains stopped. The health_check loop will exit due to self._running being false.
        logging.info("Health check thread stopped.")


    def get_user_data(self):
        logging.info(f"User Data requested: {self._user_data}")
        return self._user_data if self._user_data else {} # Return empty dict if None

    def get_rx(self):
        try:
            if os.path.isfile(RX_FILE_PATH):
                with open(RX_FILE_PATH, 'r', encoding='utf-8') as rx_file:
                    rx_str = rx_file.read().strip()
                    if rx_str: # Ensure not empty
                        return int(rx_str)
        except ValueError as e:
             logging.error(f"Failed to parse rx value from {RX_FILE_PATH}: {e}")
        except IOError as e:
            logging.error(f"Failed to read rx file {RX_FILE_PATH}: {e}")
        except Exception as e: # Generic catch
            logging.error(f"Unexpected error getting rx: {e}")
        return 0

    def minimize(self):
        if self._window: self._window.minimize()

    def close(self):
        if self._window: self._window.destroy()
        # The main exit sequence is in `finally` block of `if __name__ == '__main__'`

    def get_version(self):
        return CURRENT_VERSION

if __name__ == '__main__':
    multiprocessing.freeze_support() # Important for cx_Freeze/PyInstaller

    # Setup logging (configure once)
    app_log_path = os.path.join(user_data_dir, 'app.log') # Use user_data_dir
    logging.basicConfig(
        level=logging.INFO, # Default level
        format='%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s',
        handlers=[
            logging.FileHandler(app_log_path, mode='a', encoding='utf-8'), # Append mode
            logging.StreamHandler(sys.stdout) # Also log to console
        ]
    )
    # Quieten noisy loggers if necessary
    # logging.getLogger("requests").setLevel(logging.WARNING)
    # logging.getLogger("urllib3").setLevel(logging.WARNING)


    # Change CWD to script's directory (important for bundled app finding assets if resource_path is not used everywhere)
    # However, resource_path is designed to handle this. This line might be redundant or could be useful
    # if some relative paths are still used without resource_path.
    # For PyInstaller/cx_Freeze, sys.executable is the app, os.path.dirname(sys.executable) is its dir.
    # If running as .py, os.path.abspath(sys.argv[0]) is script path.
    if getattr(sys, 'frozen', False): # Running as bundled app
        app_dir = os.path.dirname(sys.executable)
    else: # Running as .py script
        app_dir = os.path.dirname(os.path.abspath(__file__)) # Use __file__ for script dir
    os.chdir(app_dir) # Change CWD
    logging.info(f"Application CWD set to: {app_dir}")


    api = Api()
    window = None # Initialize window variable

    # Auto-update check
    updating = False
    if api.get_preferences().get("update", "latest") != "off":
        beta_enabled = api.get_preferences().get("update") == "beta"
        logging.info(f"Checking for updates (beta_enabled: {beta_enabled})...")
        update_available, download_url = check_for_update(beta=beta_enabled)
        if update_available and download_url:
            updating = True
            def progress_callback_wrapper(progress): # Ensure window is available
                if window: window.evaluate_js(f'updateProgress({progress})')

            update_thread = threading.Thread(target=apply_update, args=(download_url, progress_callback_wrapper), daemon=True)
            update_thread.start()
            
            # Create update window
            window = webview.create_window(WINDOW_TITLE + " - Updating", UPDATE_PATH, width=300, height=250, js_api=api, frameless=True)
            api.set_window(window) # Set window for API if needed by update page's JS API
        elif update_available and not download_url:
             logging.warning("Update available but no download URL found.")
        else:
            logging.info("No new updates found or update check failed.")


    if not updating:
        # Clean up old installer if present (might be from a previous failed update)
        old_installer_path = os.path.join(tempfile.gettempdir(), "steamdl_installer.msi")
        if os.path.isfile(old_installer_path):
            try:
                os.remove(old_installer_path)
                logging.info(f"Removed old installer: {old_installer_path}")
            except OSError as e:
                logging.warning(f"Could not remove old installer {old_installer_path}: {e}")
        
        # Attempt to load token using keyring
        loaded_token_from_keyring = None
        try:
            # Need a way to determine the username/key for keyring.
            # For now, trying a generic key. If user_data was persisted, we could get username.
            # This part of token loading logic might need refinement based on how username is determined before full Api init.
            # Let's assume if a username was stored via `api._user_username_for_keyring` after a successful login previously,
            # we'd need to persist that username or try a list of potential keys.
            # Simple approach: try "user_token" as the generic username key.
            loaded_token_from_keyring = keyring.get_password(KEYRING_SERVICE_NAME, "user_token") # Generic key
            if loaded_token_from_keyring:
                logging.info("Token successfully retrieved from keyring.")
                api.submit_token(loaded_token_from_keyring, change_window=False) # Submit but don't change window yet
            else:
                logging.info("No token found in keyring with generic key 'user_token'.")
        except Exception as e_keyring:
            logging.error(f"Error retrieving token from keyring: {e_keyring}")

        # Determine which window to show
        if api._user_data: # If token was valid and user_data is populated
            window = webview.create_window(WINDOW_TITLE, INDEX_PATH, width=300, height=600, js_api=api, frameless=True, easy_drag=True)
        else:
            window = webview.create_window(WINDOW_TITLE, FORM_PATH, width=300, height=600, js_api=api, frameless=True, easy_drag=False)
        api.set_window(window) # Set window for API interaction
        
        # If auto_connect is enabled and token is valid, attempt to start service
        if api.get_preferences().get("auto_connect") and api._user_data:
            logging.info("Autoconnect is enabled and token is valid. Attempting to start service...")
            started_ip = api.toggle_proxy() # This starts the service
            if started_ip and window and api._user_data: # Check if on index_path
                 # Ensure window is fully loaded before JS eval if index.html has complex setup
                 def auto_connect_ui_update():
                    window.evaluate_js("$('#power_button').addClass('on')")
                    window.evaluate_js(f"$('#local_ip').text('{started_ip}');")
                    if api.get_preferences()['dns_server'] == "automatic":
                        api.test_anti_sanction()
                 
                 # Delay slightly to ensure JS context is ready if INDEX_PATH was just loaded
                 threading.Timer(1.0, auto_connect_ui_update).start()
            elif not started_ip:
                 logging.error("Autoconnect failed to start the service.")


    try:
        if window: # Ensure window was created
            webview.start(gui='edgechromium', debug=False) # Set debug=True for dev console
        else:
            logging.error("Window object was not created. Cannot start webview.")
    except Exception as e: # Catch specific webview start errors if known, else generic
        logging.error(f"Failed to start webview: {e}")
        # Fallback or cleanup if webview fails to start
        if api._running: # If service was started (e.g. autoconnect) but UI failed
            logging.info("UI failed to start, stopping background service...")
            api.toggle_proxy() # Stop the service

    finally:
        logging.info("Application is shutting down...")
        if api._running: # Ensure service is stopped on exit
            api.toggle_proxy() # This handles DNS restoration, proxy termination etc.
        
        # cleanup_temp_folders() # Call cleanup for WebView2 temp files - careful if it's slow
        logging.info("Cleanup complete. Exiting.")
        sys.exit()
