import sys # Add this line
from cx_Freeze import setup, Executable
from main import CURRENT_VERSION 

build_exe_options = {
    "build_exe": "dist/steamdl", # Output directory relative to setup.py
    "include_files": ["assets", "MicrosoftEdgeWebview2Setup.exe"],
    "excludes": ["tkinter", "PyQt5", "webview.platforms.android", "webview.platforms.cocoa", "mitmproxy.addons.proxyauth","mitmproxy.tools.web","setuptools"],
    "includes": ["mitmproxy_windows", "appdirs", "keyring", "packaging"], # Added appdirs, keyring, packaging
    "include_msvcr": True,
    "replace_paths": [("*", "")] # This might strip too much path info, test carefully
}

# MSI Custom Action Flags (Refer to MSI documentation for specifics)
# Type 34 = 0x0022 (Executable + Property)
# Type 50 = 0x0032 (Executable + Property, no wait)
# Flag 3072 = 0x0C00 (msidbCustomActionTypeNoImpersonate) - Note: This might be different from common interpretation. User used 3072.
# Flag 192 = 0x00C0 (msidbCustomActionTypeAsync + msidbCustomActionTypeContinue)
# Flag 64 = 0x0040 (msiCustomActionTypeIgnoreExitCode)

# User's original values:
# LaunchApp: 34 + 3072 + 192 = 3298
# RemoveLegacy: 50 + 64 = 114
LAUNCH_APP_FLAGS = 34 + 3072 + 192 # Flags for launching app after install
REMOVE_LEGACY_FLAGS = 50 + 64    # Flags for removing legacy uninstaller

bdist_msi_options = {
    "initial_target_dir": "[ProgramFiles64Folder]\\SteamDL", # Use ProgramFiles64Folder for 64-bit systems
    "upgrade_code": "{6D92AF12-4EFC-3241-88B7-84B0C6959C53}", # Keep your existing upgrade code
    "install_icon": "assets/steamdl.ico", # Ensure path to icon is correct relative to setup.py
    "summary_data": {"author": "SteamDL.ir"},
    "all_users": True,
    "data": {
        "Directory": [
            ("ProgramMenuFolder", "TARGETDIR", "."), 
            ("SteamDLShortcutDir", "ProgramMenuFolder", "SteamDL~1|SteamDL") # Unique name for shortcut dir
        ], 
        "CustomAction": [
            ("LaunchApp", LAUNCH_APP_FLAGS, "TARGETDIR", "[TARGETDIR]SteamDL.exe"), # Target name from Executable
            ("RemoveLegacy", REMOVE_LEGACY_FLAGS, "LegacyUninstallerPath", "/S")
        ],
        "Property":[ # Ensure LegacyUninstallerPath is valid or remove if not needed
            ("LegacyUninstallerPath", "C:\\Program Files (x86)\\SteamDL\\uninstall.exe") 
        ], 
        "InstallExecuteSequence": [
            ("RemoveLegacy", "NOT REMOVE", 1300), 
            ("LaunchApp", "NOT REMOVE", 6500) # Run LaunchApp late in sequence
        ],
        # Ensure Shortcut table is correctly handled by cx_Freeze or define it explicitly if needed
        # Shortcut info is also in Executable()
    }
}
# Base="Win32GUI" should be used for GUI applications on Windows to avoid console
# For webview with frameless, base might sometimes be an issue, test.
# If main.py uses multiprocessing.freeze_support(), it's good.
base = "Win32GUI" if sys.platform == "win32" else None


# Ensure icon path for executable is also correct
executable = Executable(
    "main.py", 
    target_name="SteamDL.exe", # Consistent with MSI CustomAction
    icon="assets/steamdl.ico", 
    uac_admin=True, # Requires admin rights
    shortcut_name="SteamDL",
    shortcut_dir="SteamDLShortcutDir", # Reference to Directory table entry
    base=base
)

setup(
    name = "SteamDL",
    version = CURRENT_VERSION,
    author = "SteamDL.ir",
    url = "https://steamdl.ir",
    description = "SteamDL Client Application", # Add a description
    options = {"build_exe": build_exe_options, "bdist_msi": bdist_msi_options},
    executables = [executable]
)
