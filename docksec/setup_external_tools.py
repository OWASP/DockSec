#!/usr/bin/env python3
import subprocess
import sys
import os
import platform
import shutil
from pathlib import Path
import urllib.request
import stat
import zipfile
import json

def get_os_type():
    """Determine the operating system type."""
    system = platform.system().lower()
    if system == "darwin":
        return "mac"
    return system

def check_command_exists(command):
    """Check if a command exists in the system PATH."""
    return shutil.which(command) is not None

def run_command(command, shell=False):
    """Run a command and return its output."""
    try:
        result = subprocess.run(
            command,
            shell=shell,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return True, result.stdout
    except subprocess.CalledProcessError as e:
        return False, e.stderr

def get_latest_trivy_version():
    """Get the latest Trivy release version from GitHub API."""
    try:
        url = "https://api.github.com/repos/aquasecurity/trivy/releases/latest"
        with urllib.request.urlopen(url) as response:
            data = json.loads(response.read().decode())
            return data["tag_name"].lstrip('v')
    except Exception as e:
        print(f"Error getting latest Trivy version: {str(e)}")
        return None

def install_hadolint():
    """Install Hadolint based on the operating system."""
    os_type = get_os_type()
    
    if check_command_exists("hadolint"):
        success, version = run_command(["hadolint", "--version"])
        if success:
            print(f"Hadolint is already installed: {version.strip()}")
            return True

    print("Installing Hadolint...")
    
    try:
        if os_type == "windows":
            # For Windows, download the binary directly
            url = "https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Windows-x86_64.exe"
            download_path = Path(os.environ.get("USERPROFILE", "")) / "scoop" / "shims" / "hadolint.exe"
            download_path.parent.mkdir(parents=True, exist_ok=True)
            
            urllib.request.urlretrieve(url, str(download_path))
            
        elif os_type == "mac":
            success, _ = run_command(["brew", "install", "hadolint"])
            if not success:
                print("Please install Homebrew first: https://brew.sh")
                return False
                
        elif os_type == "linux":
            # For Linux, download the binary
            url = "https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-x86_64"
            download_path = Path("/usr/local/bin/hadolint")
            
            urllib.request.urlretrieve(url, str(download_path))
            # Make the binary executable
            os.chmod(str(download_path), stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
            
        print("Hadolint installed successfully!")
        return True
        
    except Exception as e:
        print(f"Error installing Hadolint: {str(e)}")
        return False

def install_trivy():
    """Install Trivy based on the operating system."""
    os_type = get_os_type()
    
    if check_command_exists("trivy"):
        success, version = run_command(["trivy", "--version"])
        if success:
            print(f"Trivy is already installed: {version.strip()}")
            return True

    print("Installing Trivy...")
    
    try:
        if os_type == "windows":
            # Get latest version
            version = get_latest_trivy_version()
            if not version:
                print("Failed to get latest Trivy version")
                return False

            # Create installation directory in user's home
            install_dir = Path(os.environ.get("USERPROFILE", "")) / "trivy"
            install_dir.mkdir(parents=True, exist_ok=True)

            # Download URL for Windows
            url = f"https://github.com/aquasecurity/trivy/releases/download/v{version}/trivy_{version}_windows-64bit.zip"
            zip_path = install_dir / "trivy.zip"
            exe_path = install_dir / "trivy.exe"

            # Download and extract
            print(f"Downloading Trivy v{version}...")
            urllib.request.urlretrieve(url, str(zip_path))

            # Extract the zip file
            with zipfile.ZipFile(str(zip_path), 'r') as zip_ref:
                zip_ref.extractall(str(install_dir))

            # Clean up zip file
            zip_path.unlink()

            # Add to PATH if not already there
            user_path = os.environ.get("PATH", "")
            if str(install_dir) not in user_path:
                # Using setx to permanently add to PATH
                subprocess.run(["setx", "PATH", f"{user_path};{install_dir}"], shell=True)
                print("Added Trivy to PATH. Please restart your terminal for the changes to take effect.")
                
        elif os_type == "mac":
            success, _ = run_command(["brew", "install", "aquasecurity/trivy/trivy"])
            if not success:
                print("Please install Homebrew first: https://brew.sh")
                return False
                
        elif os_type == "linux":
            # Add the Trivy repository and install
            commands = [
                "sudo apt-get install wget apt-transport-https gnupg lsb-release -y",
                "wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -",
                "echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | sudo tee -a /etc/apt/sources.list.d/trivy.list",
                "sudo apt-get update",
                "sudo apt-get install trivy -y"
            ]
            
            for cmd in commands:
                success, _ = run_command(cmd, shell=True)
                if not success:
                    print(f"Error executing command: {cmd}")
                    return False
                    
        print("Trivy installed successfully!")
        return True
        
    except Exception as e:
        print(f"Error installing Trivy: {str(e)}")
        return False

def main():
    """Main function to install and verify tools."""
    print("Checking and installing required tools...")
    
    # Install Hadolint
    print("\nChecking Hadolint...")
    if install_hadolint():
        success, version = run_command(["hadolint", "--version"])
        if success:
            print(f"Hadolint version: {version.strip()}")
    else:
        print("Failed to install Hadolint")

    # Install Trivy
    print("\nChecking Trivy...")
    if install_trivy():
        success, version = run_command(["trivy", "--version"])
        if success:
            print(f"Trivy version: {version.strip()}")
    else:
        print("Failed to install Trivy")

if __name__ == "__main__":
    main()