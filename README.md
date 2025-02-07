# DevUtils

**DevUtils** is a repository containing a collection of small yet powerful scripts and utilities written in Python, Bash, TypeScript, and more. These tools are designed to simplify day-to-day tasks, automate repetitive processes, and make life easier for developers and tech enthusiasts.

## Table of Contents

- [DevUtils](#devutils)
  - [Table of Contents](#table-of-contents)
  - [Getting Started](#getting-started)
  - [Available Utilities](#available-utilities)
    - [1. Virtual Machine Manager](#1-virtual-machine-manager)
    - [2. Camera Device Manager](#2-camera-device-manager)
    - [3. Repository Migration Tool](#3-repository-migration-tool)
    - [**4. LXA Super Secure Folder Locker**](#4-lxa-super-secure-folder-locker)
  - [Adding New Utilities](#adding-new-utilities)
  - [Contributing](#contributing)
  - [License](#license)

---

## Getting Started

1. Clone the repository:

```bash
git clone https://github.com/pankajackson/devutils.git
cd devutils
```

2. Ensure you have the required dependencies for each script (mentioned in their respective sections).

3. Run the script as described in its section below.

---

## Available Utilities

### 1. Virtual Machine Manager

**Description**:  
This Python script provides an easy way to manage virtual machines (VMs) using VirtualBox. You can create, start, stop, shutdown, and destroy VMs via simple commands.

**Features**:

- Create a VM with customizable resources (CPU, memory, disk, etc.).
- Start, stop, shutdown, or delete a VM effortlessly.
- Manage storage and network configurations during VM creation.

**Dependencies**:

- Python 3.6+
- VirtualBox installed with the `VBoxManage` CLI available in your PATH.

**Usage**:

1. Navigate to the script directory:

```bash
cd devutils
```

2. Run the script:

```bash
./vm_manager [command] [options]
```

**Commands**:
| Command | Description | Example |
|-----------|------------------------------------|------------------------------------------------------------------------------------------|
| `create` | Create a new virtual machine | `./vm_manager create my-vm /path/to/image.iso --cpus 4 --memory 4000 --disk 50000` |
| `start` | Start an existing virtual machine | `./vm_manager start my-vm` |
| `stop` | Stop a running virtual machine | `./vm_manager stop my-vm` |
| `shutdown`| Shutdown a running virtual machine | `./vm_manager shutdown my-vm` |
| `destroy` | Destroy a virtual machine | `./vm_manager destroy my-vm` |
| `list` | List virtual machines and current status | `./vm_manager list` |

---

### 2. Camera Device Manager

**Description**:  
This Bash script helps manage camera devices connected to your system. It allows you to check the status of devices, turn them on or off, and check device permissions.

**Features**:

- Validate whether the specified device is a valid camera device.
- Change device permissions to turn it on or off.
- View detailed information about the device's status, including ownership and permissions.

**Dependencies**:

- `v4l2-ctl` (part of the `v4l-utils` package).
- `udevadm` (for device information).

**Usage**:

1. Navigate to the script directory:

```bash
cd devutils
```

2. Run the script with one of the following commands:

```bash
./cam_manager [action] [device] [--detail]
```

**Commands**:
| Command | Description | Example |
|----------|-------------------------------------------|----------------------------------------------------|
| `setup` | Install required dependencies | `./cam_manager setup` |
| `on` | Turn the specified device on | `./cam_manager on /dev/video0` |
| `off` | Turn the specified device off | `./cam_manager off /dev/video0` |
| `status` | Check the status of a specific device | `./cam_manager status /dev/video0` |

---

### 3. Repository Migration Tool

**Description**:  
This tool helps in migrating a Git repository from one location to another while supporting repository creation on platforms like GitHub. It simplifies cloning, pushing, and managing repositories across different remotes.

**Features**

- Validate repository URLs and names.
- Automatically create new repositories on GitHub using the GitHub API or GitHub CLI (`gh`).
- Migrate repositories, including all branches, between remotes.
- Supports SSH and HTTPS protocols for repository URLs.
- Customizable repository privacy settings (public/private).
- Provides detailed error messages and logs for easy debugging.

**Dependencies**

- [Git](https://git-scm.com/)
- [GitHub CLI (gh)](https://cli.github.com/)

**Usage**

Run the script with the required arguments:

```bash
./git_migrator <source_repo_url> [options]
```

**Arguments**

- `source_repo_url`: URL of the source Git repository to migrate.

**Options**

- `--target-repo-url`: URL of the target repository. If not provided, a new repository will be created.
- `--repo-name`: Name of the new target repository (used if creating a repository).
- `--private`: Makes the new repository private (default: `private`).
- `--target-platform`: Target platform for repository creation (e.g., `github` or `bitbucket`). Default is `github`.
- `--target-proto`: Protocol for pushing to the repository (`ssh` or `https`). Default is `ssh`.

**Examples**

1. **Migrate a repository with automatic target creation**:

```bash
./git_migrator https://github.com/user/source-repo.git --repo-name new-repo --private
```

2. **Migrate to an existing target repository**:

```bash
./git_migrator https://github.com/user/source-repo.git --target-repo-url git@github.com:user/new-repo.git
```

3. **Use HTTPS instead of SSH for migration**:

```bash
./git_migrator https://github.com/user/source-repo.git --target-proto https
```

**Logs**

The script provides detailed logging output for each step. Logs can help identify missing tools, invalid inputs, or migration issues.

---

### **4. LXA Super Secure Folder Locker**

**Description**:  
LXA Super Secure Folder Locker is a Python-based utility that securely locks and encrypts files or directories using AES-256 encryption. It provides authentication using PAM, applies strict file permissions, and prevents unauthorized access using process-based locking.

**Features**:

- Lock and encrypt files and directories securely.
- Unlock and restore encrypted files or directories.
- Check the status of a locked/unlocked file or directory.
- Uses OpenSSL AES-256 encryption with PBKDF2 key derivation.
- Supports PAM authentication before unlocking (can be skipped if required).
- Prevents concurrent access via file-based locking.
- Provides verbose logging for debugging and monitoring.

**Dependencies**:

- Python 3.x
- `openssl` (for encryption and decryption)
- `pam` (install using `sudo pacman -S python-pam` or `pip install python-pam`)
- `tar` (for compressing directories before encryption)

---

**Usage**

1. Navigate to the script directory:

   ```bash
   cd devutils
   ```

2. Run the script with one of the following commands:

   ```bash
   python3 locker [command] [options]
   ```

**Commands**:
| Command | Description | Example |
|---------|------------|---------|
| `lock` | Lock and encrypt a file or directory | `python3 locker lock -p ~/Documents` |
| `unlock` | Unlock and decrypt a file or directory | `python3 locker unlock -p ~/Documents` |
| `status` | Check if a file/directory is locked or unlocked | `python3 locker status -p ~/Documents` |
| `lock (batch mode)` | Lock multiple directories using an index file | `python3 locker lock -i ~/index.locker` |

---

**Options**

| Option          | Description                                       | Example                   |
| --------------- | ------------------------------------------------- | ------------------------- |
| `-p, --path`    | Path to the file or directory to lock/unlock.     | `-p ~/Downloads`          |
| `-i, --index`   | Path to an index file containing multiple paths.  | `-i ~/index.locker`       |
| `-V, --verbose` | Enable verbose logging.                           | `--verbose`               |
| `--skip-auth`   | Skip user authentication (useful for automation). | `--skip-auth`             |
| `--skip-enc`    | Skip encryption (locks using permissions only).   | `--skip-enc`              |
| `--password`    | Provide a password for encryption/decryption.     | `--password mysecurepass` |

---

**Examples**

🔒 **Lock a directory with encryption**:

```bash
python3 locker lock -p ~/Documents
```

🔓 **Unlock a directory**:

```bash
python3 locker unlock -p ~/Documents
```

📂 **Check if a directory is locked**:

```bash
python3 locker status -p ~/Documents
```

📄 **Lock a directory without encryption (permission-based only)**:

```bash
python3 locker lock -p ~/Documents --skip-enc
```

🔐 **Batch lock multiple directories using an index file**:

```bash
echo "/home/user/Documents" > ~/index.locker
echo "/home/user/Downloads" >> ~/index.locker
python3 locker lock -i ~/index.locker
```

---

**Security & Encryption Details**

- Uses **AES-256 encryption** via OpenSSL.
- Supports **PBKDF2 key derivation** with 100,000 iterations.
- Uses **PAM authentication** for access control.
- Implements **process-based file locking** to prevent simultaneous access.

---

**Troubleshooting**

❌ **Error: "Required binary 'openssl' is missing."**  
🔹 Solution: Install OpenSSL.

```bash
sudo apt install openssl  # Debian-based
sudo pacman -S openssl    # Arch-based
```

❌ **Error: "Authentication failed after 3 attempts."**  
🔹 Solution: Ensure you enter the correct system password. If PAM is misconfigured, try `--skip-auth` (not recommended for secure environments).

❌ **Error: "Failed to remove <path>"**  
🔹 Solution: The file might be **locked by another process**. Ensure no other instance is running.

---

## Adding New Utilities

To add a new utility:

1. Place your script in the appropriate subdirectory (e.g., `python/`, `bash/`, `typescript/`).
2. Update the `README.md`:

- Add a new subsection under **Available Utilities** with details about your script.
- Include dependencies, usage instructions, and examples.

3. Commit your changes and create a pull request if contributing.

---

## Contributing

Contributions are welcome! If you have a handy script or utility that you think others would benefit from, feel free to fork the repository, add your script, and submit a pull request.

---

## License

This repository is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
