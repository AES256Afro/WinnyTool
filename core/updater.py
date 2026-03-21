"""
WinnyTool - GitHub Auto-Updater
Checks for new releases on GitHub and handles downloading/applying updates.
Uses only stdlib (urllib.request, json) with no external dependencies.
"""

import json
import os
import subprocess
import tempfile
import urllib.request
import urllib.error
from typing import Optional

CURRENT_VERSION = "1.4.0"
GITHUB_REPO = "AES256Afro/WinnyTool"
GITHUB_API_URL = "https://api.github.com/repos/{repo}/releases/latest"


def _parse_version(version_str: str) -> tuple:
    """
    Parse a version string like '1.2.3' or 'v1.2.3' into a tuple of ints
    for comparison. Handles optional 'v' prefix.
    """
    v = version_str.strip().lstrip("v")
    parts = []
    for part in v.split("."):
        try:
            parts.append(int(part))
        except ValueError:
            # Handle pre-release tags like '1.0.0-beta1' by stripping non-numeric suffix
            numeric = ""
            for ch in part:
                if ch.isdigit():
                    numeric += ch
                else:
                    break
            parts.append(int(numeric) if numeric else 0)
    return tuple(parts)


def _fetch_json(url: str) -> Optional[dict]:
    """Fetch JSON from a URL using urllib. Returns None on failure."""
    try:
        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "WinnyTool-Updater",
            },
        )
        with urllib.request.urlopen(req, timeout=15) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 403:
            print(f"[Updater] Rate limited by GitHub API. Try again later.")
        elif e.code == 404:
            print(f"[Updater] Repository or release not found.")
        else:
            print(f"[Updater] HTTP error {e.code}: {e.reason}")
        return None
    except urllib.error.URLError as e:
        print(f"[Updater] Network error: {e.reason}")
        return None
    except (json.JSONDecodeError, OSError) as e:
        print(f"[Updater] Error fetching update info: {e}")
        return None


def check_for_updates(repo: str = GITHUB_REPO) -> dict:
    """
    Check GitHub for the latest release and compare with current version.

    Args:
        repo: GitHub repository in 'owner/repo' format.

    Returns:
        dict with keys:
            update_available (bool)
            current_version (str)
            latest_version (str)
            download_url (str)  - best asset URL (prefers .exe > .msi > .zip)
            release_notes (str)
            assets (list[dict]) - each dict has 'name', 'url', 'size' keys
    """
    result = {
        "update_available": False,
        "current_version": CURRENT_VERSION,
        "latest_version": CURRENT_VERSION,
        "download_url": "",
        "release_notes": "",
        "assets": [],
    }

    url = GITHUB_API_URL.format(repo=repo)
    data = _fetch_json(url)
    if data is None:
        return result

    latest_tag = data.get("tag_name", "")
    if not latest_tag:
        return result

    result["latest_version"] = latest_tag.lstrip("v")
    result["release_notes"] = data.get("body", "No release notes provided.")

    # Build structured assets list
    raw_assets = data.get("assets", [])
    asset_list = []
    for asset in raw_assets:
        asset_list.append({
            "name": asset.get("name", ""),
            "url": asset.get("browser_download_url", ""),
            "size": asset.get("size", 0),
        })
    result["assets"] = asset_list

    # Find the best download asset (prefer .exe, then .zip, then .msi)
    download_url = ""
    priority = {"exe": 3, "msi": 2, "zip": 1}
    best_priority = 0

    for asset in raw_assets:
        name = asset.get("name", "").lower()
        url_candidate = asset.get("browser_download_url", "")
        ext = name.rsplit(".", 1)[-1] if "." in name else ""
        p = priority.get(ext, 0)
        if p > best_priority:
            best_priority = p
            download_url = url_candidate

    # Fallback to zipball if no assets
    if not download_url:
        download_url = data.get("zipball_url", "")

    result["download_url"] = download_url

    # Compare versions
    try:
        current = _parse_version(CURRENT_VERSION)
        latest = _parse_version(latest_tag)
        result["update_available"] = latest > current
    except (ValueError, TypeError):
        result["update_available"] = False

    return result


def download_update(url: str, dest_path: str = "") -> bool:
    """
    Download a release asset from the given URL.

    Args:
        url: Direct download URL for the update file.
        dest_path: Destination file path. If empty, saves to a temp directory.

    Returns:
        bool indicating success. On success, dest_path is populated.
    """
    if not url:
        print("[Updater] No download URL provided.")
        return False

    if not dest_path:
        # Determine file extension from URL
        filename = url.rsplit("/", 1)[-1] if "/" in url else "winnytool_update"
        dest_path = os.path.join(tempfile.gettempdir(), filename)

    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "WinnyTool-Updater"},
        )
        with urllib.request.urlopen(req, timeout=120) as response:
            total_size = response.headers.get("Content-Length")
            total_size = int(total_size) if total_size else None

            downloaded = 0
            chunk_size = 65536
            with open(dest_path, "wb") as f:
                while True:
                    chunk = response.read(chunk_size)
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total_size:
                        pct = (downloaded / total_size) * 100
                        print(f"\r[Updater] Downloading: {pct:.1f}%", end="", flush=True)

        print(f"\n[Updater] Downloaded to: {dest_path}")
        return True

    except urllib.error.HTTPError as e:
        print(f"[Updater] Download failed - HTTP {e.code}: {e.reason}")
        return False
    except urllib.error.URLError as e:
        print(f"[Updater] Download failed - Network error: {e.reason}")
        return False
    except OSError as e:
        print(f"[Updater] Download failed - File error: {e}")
        return False


def apply_update(file_path: str) -> bool:
    """
    Apply a downloaded update by running the installer or extracting the archive.

    Args:
        file_path: Path to the downloaded update file (.exe, .msi, or .zip).

    Returns:
        bool indicating whether the update process was started successfully.
    """
    if not os.path.isfile(file_path):
        print(f"[Updater] Update file not found: {file_path}")
        return False

    ext = file_path.rsplit(".", 1)[-1].lower() if "." in file_path else ""

    try:
        if ext == "exe":
            # Run the installer
            subprocess.Popen(
                [file_path],
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if hasattr(subprocess, "CREATE_NEW_PROCESS_GROUP") else 0,
            )
            print("[Updater] Installer launched. WinnyTool will close for the update.")
            return True

        elif ext == "msi":
            subprocess.Popen(
                ["msiexec", "/i", file_path],
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if hasattr(subprocess, "CREATE_NEW_PROCESS_GROUP") else 0,
            )
            print("[Updater] MSI installer launched.")
            return True

        elif ext == "zip":
            import zipfile
            extract_dir = os.path.dirname(os.path.abspath(file_path))
            with zipfile.ZipFile(file_path, "r") as zf:
                zf.extractall(extract_dir)
            print(f"[Updater] Update extracted to: {extract_dir}")
            return True

        else:
            print(f"[Updater] Unsupported file type: .{ext}")
            return False

    except OSError as e:
        print(f"[Updater] Failed to apply update: {e}")
        return False


if __name__ == "__main__":
    info = check_for_updates()
    print(json.dumps(info, indent=2))
