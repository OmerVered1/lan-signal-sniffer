"""In-app updater: check GitHub Releases and install the newer build.

Adapted from keithley-smu-control/updater.py so both apps behave the same way —
same release-tag comparison, same modal download, same hand-off to the platform
installer. Kept synchronous and small: the download pumps the Qt event loop
rather than spawning worker threads.

One behaviour is specific to this app. The installer needs to replace files that
a running capture has open, and on Windows the app is typically running elevated,
so the update is refused outright while a capture is active rather than left to
fail halfway through.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import webbrowser
from typing import Optional

from PyQt5.QtWidgets import QApplication, QMessageBox

from ._version import GITHUB_OWNER, GITHUB_REPO

_GITHUB_LATEST_API = (
    f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/releases/latest"
)
_RELEASES_PAGE = f"https://github.com/{GITHUB_OWNER}/{GITHUB_REPO}/releases"

# These must match the asset names the release workflow uploads.
_WINDOWS_ASSET = "LAN-Signal-Sniffer-Windows-Setup.exe"
_MACOS_ASSET = "LAN-Signal-Sniffer-macOS.zip"


def _parse_version(v: str) -> tuple:
    """Parse 'v0.2.1', 'v0.2.1-rc1', or '0.2.1' into a comparable tuple."""
    v = (v or "").lstrip("v").strip()
    out = []
    for part in v.split("."):
        digits = "".join(c for c in part if c.isdigit())
        out.append(int(digits) if digits else 0)
    while len(out) < 3:
        out.append(0)
    return tuple(out)


def _fetch_latest_release(timeout: float = 10.0) -> dict:
    request = urllib.request.Request(
        _GITHUB_LATEST_API,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": f"{GITHUB_REPO}-updater",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read())


def _platform_asset_name() -> Optional[str]:
    if sys.platform == "win32":
        return _WINDOWS_ASSET
    if sys.platform == "darwin":
        return _MACOS_ASSET
    return None


def _download_with_progress(url: str, dest_path: str, parent=None) -> bool:
    from PyQt5.QtCore import Qt
    from PyQt5.QtWidgets import QProgressDialog

    progress = QProgressDialog("Downloading update…", "Cancel", 0, 100, parent)
    progress.setWindowTitle("Updating")
    progress.setWindowModality(Qt.ApplicationModal)
    progress.setMinimumDuration(0)
    progress.setValue(0)
    QApplication.processEvents()

    cancelled = {"flag": False}

    def reporthook(blocks: int, block_size: int, total_size: int) -> None:
        if progress.wasCanceled():
            cancelled["flag"] = True
            raise IOError("Download cancelled")
        if total_size > 0:
            progress.setValue(min(100, int(blocks * block_size * 100 / total_size)))
            QApplication.processEvents()

    try:
        urllib.request.urlretrieve(url, dest_path, reporthook=reporthook)
    except Exception:
        progress.close()
        if cancelled["flag"]:
            return False
        raise
    progress.close()
    return True


def check_for_updates(
    current_version: str,
    parent=None,
    silent_if_uptodate: bool = False,
    capture_active: bool = False,
) -> None:
    """Offer the latest release, if there is one newer than what is running.

    `capture_active` stops an update mid-experiment: the installer cannot
    replace files the running app holds open, and interrupting a recording to
    find that out is worse than being told to stop first.
    """
    if capture_active:
        QMessageBox.information(
            parent,
            "Stop the capture first",
            "An update replaces the running program's files, which cannot be "
            "done while a capture is open.\n\nStop the capture — and finish any "
            "recording in progress — then check again.",
        )
        return

    try:
        data = _fetch_latest_release()
    except urllib.error.HTTPError as e:
        if not silent_if_uptodate:
            detail = (
                "The releases API returned 404. If no release has been "
                "published yet, that is expected."
                if e.code == 404
                else f"GitHub returned HTTP {e.code}."
            )
            QMessageBox.warning(parent, "Update check failed", detail)
        return
    except Exception as e:
        if not silent_if_uptodate:
            QMessageBox.warning(
                parent, "Update check failed", f"Couldn't reach GitHub:\n{e}"
            )
        return

    latest_tag = data.get("tag_name") or ""
    release_url = data.get("html_url") or _RELEASES_PAGE
    assets = data.get("assets") or []

    if not latest_tag:
        if not silent_if_uptodate:
            QMessageBox.information(
                parent, "Update check", "Couldn't read the latest release tag."
            )
        return

    if _parse_version(latest_tag) <= _parse_version(current_version):
        if not silent_if_uptodate:
            QMessageBox.information(
                parent, "Up to date", f"You're on the latest version (v{current_version})."
            )
        return

    asset_name = _platform_asset_name()
    asset_url = None
    for asset in assets:
        if asset.get("name") == asset_name:
            asset_url = asset.get("browser_download_url")
            break

    box = QMessageBox(parent)
    box.setIcon(QMessageBox.Information)
    box.setWindowTitle("Update available")
    box.setText(
        f"<b>Version {latest_tag} is available.</b><br>"
        f"You're currently on v{current_version}."
    )
    if asset_url:
        box.setInformativeText(
            "Download and run the installer now?<br><br>"
            "You'll need to close this app when the installer asks."
        )
    else:
        box.setInformativeText(
            "There's no installer for this platform in that release. "
            "Open the release page instead?"
        )
    box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
    box.setDefaultButton(QMessageBox.Yes)
    if box.exec_() != QMessageBox.Yes:
        return

    if not asset_url:
        webbrowser.open(release_url)
        return

    try:
        dest = os.path.join(tempfile.mkdtemp(prefix="lss_update_"), asset_name)
        if not _download_with_progress(asset_url, dest, parent):
            return
    except Exception as e:
        QMessageBox.critical(parent, "Download failed", str(e))
        return

    if sys.platform == "win32":
        try:
            subprocess.Popen([dest], shell=False)
        except Exception as e:
            QMessageBox.critical(
                parent,
                "Couldn't start the installer",
                f"{e}\n\nThe installer was downloaded to:\n{dest}",
            )
            return
        QMessageBox.information(
            parent,
            "Installer started",
            f"{asset_name} is running.\n\nClose this app when prompted so the "
            "installer can replace its files.",
        )
    elif sys.platform == "darwin":
        subprocess.run(["open", "-R", dest], check=False)
        QMessageBox.information(
            parent,
            "Update downloaded",
            f"Downloaded to:\n{dest}\n\nQuit this app, then unzip and drag the "
            "new app into Applications, replacing the existing one.",
        )
