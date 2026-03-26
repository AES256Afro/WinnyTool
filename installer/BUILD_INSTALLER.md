# Building WinnyTool Installers

This guide covers building the WinnyTool Windows installer using either **NSIS** or **Inno Setup**.

---

## Prerequisites

| Tool | Download | Notes |
|------|----------|-------|
| Python 3.10+ | https://www.python.org/downloads/ | Ensure `pip` is available |
| PyInstaller 6+ | `pip install pyinstaller>=6.0` | Packages Python into a standalone `.exe` |
| NSIS 3.x | https://nsis.sourceforge.io/Download | For the `.nsi` installer script |
| Inno Setup 6.x | https://jrsoftware.org/isdl.php | For the `.iss` installer script (alternative) |

You only need **one** of NSIS or Inno Setup -- pick whichever you prefer.

---

## Step 1: Build the Executable with PyInstaller

From the project root directory:

```bash
pip install pyinstaller>=6.0

pyinstaller --onefile --windowed ^
    --icon=assets/winnytool.ico ^
    --name=WinnyTool ^
    --add-data "data;data" ^
    --add-data "assets;assets" ^
    winnytool.py
```

Or use the provided build script:

```bash
python build.py
```

This produces `dist/WinnyTool.exe`.

---

## Step 2: Build the Installer

### Option A: NSIS

1. Open a terminal in the `installer/` directory.
2. Run:

```bash
makensis winnytool_setup.nsi
```

3. The installer is written to `dist/WinnyTool_Setup_v1.4.0.exe`.

### Option B: Inno Setup

1. Open `installer/inno_setup.iss` in Inno Setup Compiler, or run from the command line:

```bash
iscc installer/inno_setup.iss
```

2. The installer is written to `dist/WinnyTool_Setup_v1.4.0.exe`.

---

## Step 3: Test the Installer

1. Run the generated `WinnyTool_Setup_v1.4.0.exe`.
2. Verify the following:
   - The license page displays correctly.
   - Installation completes to `C:\Program Files\WinnyTool`.
   - A Start Menu folder "WinnyTool" is created with app and uninstall shortcuts.
   - (If selected) A Desktop shortcut is created.
   - WinnyTool appears in **Settings > Apps > Installed Apps** (Add/Remove Programs).
   - The application launches correctly from the installed location.
3. Test the uninstaller:
   - Uninstall via Add/Remove Programs or the Start Menu uninstall shortcut.
   - Verify all files, shortcuts, and registry entries are removed.

---

## Notes on Code Signing (Optional but Recommended)

Unsigned installers trigger Windows SmartScreen warnings. To avoid this:

1. Obtain a code signing certificate from a trusted CA (e.g., DigiCert, Sectigo, SSL.com).
2. Sign the built executable before packaging:

```bash
signtool sign /tr http://timestamp.digicert.com /td sha256 /fd sha256 /a dist\WinnyTool.exe
```

3. Sign the installer after building it:

```bash
signtool sign /tr http://timestamp.digicert.com /td sha256 /fd sha256 /a dist\WinnyTool_Setup_v1.4.0.exe
```

`signtool` is included in the Windows SDK. The `/a` flag auto-selects the best certificate from the local certificate store.

---

## Updating the Version Number

When releasing a new version, update the version string in:

- `installer/winnytool_setup.nsi` -- the `PRODUCT_VERSION` define
- `installer/inno_setup.iss` -- the `MyAppVersion` define
- `.github/workflows/build.yml` -- the `WINNYTOOL_VERSION` env variable
