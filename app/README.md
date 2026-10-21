# Zero Breach desktop app

A windowed version of the scanner for Windows and macOS that needs **no Python
installed**. It runs exactly the same read-only checks as the command line, inside
the same no-network guard, and shows the same report. It adds no scanning logic.

## Downloads

Built by the [`desktop-app`](../.github/workflows/desktop-app.yml) workflow and
attached to each `v*` release, with `SHA256SUMS-desktop.txt`:

| platform | file |
|---|---|
| Windows 10/11 (64-bit) | `ZeroBreach-<version>-windows-x64.exe` |
| macOS 11+ Apple Silicon (M1 and later) | `ZeroBreach-<version>-macos-arm64.zip` |
| macOS 11+ Intel | `ZeroBreach-<version>-macos-x64.zip` |

Check the SHA-256 of the download against `SHA256SUMS-desktop.txt` before running:
`certutil -hashfile ZeroBreach-...exe SHA256` (Windows) or
`shasum -a 256 ZeroBreach-...zip` (macOS).

## Running it

- **Windows:** double-click the `.exe`. The builds are not code-signed yet, so
  SmartScreen may say "Windows protected your PC": choose **More info → Run anyway**.
  Some antivirus products flag PyInstaller apps generically; checksums are the
  way to confirm the file is the published one.
- **macOS:** unzip, then open **Zero Breach.app**. The builds are not notarized
  yet, so macOS blocks the first launch: open **System Settings → Privacy &
  Security** and click **Open Anyway** (or right-click the app → **Open** on
  older macOS). macOS may ask for permission to read browser data folders.

Close your web browsers first, tick **Quick scan** if you want it faster, and
click **Start scan**. When it finishes, **Save report…** writes the text report
and **Save JSON…** the machine-readable one. Reports can contain your username,
browser profile names and browsing details; do not post them publicly.

The optional experimental Candiru file-pattern check is included (the pinned
`yara-x` from `requirements-patterns.txt` is bundled), and appears as a checkbox.

## Building it yourself

Needs Python 3.9+ with Tk (the python.org installers include it).

```
python -m pip install -r app/requirements-build.txt
python -m pip install -r requirements-patterns.txt   # optional pattern engine
pyinstaller --noconfirm --clean --distpath app/dist --workpath app/build app/zero-breach.spec
```

Output: `app/dist/ZeroBreach.exe` on Windows, `app/dist/Zero Breach.app` on macOS.
PyInstaller does not cross-compile, so build each platform on that platform.
Check a build without opening a window:

```
app/dist/ZeroBreach --self-test        # or ".../Zero Breach.app/Contents/MacOS/ZeroBreach --self-test"
```

From source, without packaging: `python app/zero_breach_gui.py`.

## Signing (not done yet)

To remove the SmartScreen and Gatekeeper warnings, releases need a Windows
Authenticode certificate and an Apple Developer ID with notarization. Both can
be added as steps in the workflow once the certificates exist as repository
secrets.
