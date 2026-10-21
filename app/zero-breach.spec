# PyInstaller spec for the Zero Breach desktop app.
#
#   pyinstaller --noconfirm --clean --distpath app/dist --workpath app/build app/zero-breach.spec
#
# Windows: app/dist/ZeroBreach.exe (one file, no console window).
# macOS:   app/dist/Zero Breach.app.
# Linux:   app/dist/ZeroBreach (one file; not a release target, but handy for testing).
#
# The optional Candiru pattern engine (yara-x) is bundled when it is installed in
# the build environment from requirements-patterns.txt; without it the app still
# builds and the pattern option shows as unavailable.
import os
import sys

from PyInstaller.utils.hooks import collect_submodules, copy_metadata

ROOT = os.path.dirname(SPECPATH)
sys.path.insert(0, os.path.join(ROOT, "scan"))
from adint_scan import __version__  # noqa: E402

hiddenimports = collect_submodules("adint_scan")
datas = [
    (os.path.join(ROOT, "iocs", "adfection_iocs.txt"), "iocs"),
    (os.path.join(ROOT, "LICENSE"), "."),
    (os.path.join(ROOT, "NOTICE"), "."),
    (os.path.join(ROOT, "third_party", "candiru"), os.path.join("third_party", "candiru")),
]
try:
    import yara_x  # noqa: F401
except ImportError:
    print("zero-breach.spec: yara-x not installed; building without the pattern engine")
else:
    hiddenimports.append("yara_x")
    # patternscan checks importlib.metadata.version("yara-x"); ship the metadata.
    datas += copy_metadata("yara-x")

a = Analysis(
    [os.path.join(SPECPATH, "zero_breach_gui.py")],
    pathex=[os.path.join(ROOT, "scan")],
    hiddenimports=hiddenimports,
    datas=datas,
    excludes=["pytest", "unittest.mock", "pydoc_data"],
    noarchive=False,
)
pyz = PYZ(a.pure)

if sys.platform == "darwin":
    exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name="ZeroBreach",
              console=False, upx=False, argv_emulation=False)
    coll = COLLECT(exe, a.binaries, a.datas, upx=False, name="ZeroBreach")
    app = BUNDLE(
        coll,
        name="Zero Breach.app",
        bundle_identifier="org.techforpalestine.zerobreach",
        version=__version__,
        info_plist={
            "CFBundleShortVersionString": __version__,
            "CFBundleVersion": __version__,
            "NSHighResolutionCapable": True,
            "LSMinimumSystemVersion": "11.0",
        },
    )
else:
    exe = EXE(pyz, a.scripts, a.binaries, a.datas, [], name="ZeroBreach",
              console=False, upx=False, runtime_tmpdir=None)
