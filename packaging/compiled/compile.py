#!/usr/bin/env python3
"""
Runs inside the build image (packaging/compiled/Dockerfile) and turns Network VMap's Python into a form shipped without
source:

  - the modules in cython_modules.txt (the drivers, check rules, version logic and the SSH executor: the know-how)
    become native .so files (compiled C);
  - every other .py under the shipped trees becomes a sourceless .pyc next to where it was (Python imports it the same);
  - every .py (and Cython's .c leftovers, __pycache__) is then removed, so no readable source ships;
  - vendor/lab-only files are dropped.

manage.py stays as text: it is a three-line launcher. Templates, static files, help .md and JSON are not Python and are
untouched. The build fails if the compiled tree no longer passes Django's checks or cannot load every module.

    python packaging/compiled/compile.py [tree ...]     (default: apps config labnet collector)
"""
import importlib
import os
import py_compile
import shutil
import subprocess
import sys
from pathlib import Path

os.environ.setdefault("SETUPTOOLS_USE_DISTUTILS", "local")

ROOT = Path.cwd()
LIST = Path(__file__).with_name("cython_modules.txt")
KEEP_SOURCE = {"manage.py"}
DROP = {"apps/core/management/commands/lab_setup.py"}       # sets up the mock lab: vendor only


def cython_targets(trees):
    out = []
    for line in LIST.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or not any(line.startswith(t + "/") for t in trees):
            continue
        p = ROOT / line
        if not p.is_file():
            sys.exit(f"compile: {line} in cython_modules.txt does not exist")
        out.append(p)
    return out


def native(paths):
    if not paths:
        return
    import setuptools  # noqa: F401  (its distutils shim must load before Cython)
    from Cython.Build import cythonize
    from setuptools.dist import Distribution
    exts = cythonize([str(p.relative_to(ROOT)) for p in paths], quiet=True, nthreads=os.cpu_count() or 2,
                     compiler_directives={"language_level": "3", "infer_types": False, "annotation_typing": False,
                                          "binding": True, "embedsignature": False, "emit_code_comments": False})
    dist = Distribution({"ext_modules": exts})
    cmd = dist.get_command_obj("build_ext")
    cmd.inplace = 1
    cmd.parallel = os.cpu_count() or 2
    cmd.ensure_finalized()
    cmd.run()
    for p in paths:
        if not list(p.parent.glob(p.stem + ".*.so")):
            sys.exit(f"compile: no .so produced for {p.relative_to(ROOT)}")
        p.unlink()
        p.with_suffix(".c").unlink(missing_ok=True)
        print(f"native   {p.relative_to(ROOT)}")
    shutil.rmtree(ROOT / "build", ignore_errors=True)


def main():
    trees = sys.argv[1:] or ["apps", "config", "labnet", "collector"]
    for rel in DROP:
        (ROOT / rel).unlink(missing_ok=True)
    for tree in trees:                                   # stale caches never ship
        for d in list((ROOT / tree).rglob("__pycache__")):
            shutil.rmtree(d)
        for f in (ROOT / tree).rglob("*.pyc"):
            f.unlink()
    nat = cython_targets(trees)
    native(nat)
    n = 0
    for tree in trees:
        for py in sorted((ROOT / tree).rglob("*.py")):
            if py.relative_to(ROOT).as_posix() in KEEP_SOURCE:
                continue
            py_compile.compile(str(py), cfile=str(py.with_suffix(".pyc")), doraise=True, optimize=0)
            py.unlink()
            n += 1
    for tree in trees:
        for d in list((ROOT / tree).rglob("__pycache__")):
            shutil.rmtree(d)
        left = [p for p in (ROOT / tree).rglob("*") if p.suffix in (".py", ".c", ".pyx")]
        if left:
            sys.exit(f"compile: source left behind: {[str(p) for p in left[:5]]}")
    print(f"compiled {len(nat)} native modules and {n} bytecode modules; no .py left in {', '.join(trees)}")
    if "apps" in trees:
        check_django()


def check_django():
    env = {**os.environ, "DJANGO_SETTINGS_MODULE": "config.settings", "DJANGO_SECRET_KEY": "x" * 60,
           "VMAP_VAR_DIR": "/tmp/vmap-check", "DATABASE_URL": "sqlite:////tmp/vmap-check/db.sqlite3"}
    for cmd in (["manage.py", "check"], ["manage.py", "makemigrations", "--check", "--dry-run"]):
        if subprocess.run([sys.executable, *cmd], cwd=ROOT, env=env).returncode:
            sys.exit(f"compile: the compiled app fails 'manage.py {' '.join(cmd[1:])}'")
    # import every module once: a module that only fails when first used (a Cython quirk) fails the build here instead
    code = ("import django,pkgutil,importlib; django.setup()\n"
            "import apps, labnet, collector\n"
            "bad=[]\n"
            "for pkg in (apps, labnet, collector):\n"
            "    for m in pkgutil.walk_packages(pkg.__path__, pkg.__name__ + '.'):\n"
            "        try: importlib.import_module(m.name)\n"
            "        except Exception as e: bad.append(f'{m.name}: {e!r}')\n"
            "print('\\n'.join(bad)); raise SystemExit(1 if bad else 0)\n")
    if subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env).returncode:
        sys.exit("compile: some compiled modules do not import (above)")
    print("compiled app passes manage.py check and imports every module")


if __name__ == "__main__":
    main()
