#!/usr/bin/env python3
"""Offline Linux application-directory bundler, using installed trusted packages.
No downloads and no automatic administrator operations. Never copies vault data.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import sysconfig

ROOT=Path(__file__).resolve().parents[1]
DIST=ROOT/'dist'
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', type=Path, default=DIST/'ClaraKey',
                    help='Clean build destination under dist/; existing vault data is never replaced.')
OUT=parser.parse_args().output.absolute()
if not OUT.resolve().is_relative_to(DIST.resolve()) or OUT.resolve()==DIST.resolve():
    raise SystemExit('Build output must be a child directory of dist/.')
if platform.system()!='Linux' or platform.machine()!='x86_64':
    raise SystemExit('This bundler currently targets Linux x86_64.')
if OUT.exists():
    # Preserve user data: refuse even if only one of the possible vault locations exists.
    if list(OUT.rglob('*.vault')) or (OUT/'.clarakey.lock').exists():
        raise SystemExit('Existing dist/ClaraKey contains vault data. Move it somewhere safe before rebuilding.')
    shutil.rmtree(OUT)
OUT.mkdir(parents=True)
RUNTIME=OUT/'runtime'
LIB=RUNTIME/'lib'
LIB.mkdir(parents=True)
(RUNTIME/'bin').mkdir()
(RUNTIME/'etc').mkdir()
(RUNTIME/'share').mkdir()
(OUT/'app').mkdir()
for folder in ('vault','backups'):
    (OUT/folder).mkdir(mode=0o700)
ignore=shutil.ignore_patterns('__pycache__','*.pyc','test','tests','tkinter','idlelib','ensurepip','turtledemo')
stdlib=Path(sysconfig.get_path('stdlib'))
shutil.copytree(stdlib,LIB/('python'+sysconfig.get_python_version()),ignore=ignore,dirs_exist_ok=True)
shutil.copy2(sys.executable,RUNTIME/'bin/python3')
packages=LIB/'python3/dist-packages'; packages.mkdir(parents=True)
for name in ('cryptography','gi','cairo'):
    spec=importlib.util.find_spec(name)
    if not spec or not spec.origin:
        raise SystemExit('Missing installed package: '+name)
    shutil.copytree(Path(spec.origin).parent,packages/name,ignore=ignore)
backend = Path(importlib.util.find_spec('_cffi_backend').origin)
shutil.copy2(backend, packages/backend.name)
typing_extensions = Path(importlib.util.find_spec('typing_extensions').origin)
shutil.copy2(typing_extensions, packages/typing_extensions.name)
shutil.copytree(ROOT/'clarakey',OUT/'app/clarakey',ignore=ignore)
shutil.copy2(ROOT/'run.py',OUT/'app/run.py')

# ldd is used only on installed executable/shared objects, never on vault or imported data.
origins=set()
def dependencies(path):
    result=subprocess.run(['ldd',str(path)],text=True,capture_output=True)
    deps=[]
    for line in result.stdout.splitlines():
        if 'not found' in line:
            raise SystemExit('Unresolved runtime dependency while packaging '+path.name)
        match=re.search(r'(?:=>\s+)?(/[^\s]+)',line)
        if match: deps.append(Path(match.group(1)))
    return deps

seeds=[Path(sys.executable)]
seeds.append(backend)
seeds.extend(stdlib.rglob('*.so'))
for name in ('cryptography','gi','cairo'):
    seeds.extend(Path(importlib.util.find_spec(name).origin).parent.rglob('*.so'))
multiarch=sysconfig.get_config_var('MULTIARCH')
system_lib=Path('/usr/lib')/multiarch
for name in ('libgtk-4.so.1','libgirepository-2.0.so.0','libgirepository-1.0.so.1','libgdk_pixbuf-2.0.so.0',
             'libpangocairo-1.0.so.0','libpangoft2-1.0.so.0','libcairo-gobject.so.2','libgmodule-2.0.so.0'):
    path=system_lib/name
    if path.exists(): seeds.append(path)
for path in seeds:
    for dep in dependencies(path)+([path] if path.parent==system_lib else []):
        if dep.name.startswith('ld-linux'):
            target=RUNTIME/'ld-linux-x86-64.so.2'
        else:
            target=LIB/dep.name
        if not target.exists(): shutil.copy2(dep.resolve(),target)
        origins.add(dep.resolve())

types=LIB/'girepository-1.0'; types.mkdir()
for name in ('Gtk-4.0','Gdk-4.0','Gsk-4.0','GLib-2.0','GObject-2.0','Gio-2.0','GModule-2.0',
             'GdkPixbuf-2.0','Pango-1.0','PangoCairo-1.0','HarfBuzz-0.0','cairo-1.0','freetype2-2.0',
             'Graphene-1.0','GIRepository-2.0','GIRepository-3.0','GdkX11-4.0','GdkWayland-4.0'):
    path=system_lib/'girepository-1.0'/(name+'.typelib')
    if path.exists(): shutil.copy2(path,types/path.name)
fonts=RUNTIME/'share/fonts'; fonts.mkdir()
for name in ('DejaVuSans.ttf','DejaVuSans-Bold.ttf','DejaVuSansMono.ttf'):
    shutil.copy2(Path('/usr/share/fonts/truetype/dejavu')/name,fonts/name)
(RUNTIME/'etc/fonts.conf').write_text('''<?xml version="1.0"?>
<!DOCTYPE fontconfig SYSTEM "fonts.dtd">
<fontconfig><dir prefix="relative">../share/fonts</dir>
<cachedir prefix="relative">../cache/fontconfig</cachedir>
<alias><family>sans-serif</family><prefer><family>DejaVu Sans</family></prefer></alias>
<alias><family>monospace</family><prefer><family>DejaVu Sans Mono</family></prefer></alias></fontconfig>
''')
# GTK includes symbolic fallback icons in its resources; no desktop-specific theme needed.
(RUNTIME/'lib/gio/modules').mkdir(parents=True)
for name in ('README.md','ARCHITECTURE.md','SECURITY.md','THREAT_MODEL.md','VAULT_FORMAT.md','LICENSE'):
    if (ROOT/name).exists(): shutil.copy2(ROOT/name,OUT/name)
if (ROOT/'docs').exists(): shutil.copytree(ROOT/'docs',OUT/'docs')
shutil.copy2(ROOT/'packaging/AppRun',OUT/'ClaraKey')
shutil.copy2(ROOT/'packaging/AppRun',OUT/'AppRun')
for name in ('ClaraKey','AppRun'): (OUT/name).chmod(0o755)
shutil.copy2(ROOT/'packaging/clarakey.desktop',OUT/'clarakey.desktop')
shutil.copy2(ROOT/'packaging/clarakey.svg',OUT/'clarakey.svg')
(OUT/'README.txt').write_text('ClaraKey portable Linux vault\n\nRun ./ClaraKey from a trusted Linux desktop. Keep this whole directory together.\nVault data stays in vault/ and encrypted copies in backups/.\nSee README.md, SECURITY.md and docs/TEST_RESULTS.md before using real credentials.\n')

# Preserve vendor copyright/license notices for all bundled installed packages.
licenses=OUT/'licenses'; licenses.mkdir()
packages_used=set()
for source in sorted(origins|{backend,typing_extensions,Path(sys.executable),Path(importlib.util.find_spec('gi').origin),
                             Path(importlib.util.find_spec('cryptography').origin),Path(importlib.util.find_spec('cairo').origin)}):
    result=subprocess.run(['dpkg-query','-S',str(source)],capture_output=True,text=True)
    if result.returncode==0:
        packages_used.add(result.stdout.split(': ')[0])
for package in sorted(packages_used|{'fonts-dejavu-core'}):
    source=Path('/usr/share/doc')/package.split(':')[0]/'copyright'
    if source.exists(): shutil.copy2(source,licenses/(package.replace(':','_')+'.copyright'))
versions=subprocess.run(['dpkg-query','-W','-f=${binary:Package}\t${Version}\t${source:Package}\t${source:Version}\n',*sorted(packages_used)],capture_output=True,text=True)
(OUT/'THIRD_PARTY.txt').write_text('Bundled installed package versions and source package identifiers:\n'+versions.stdout+
    '\nVendor copyright/license texts are in licenses/. Obtain corresponding source from the Ubuntu/Debian source archives for these exact versions before redistribution where licenses require it. This local build does not itself establish third-party source-distribution compliance.\n')
manifest={str(path.relative_to(OUT)):hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(OUT.rglob('*')) if path.is_file()}
(OUT/'MANIFEST.sha256').write_text(''.join(digest+'  '+path+'\n' for path,digest in manifest.items()))
print('Portable application directory:',OUT)
print('Bundled files:',len(manifest))
