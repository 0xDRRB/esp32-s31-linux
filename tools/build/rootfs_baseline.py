#!/usr/bin/env python3
"""Explicit incremental rootfs repack; never masquerades as a clean Buildroot build."""
import argparse
import ast
from datetime import datetime, timezone
import hashlib
import json
import lzma
import os
from pathlib import Path
import posixpath
import re
import stat
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
MODULE = 'usr/lib/s31-radio/esp32s31-radio.ko.xz'
RETIRED_DIAGNOSTICS = (
    'usr/bin/coremark', 'usr/bin/spidev_test',
    'usr/bin/s31-hil-agent', 'usr/bin/s31-peripheral-test',
    'usr/bin/s31-selftest', 'usr/sbin/segfault', 'usr/sbin/forktest',
    'usr/sbin/membench', 'usr/sbin/s31-crypto-test',
    'usr/sbin/s31-ext-test', 'usr/sbin/s31-libc-test',
    'usr/sbin/s31-mem-compare', 'usr/sbin/s31-string-bench',
    'usr/sbin/s31-hil-io', 'usr/sbin/s31-tlb-stress',
    'usr/sbin/s31-cpu-sample',
)
SERVICE_SCRIPTS = ('etc/init.d/S01syslogd', 'etc/init.d/S02klogd', 'etc/init.d/S50crond')
# The explicit repack mode must not turn an incomplete userspace into a full
# build by relabeling it. Inherited binaries are never claimed to be rebuilt.
FULL_RUNTIME = [
    *SERVICE_SCRIPTS,
    'usr/bin/aplay', 'usr/bin/arecord', 'usr/bin/candump', 'usr/bin/cansend',
    'usr/sbin/i2cdetect', 'usr/sbin/i2cdump', 'usr/sbin/i2cget',
    'usr/sbin/i2cset', 'usr/sbin/i2ctransfer',
    'usr/sbin/s31-btstack-a2dp',
]
SERVICE_APPLETS = ('bin/sh', 'bin/rm', 'bin/sleep', 'sbin/start-stop-daemon',
                   'sbin/syslogd', 'sbin/klogd', 'usr/sbin/crond')
SERVICE_CONFIG = (
    'SYSLOGD', 'KLOGD', 'CROND', 'START_STOP_DAEMON',
    'FEATURE_START_STOP_DAEMON_LONG_OPTIONS', 'FEATURE_START_STOP_DAEMON_FANCY',
    'LONG_OPTS', 'RM', 'SLEEP', 'FEATURE_FANCY_SLEEP',
    'SH_IS_ASH', 'ASH', 'ASH_ECHO', 'ASH_PRINTF', 'ASH_TEST',
    'SHOW_USAGE', 'FEATURE_VERBOSE_USAGE',
)


def verify_full_inputs(kernel_output, entries, restorable=(), incremental_radio_update=False):
    if not incremental_radio_update:
        modules = (kernel_output / 'modules.order').read_text().splitlines()
        if modules != ['drivers/platform/esp32s31-radio.o']:
            raise SystemExit('Baseline repack supports only the radio module; full kernel has additional or missing modules. Use native Buildroot.')
    allowed = set(restorable) & set(SERVICE_SCRIPTS)
    missing = [name for name in FULL_RUNTIME if name not in entries and name not in allowed]
    if missing:
        raise SystemExit('Baseline does not satisfy full userspace requirements; use native Buildroot. Missing: ' + ', '.join(missing))

    for name in FULL_RUNTIME:
        if name not in entries:
            continue
        path = name
        seen = set()
        while entries.get(path, {}).get('mode', '')[:1] == 'l' and path not in seen:
            seen.add(path)
            link = entries[path]['link']
            path = posixpath.normpath(link.lstrip('/') if link.startswith('/') else posixpath.join(posixpath.dirname(path), link))
        mode = entries.get(path, {}).get('mode', '')
        if not mode.startswith('-') or not any(c in mode[3::3] for c in 'xst'):
            raise SystemExit('Baseline full userspace entry is not executable: ' + name)


def sha(p):
    with Path(p).open('rb') as f: return hashlib.file_digest(f, 'sha256').hexdigest()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(args):
    env = dict(os.environ)
    # Repacking must preserve baseline inode timestamps, even if native builds
    # use a deterministic source epoch earlier than the inherited filesystem.
    if str(args[0]) == 'mksquashfs': env.pop('SOURCE_DATE_EPOCH', None)
    subprocess.run(list(map(str, args)), check=True, env=env)


def metadata(image):
    output = subprocess.check_output(['unsquashfs', '-lln', '-full-precision', '-UTC', str(image)], text=True)
    entries = {}
    for line in output.splitlines():
        match = re.match(r'^(\S{10}) (\d+)/(\d+)\s+\d+ (\S+) (\S+) squashfs-root(?:/(.*))?$', line)
        if not match: raise SystemExit('Unsupported SquashFS listing entry: ' + line)
        mode, uid, gid, date, time, path = match.groups()
        path = path or '.'
        path, _, link = path.partition(' -> ')
        if mode[0] not in '-dl': raise SystemExit('Baseline contains unsupported special inode: ' + path)
        entries[path] = {'mode': mode, 'uid': int(uid), 'gid': int(gid), 'date': date, 'time': time, 'link': link}
    return entries


def c_string_bytes(text):
    """Read generated C string literals, never evaluate source as Python code."""
    return b''.join(ast.literal_eval('b' + token) for token in re.findall(r'"(?:[^"\\]|\\.)*"', text))


def verify_service_busybox(binary, build, entries):
    """Conservative offline check: require config, applet table AND exact help.

    A nearby .config alone cannot establish an inherited binary's capabilities.
    Matching generated applet/help data and the actual long-option parser table
    binds the required features to that binary, without pretending to run it.
    Other BusyBox layouts/configurations must use a native Buildroot build.
    """
    inputs = {name: (build / name).read_bytes() for name in
              ('.config', 'include/applet_tables.h', 'include/usage_compressed.h')}
    config = set(inputs['.config'].decode().splitlines())
    missing = [name for name in SERVICE_CONFIG if f'CONFIG_{name}=y' not in config]
    if missing or 'CONFIG_FEATURE_CROND_DIR="/etc/cron"' not in config:
        raise SystemExit('BusyBox build config lacks required service options: ' + ', '.join(missing or ['FEATURE_CROND_DIR=/etc/cron']))
    if 'CONFIG_FEATURE_COMPRESS_USAGE=y' in config:
        raise SystemExit('Service restoration requires matching uncompressed BusyBox usage data')
    for path in SERVICE_APPLETS:
        entry = entries.get(path, {})
        resolved = posixpath.normpath(posixpath.join(posixpath.dirname(path), entry.get('link', '')))
        if entry.get('mode', '')[:1] != 'l' or resolved != 'bin/busybox':
            raise SystemExit('Baseline lacks a verified BusyBox service applet link: ' + path)
    for path in ('bin/busybox', 'etc/init.d/rcS', 'etc/inittab', 'etc/cron', 'etc/cron/crontabs', 'var/log', 'run'):
        if path not in entries:
            raise SystemExit('Baseline lacks service runtime support: ' + path)
    try:
        table = inputs['include/applet_tables.h'].decode().split('const char applet_names[] ALIGN1 =', 1)[1].split(';', 1)[0]
        applets = c_string_bytes(table)
        usage = c_string_bytes(inputs['include/usage_compressed.h'].decode().split('#define UNPACKED_USAGE_LENGTH', 1)[0])
    except (IndexError, SyntaxError, ValueError) as exc:
        raise SystemExit('Unsupported generated BusyBox applet/usage data') from exc
    if not applets or not usage or binary.count(applets) != 1 or binary.count(usage) != 1:
        raise SystemExit('Baseline BusyBox does not match the supplied generated applet/usage data')
    names = applets.rstrip(b'\0').split(b'\0')
    help_entries = usage.rstrip(b'\0').split(b'\0')
    if len(names) != len(help_entries) or len(set(names)) != len(names):
        raise SystemExit('Invalid BusyBox applet/usage table')
    helps = dict(zip(names, help_entries))
    requirements = {
        b'syslogd': (b'\t-n\t',), b'klogd': (b'\t-n\t',),
        b'crond': (b'\t-f\t', b'/etc/cron/crontabs'),
        b'start-stop-daemon': (b'\t-b\t', b'\t-m\t', b'\t-t\t', b'\t-q\t'),
        b'sleep': (b'[N]...', b'(s)econds'), b'sh': (b'Unix shell interpreter',), b'rm': (b'\t-f\t',),
    }
    for name, markers in requirements.items():
        if any(marker not in helps.get(name, b'') for marker in markers):
            raise SystemExit('Baseline BusyBox lacks required service usage: ' + name.decode())
    # getopt32's compiled long-options data: argument arity and short option.
    for option, arity, short in [('stop', 0, 'K'), ('start', 0, 'S'), ('background', 0, 'b'),
                                 ('quiet', 0, 'q'), ('test', 0, 't'), ('make-pidfile', 0, 'm'),
                                 ('pidfile', 1, 'p'), ('exec', 1, 'x')]:
        if option.encode() + b'\0' + bytes([arity]) + short.encode() not in binary:
            raise SystemExit('Baseline BusyBox lacks required start-stop-daemon option: --' + option)
    return {'busybox_sha256': digest(binary),
            'busybox_build_inputs_sha256': {name: digest(data) for name, data in inputs.items()},
            'verified_config_options': list(SERVICE_CONFIG) + ['FEATURE_CROND_DIR=/etc/cron'],
            'verification': 'Static matching applet/usage data and compiled option table; not target-runtime tested.'}


def service_restoration(baseline, entries, source, busybox_build):
    missing = [path for path in SERVICE_SCRIPTS if path not in entries]
    if not missing:
        return {}, {}
    if source is None or busybox_build is None:
        raise SystemExit('Restoring missing full-service scripts requires --restore-full-services-from and --busybox-build; otherwise use native Buildroot.')
    # Only the recorded, unchanged submodule scripts qualify as stock sources.
    pin = subprocess.check_output(['git', '-C', str(ROOT), 'ls-tree', 'HEAD', 'buildroot'], text=True).split()
    head = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
    if len(pin) != 4 or pin[0] != '160000' or head != pin[2]:
        raise SystemExit('Service restoration source does not match the pinned Buildroot commit')
    scripts = {}
    for path in missing:
        relative = 'package/busybox/' + Path(path).name
        stock = subprocess.check_output(['git', '-C', str(source), 'show', f'{head}:{relative}'])
        if (source / relative).read_bytes() != stock:
            raise SystemExit('Modified Buildroot service source is not allowed: ' + relative)
        scripts[path] = stock
    if entries.get('etc/init.d', {}).get('mode', '')[:1] != 'd':
        raise SystemExit('Baseline lacks a real etc/init.d directory')
    binary = subprocess.check_output(['unsquashfs', '-cat', str(baseline), 'bin/busybox'])
    evidence = verify_service_busybox(binary, busybox_build, entries)
    evidence.update(buildroot_commit=head, scripts={path: {'source': 'package/busybox/' + Path(path).name,
                                                         'sha256': digest(data)} for path, data in scripts.items()})
    return scripts, evidence


def contents(tree):
    return {str(p.relative_to(tree)): sha(p) for p in tree.rglob('*') if p.is_file() and not p.is_symlink()}


def install_services(tree, scripts, before):
    """Add only missing scripts; preserve the inherited init directory mtime."""
    expected = dict(before)
    if not scripts:
        return expected
    parent = tree / 'etc/init.d'
    timestamp = parent.stat().st_mtime_ns
    for path, data in scripts.items():
        target = tree / path
        with target.open('xb') as stream:
            stream.write(data)
        target.chmod(0o755)
        os.utime(target, ns=(timestamp, timestamp))
        expected[path] = dict(before['etc/init.d'], mode='-rwxr-xr-x', uid=0, gid=0, link='')
    os.utime(parent, ns=(timestamp, timestamp))
    return expected


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for flag in ['baseline', 'module', 'output', 'report', 'staging']: p.add_argument('--'+flag, type=Path, required=True)
    p.add_argument('--kernel-output', type=Path, required=True)
    p.add_argument('--incremental-radio-update', action='store_true', help='Update the qualified radio artifact only; do not claim a full kernel-module installation')
    p.add_argument('--replacement-manifest', type=Path, help='Explicit target-relative files and local sources; preserves inherited metadata')
    p.add_argument('--restore-full-services-from', type=Path)
    p.add_argument('--busybox-build', type=Path)
    p.add_argument('--strip', required=True); p.add_argument('--jobs', default='4')
    a = p.parse_args()
    before = metadata(a.baseline)
    verify_full_inputs(a.kernel_output, before, SERVICE_SCRIPTS if a.restore_full_services_from else (), a.incremental_radio_update)
    scripts, restoration = service_restoration(a.baseline, before, a.restore_full_services_from, a.busybox_build)
    replacements = {}
    if a.replacement_manifest:
        entries = json.loads(a.replacement_manifest.read_text())
        if not isinstance(entries, dict):
            raise SystemExit('Replacement manifest must map target-relative paths to source specifications')
        for target_path, spec in entries.items():
            if not isinstance(target_path, str) or target_path.startswith('/') or posixpath.normpath(target_path) != target_path or '..' in target_path.split('/') or any(c.isspace() for c in target_path):
                raise SystemExit('Invalid replacement path: ' + repr(target_path))
            if target_path in {'.', MODULE, *scripts, *RETIRED_DIAGNOSTICS}:
                raise SystemExit('Conflicting replacement path: ' + target_path)
            if isinstance(spec, str): spec = {'source': spec}
            if not isinstance(spec, dict) or set(spec) - {'source', 'mode'} or 'source' not in spec:
                raise SystemExit('Invalid replacement specification: ' + target_path)
            source = Path(spec['source']).resolve(strict=True)
            if not source.is_file(): raise SystemExit('Replacement source is not a regular file: ' + str(source))
            entry = before.get(target_path)
            if entry:
                if not entry['mode'].startswith('-') or 'mode' in spec:
                    raise SystemExit('Existing replacements must preserve regular-file metadata: ' + target_path)
            else:
                parent = before.get(posixpath.dirname(target_path))
                if not parent or not parent['mode'].startswith('d') or 'mode' not in spec:
                    raise SystemExit('New files require an existing parent and explicit mode: ' + target_path)
                mode = int(spec['mode'], 8)
                if mode & ~0o777: raise SystemExit('Invalid new-file mode: ' + target_path)
                entry = dict(before['.'], mode=stat.filemode(stat.S_IFREG | mode), link='')
            replacements[target_path] = {'source': source, 'sha256': sha(source), 'metadata': entry}
    ident = {'kernel_config_sha256': sha(a.kernel_output / '.config'), 'modules_order_sha256': None if a.incremental_radio_update else sha(a.kernel_output / 'modules.order'), 'full_runtime_contract_verified': True, 'optimization': 'Inherited userspace binaries; optimization flags are not reverified or changed.', 'mode': 'incremental-baseline', 'baseline_sha256': sha(a.baseline), 'module_sha256': sha(a.module), 'repacker_sha256': sha(__file__), 'strip_sha256': sha(shutil.which(a.strip) or a.strip), 'limitation': 'Userspace inherited from explicit baseline; not a clean source build.', 'service_restoration': restoration}
    ident['full_kernel_module_inventory_verified'] = not a.incremental_radio_update
    ident['incremental_radio_update'] = a.incremental_radio_update
    ident['replacement_manifest_sha256'] = sha(a.replacement_manifest) if a.replacement_manifest else None
    ident['replacement_files'] = {path: {'source': str(spec['source']), 'sha256': spec['sha256'], 'metadata': spec['metadata']} for path, spec in replacements.items()}
    if a.report.exists() and a.output.exists():
        old = json.loads(a.report.read_text())
        if all(old.get(k) == v for k,v in ident.items()) and old.get('rootfs_sha256') == sha(a.output):
            print('Baseline rootfs inputs unchanged; keeping verified image.')
            return
    if MODULE not in before: raise SystemExit('Baseline lacks the expected radio module')
    a.staging.mkdir(parents=True, exist_ok=True); a.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='rootfs-baseline-', dir=a.staging) as work:
        work = Path(work); tree = work / 'tree'
        run(['unsquashfs', '-no-progress', '-d', tree, a.baseline])
        initial = contents(tree)
        expected = install_services(tree, scripts, before)
        # File additions change parent timestamps. Restore every inherited
        # directory after installation, preserving the baseline metadata.
        directory_times = {path: (tree / path).stat().st_mtime_ns for path, entry in before.items() if entry['mode'].startswith('d')}
        for path in RETIRED_DIAGNOSTICS:
            if path in expected:
                target = tree / path
                if target.is_dir() and not target.is_symlink():
                    raise SystemExit('Expected a retired executable, found directory: ' + path)
                target.unlink()
                expected.pop(path)
        for path, spec in replacements.items():
            destination = tree / path
            timestamp = destination.stat().st_mtime_ns if path in before else int(datetime.fromisoformat(spec['metadata']['date'] + 'T' + spec['metadata']['time']).replace(tzinfo=timezone.utc).timestamp()) * 1000000000
            destination.write_bytes(spec['source'].read_bytes())
            if path not in before:
                destination.chmod(int(entries[path]['mode'], 8))
                expected[path] = spec['metadata']
            os.utime(destination, ns=(timestamp, timestamp))
        for path, timestamp in directory_times.items():
            os.utime(tree / path, ns=(timestamp, timestamp))
        target = tree / MODULE; timestamp = target.stat().st_mtime_ns
        module = work / 'esp32s31-radio.ko'
        run([a.strip, '--strip-debug', '-o', module, a.module])
        target.write_bytes(lzma.compress(module.read_bytes(), format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC32, filters=[{'id': lzma.FILTER_LZMA2, 'dict_size': 65536}]))
        os.utime(target, ns=(timestamp, timestamp))
        pseudo = work / 'metadata.pseudo'
        lines = []
        for path, entry in expected.items():
            if path == '.': continue
            if any(c.isspace() for c in path): raise SystemExit('Whitespace path unsupported by metadata repacker')
            text = entry['mode']
            mode = sum(bit for char, bit in zip(text[1:], [256,128,64,32,16,8,4,2,1]) if char not in '-ST')
            if text[3] in 'sS': mode |= stat.S_ISUID
            if text[6] in 'sS': mode |= stat.S_ISGID
            if text[9] in 'tT': mode |= stat.S_ISVTX
            lines.append(f"{path} m {mode:o} {entry['uid']} {entry['gid']}\n")
        pseudo.write_text(''.join(lines))
        temp_image = work / 'rootfs.sqfs'
        run(['mksquashfs', tree, temp_image, '-noappend', '-comp', 'xz', '-b', '65536', '-processors', a.jobs, '-root-time', str(int(tree.stat().st_mtime)), '-root-uid', str(before['.']['uid']), '-root-gid', str(before['.']['gid']), '-pf', pseudo, '-no-progress'])
        after = metadata(temp_image)
        if expected != after: raise SystemExit('Rootfs metadata changed; refusing publication: ' + json.dumps({k: [expected.get(k), after.get(k)] for k in expected.keys() | after.keys() if expected.get(k) != after.get(k)}, sort_keys=True))
        if any(path in after for path in RETIRED_DIAGNOSTICS):
            raise SystemExit('Retired diagnostics survived baseline repack')
        verify_full_inputs(a.kernel_output, after, incremental_radio_update=a.incremental_radio_update)
        verify = work / 'verify'; run(['unsquashfs', '-no-progress', '-d', verify, temp_image])
        final = contents(verify)
        changed = sorted(k for k in initial.keys() | final.keys() if initial.get(k) != final.get(k))
        if set(changed) - {MODULE, *scripts, *replacements, *RETIRED_DIAGNOSTICS}: raise SystemExit('Unexpected rootfs content changes: ' + str(changed))
        for path, data in scripts.items():
            if (verify / path).read_bytes() != data: raise SystemExit('Restored service verification failed: ' + path)
        if lzma.decompress((verify / MODULE).read_bytes()) != module.read_bytes(): raise SystemExit('Installed module verification failed')
        for path, spec in replacements.items():
            if sha(verify / path) != spec['sha256']:
                raise SystemExit('Installed replacement verification failed: ' + path)
        ident.update(rootfs_sha256=sha(temp_image), changed_files=changed, restored_service_scripts=sorted(scripts), metadata_entries=len(after), inherited_files=len(initial), metadata_preserved=True, packaged_module_sha256=sha(verify / MODULE), stripped_module_sha256=sha(module))
        os.replace(temp_image, a.output)
        a.report.parent.mkdir(parents=True, exist_ok=True)
        tmp = a.report.with_suffix('.tmp'); tmp.write_text(json.dumps(ident, indent=2, sort_keys=True)+'\n'); tmp.replace(a.report)
        print(json.dumps(ident, indent=2))

if __name__ == '__main__': main()
