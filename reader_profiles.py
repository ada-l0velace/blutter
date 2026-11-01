"""Explicit snapshot readers. A failed official download is not identification."""
from dataclasses import dataclass

SHOREBIRD_HASH = '3c9c63bc42bff27a9fd51d020f3771ec'
SHOREBIRD_ENGINE = '4b936a0c03e13389ddfb1ac48823f187964975c2'
SHOREBIRD_BASE = '04bcd1036cdc799ac6564988f159ee454d42c822'
SHOREBIRD_PROFILE = 'shorebird_3c9c'
SHOREBIRD_312_HASH = '839937ddd3133a1c0758aeeefce5448c'
SHOREBIRD_312_ENGINE = 'a787a8fe98e99918255bb4bf4835f6ae010c1035'
SHOREBIRD_312_BASE = 'd684a576a6aa954ae107a03b2b4e1d61c3bebe93'
SHOREBIRD_312_PROFILE = 'shorebird_8399'


@dataclass(frozen=True)
class RuntimeProfile:
    version: str
    snapshot_hash: str
    engine: str
    source_base: str
    macro: str
    patch: str


RUNTIME_PROFILES = {
    SHOREBIRD_PROFILE: RuntimeProfile('3.13.5', SHOREBIRD_HASH, SHOREBIRD_ENGINE,
                                     SHOREBIRD_BASE, 'BLUTTER_SHOREBIRD_3C9C',
                                     'shorebird_3c9c_runtime.patch'),
    SHOREBIRD_312_PROFILE: RuntimeProfile('3.12.2', SHOREBIRD_312_HASH,
                                         SHOREBIRD_312_ENGINE, SHOREBIRD_312_BASE,
                                         'BLUTTER_SHOREBIRD_8399',
                                         'shorebird_8399_runtime.patch'),
}


def runtime_profile(name):
    if name is None:
        return None
    if name not in RUNTIME_PROFILES:
        raise ValueError(f'Unknown runtime reader profile: {name}')
    return RUNTIME_PROFILES[name]

# Runtime-format identifiers, independent of individual application contents.
UNSUPPORTED_FORMATS = {}


def reader_profile(version, os_name, arch, compressed, snapshot_hash):
    if snapshot_hash in UNSUPPORTED_FORMATS:
        raise RuntimeError(
            f'Unsupported snapshot format: {UNSUPPORTED_FORMATS[snapshot_hash]} '
            f'({snapshot_hash}). A compatible reader has not been verified; '
            'an upstream SDK download or hash replacement will not supply one.')
    for name, profile in RUNTIME_PROFILES.items():
        if snapshot_hash == profile.snapshot_hash:
            if (version, os_name, arch, compressed) != (profile.version, 'android', 'arm64', True):
                raise RuntimeError(f'Known Shorebird snapshot requires Dart {profile.version}, Android ARM64 and compressed pointers')
            return name
    return None


def verify_engine_profile(profile, engine_ids, flags):
    selected = runtime_profile(profile)
    if selected:
        if selected.engine not in engine_ids:
            raise RuntimeError('Shorebird snapshot matches, but the engine revision is unverified')
        required = {'product', 'no-shared_data', 'compressed-pointers'}
        if not required.issubset(flags):
            raise RuntimeError('Unsupported build flags for the Shorebird snapshot reader')
