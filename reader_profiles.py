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
    abi_probe: str = 'guarded'


RUNTIME_PROFILES = {
    'shorebird_db65': RuntimeProfile('3.10.9', 'db65a563da4e182bf14dd4caee095ad7',
                                     'dda6221689d0b21dabed81b20f6a13c89cb0b5a2',
                                     '7c8a3e077e8a3c6209c865301aada26e9fde764a',
                                     'BLUTTER_SHOREBIRD_DB65', 'shorebird_db65_runtime.patch',
                                     'guarded_relocations_v1'),
    'shorebird_26a7': RuntimeProfile('3.14.0', '26a7b50c0924ef9952d7cc8b84c67e13',
                                     'f0a7d29193ea6e077e02080a3511b405a4401b6f',
                                     'fa8c1270c374c1346931583a17c3b7f278d3822d',
                                     'BLUTTER_SHOREBIRD_26A7', 'shorebird_26a7_runtime.patch',
                                     'arm64_stub_layout_v1'),
    'shorebird_7d8f': RuntimeProfile('3.11.4', '7d8fb82a698d78184f7d1e3bbc00540a',
                                     'a8578c0205c4f52bc8a0d07c5d75f2a19e208187',
                                     '02abc57898bebc334a997e609ce5827c8ef207d7',
                                     'BLUTTER_SHOREBIRD_7D8F', 'shorebird_7d8f_runtime.patch'),
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
    matching = [(name, profile) for name, profile in RUNTIME_PROFILES.items()
                if snapshot_hash == profile.snapshot_hash]
    for name, profile in matching:
        if (version, os_name, arch, compressed) == (profile.version, 'android', 'arm64', True):
            return name
    if matching:
        versions = ', '.join(sorted({profile.version for _, profile in matching}))
        raise RuntimeError(f'Known Shorebird snapshot requires Dart {versions}, Android ARM64 and compressed pointers')
    return None


def verify_engine_profile(profile, engine_ids, flags):
    selected = runtime_profile(profile)
    if selected:
        if selected.engine not in engine_ids:
            raise RuntimeError('Shorebird snapshot matches, but the engine revision is unverified')
        verify_build_flags(flags)


def verify_build_flags(flags):
    required = {'product', 'no-shared_data', 'compressed-pointers'}
    if not required.issubset(flags):
        raise RuntimeError('Unsupported build flags for the Shorebird snapshot reader')


def candidate_profiles(version, os_name, arch, compressed, snapshot_hash):
    """Candidate discovery only; each unregistered build still requires probing."""
    if (snapshot_hash in UNSUPPORTED_FORMATS or
            (os_name, arch, compressed) != ('android', 'arm64', True)):
        return ()
    minor = version.split('.')[:2]
    implementations = {}
    for name, profile in RUNTIME_PROFILES.items():
        if profile.snapshot_hash == snapshot_hash and profile.version.split('.')[:2] == minor:
            key = (profile.version, profile.source_base, profile.macro, profile.patch)
            implementations.setdefault(key, name)
    return tuple(implementations.values())


def profile_cmake_options(selected):
    active = runtime_profile(selected).macro if selected else None
    return [f'-D{macro}={"ON" if macro == active else "OFF"}'
            for macro in sorted({p.macro for p in RUNTIME_PROFILES.values()})]
