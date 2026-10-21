"""Explicit snapshot readers. A failed official download is not identification."""

SHOREBIRD_HASH = '3c9c63bc42bff27a9fd51d020f3771ec'
SHOREBIRD_ENGINE = '4b936a0c03e13389ddfb1ac48823f187964975c2'
SHOREBIRD_BASE = '04bcd1036cdc799ac6564988f159ee454d42c822'
SHOREBIRD_PROFILE = 'shorebird_3c9c'


def reader_profile(version, os_name, arch, compressed, snapshot_hash):
    if snapshot_hash != SHOREBIRD_HASH:
        return None
    if (version, os_name, arch, compressed) != ('3.13.5', 'android', 'arm64', True):
        raise RuntimeError('Known Shorebird snapshot requires Dart 3.13.5, Android ARM64 and compressed pointers')
    return SHOREBIRD_PROFILE


def verify_engine_profile(profile, engine_ids, flags):
    if profile == SHOREBIRD_PROFILE:
        if SHOREBIRD_ENGINE not in engine_ids:
            raise RuntimeError('Shorebird snapshot matches, but the engine revision is unverified')
        required = {'product', 'no-shared_data', 'compressed-pointers'}
        if not required.issubset(flags):
            raise RuntimeError('Unsupported build flags for the Shorebird snapshot reader')
