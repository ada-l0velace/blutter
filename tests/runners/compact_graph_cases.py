"""Compare native export modes against the same authored instruction fixtures."""
import json
import copy
import subprocess
from pathlib import Path


def without_states(graph):
    result = copy.deepcopy(graph)
    for certificate in result.get('receiver_certificates', []):
        certificate.pop('blocks', None)
    for family in ('call_contexts', 'array_contexts', 'array_path_contexts',
                   'array_entry_traces', 'array_result_traces', 'register_contexts',
                   'call_result_contexts', 'sdk_stub_producer_contexts', 'sdk_stub_caller_contexts'):
        for context in result.get(family, []):
            certificate = context.get('certificate')
            if certificate is not None:
                certificate.pop('blocks', None)
    for family in ('call_effects', 'prefix_call_effects', 'register_call_effects'):
        for effect in result.get(family, []):
            effect.pop('states', None)
            if effect.get('array_return') is not None:
                effect['array_return'].pop('states', None)
    return result


def check_compact(command, environment, path, full):
    assembly = Path(str(path) + '.asm')
    original = assembly.read_bytes()
    subprocess.run(command, check=True, env=dict(environment, BLUTTER_TEST_GRAPH_COMPACT='1'))
    compact = json.loads(path.read_text())
    assert full['export'] == {'detail': 'full', 'omitted': []}
    assert compact['export'] == {'detail': 'compact', 'omitted': ['receiver_blocks', 'call_effect_states']}
    assert without_states({k: v for k, v in full.items() if k != 'export'}) == {
        k: v for k, v in compact.items() if k != 'export'}, 'Compact export changed facts or conditions'
    assert assembly.read_bytes() == original, 'Compact export changed assembly'
    # Keep the full graph for independent original-byte verification and callers.
    path.write_text(json.dumps(full))
