"""Optional call-input capabilities from reviewed public SDK compiler policies.

This build-time gate never selects a snapshot reader. Unknown source policies
leave the native analyzer's physical observations available without order labels.
"""
import hashlib
import json
from pathlib import Path
import re

# Lex strings before comments, so comment-looking bytes in literals are retained.
_LEX = re.compile(
    r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*.*?\*/'
    r'|>>=|<<=|<=>|\.\.\.|::|->\*|->|\.\*|\+\+|--|&&|\|\||<<|>>|<=|>=|==|!='
    r'|\+=|-=|\*=|/=|%=|&=|\|=|\^=|##|[A-Za-z_]\w*|\d+|[^\s]', re.S)
_MAX_SOURCE_BYTES = 8 * 1024 * 1024
_MAX_TOKENS = 1000000

_POLICIES = {
    'register_limit': ('object.cc', 'intptr_t Function::MaxNumberOfParametersInRegisters('),
    'assignment': ('compiler/backend/dart_calling_conventions.cc', 'intptr_t ComputeCallingConvention('),
    'fixed': ('compiler/backend/flow_graph.cc', 'intptr_t FlowGraph::ComputeLocationsOfFixedParameters('),
    'representations': ('compiler/backend/flow_graph.cc', 'Representation FlowGraph::ParameterRepresentationAt('),
    'size': ('compiler/backend/flow_graph.cc', 'intptr_t FlowGraph::ComputeArgumentsSizeInWords('),
    'caller_sp': ('compiler/backend/locations.cc', 'Location Location::ToCallerSpRelative('),
    'sp_conversion': ('compiler/backend/locations.cc', 'Location Location::ToSpRelative('),
    'static_size': ('compiler/backend/il.cc', 'intptr_t StaticCallInstr::ArgumentsSize('),
    'descriptor': ('compiler/backend/il.h', 'ArrayPtr GetArgumentsDescriptor() const'),
    'type_prefix': ('compiler/backend/il.h', 'intptr_t FirstArgIndex() const'),
    'input_count': ('compiler/backend/il.h', 'intptr_t ArgumentCountWithoutTypeArgs() const'),
    'input_size': ('compiler/backend/il.h', 'intptr_t ArgumentsSizeWithoutTypeArgs() const'),
    'static_packet': ('compiler/backend/il.h', 'ArgumentsInfo(intptr_t type_args_len,'),
    'static_descriptor': ('compiler/backend/il.h', 'ArrayPtr ToArgumentsDescriptor() const'),
    'static_call': ('compiler/backend/flow_graph_compiler.cc', 'void FlowGraphCompiler::GenerateStaticCall('),
    'static_emit': ('compiler/backend/flow_graph_compiler_arm64.cc', 'void FlowGraphCompiler::EmitOptimizedStaticCall('),
    'descriptor_need': ('object.cc', 'bool Function::PrologueNeedsArgumentsDescriptor('),
}


def function_tokens(text, marker):
    if len(text) > _MAX_SOURCE_BYTES:
        raise ValueError('SDK policy source exceeds its bound')
    # C++ line splicing precedes comment/literal tokenization.
    text = text.replace('\\\r\n', '').replace('\\\n', '')
    tokens = []
    for match in _LEX.finditer(text):
        value = match[0]
        # An unterminated literal/comment must not fall through into ordinary
        # tokens. Reject at its first opener, avoiding repeated tail scans.
        if value in ('"', "'") or value == '/' and text.startswith('/*', match.start()):
            raise ValueError('Unterminated SDK policy literal or comment')
        if not value.startswith(('//', '/*')):
            tokens.append(value)
            if len(tokens) > _MAX_TOKENS:
                raise ValueError('SDK policy token bound exceeded')
    wanted = _LEX.findall(marker)
    starts = [i for i in range(len(tokens) - len(wanted) + 1) if tokens[i:i + len(wanted)] == wanted]
    if len(starts) != 1:
        raise ValueError('SDK policy definition is absent or ambiguous')
    start = starts[0]
    brace = tokens.index('{', start + len(wanted))
    if ';' in tokens[start:brace]:
        raise ValueError('SDK policy has no inline definition')
    depth = 0
    for end in range(brace, len(tokens)):
        depth += (tokens[end] == '{') - (tokens[end] == '}')
        if depth == 0:
            return tokens[start:end + 1]
    raise ValueError('Unterminated SDK policy')


def fingerprint(tokens):
    return hashlib.sha256(json.dumps(tokens, separators=(',', ':')).encode()).hexdigest()


# Fingerprints of the public compiler functions listed above, not application
# bytes or snapshot hashes. A semantic change requires a new source review.
_REVIEWED = {
    'register_limit': ('4c1cd31aff5f9e2463d9e16b7ef5f933d9aa9d19e6ed3ec71b82d37896ac82fc',),
    'assignment': ('be7d7945af65204e4cde0acca5af47a55ec52dc53504677a12cb0f97225b2991',),
    'fixed': ('15ee4ff759b3a9c94f605975d57c3bb41099ed4ca694cfc4462743b2ae6c9cef', 'c7771ee3fe75237c5a54e633187ee34fed312a4041b57e3e97608c86b124a3aa'),
    'representations': ('d6391990b0b267ede59dd57ba87346630df9f56b1a7d32a5077190dd16ea7fa5',),
    'size': ('9d108ca8808ed61ab2df6c47bb3f2ffba13dae955b94414b38c2e8788877048a',),
    'caller_sp': ('28c0dd9297b3bd366760518a76e051f7388c01d2f7e8e52a5928dbf1c9822345',),
    'sp_conversion': ('8dc374e9bd27f8f57e1e1100653f6d17d92f37e80698146cb69de1d438818b07',),
    'static_size': ('40f3bb4db7ad6c48ceb0ca9446c7093675e32c569a917ba2a78bffbf6309fddb',),
    'descriptor': ('9b5b9142b3c7a253438cb9e461021b34af67aa6742290e6f7330cd52a59e0f7c',),
    'type_prefix': ('787fac69d2793cd7c9acf9c632daf4c8ab7da7ee67d6b728216bebc9160f2617',),
    'input_count': ('e1303043972511b09001c171d8432f7783f751dbca2a7ef768d8e6a05acb7181',),
    'input_size': ('d2f1a0e61ef554a605d9003ab7af33323e3848596f4694025564138a627eef18',),
    'static_packet': ('c6cfe33643c36ea2f7832ee5e1e097f7bc239c99296a48f7a1f654948b859c9e',),
    'static_descriptor': ('7b7f2e2fd35f16f67f823425175aef82ff8bdb532daaec05235886b5ae155b21',),
    'static_call': ('786928933f7cbbf496e7b1f60000170c4a4c33c76fe52d87ef07ae015372c01f',),
    'static_emit': ('50ae422c9f520495b065c153524a55ffdcf88bc6b624902369a9026f20f03777',),
    'descriptor_need': ('1c607d2497beb2042f5cd08bc3047a81f0d2c19d770b05f994477d47ca5ba40d',),
}


_PROLOGUE_POLICY = ('compiler/frontend/prologue_builder.cc', 'Fragment PrologueBuilder::BuildTypeArgumentsHandling(')
_PARAMETER_POLICY = ('compiler/frontend/prologue_builder.cc', 'Fragment PrologueBuilder::BuildParameterHandling(')
_PARAMETER_REVIEWED = ('df4641862bd976c4a402fcdac14f6e6881488fbbf04652ab74a10679fbf5e8cf',)
_PROLOGUE_REVIEWED = ('4815776b275195a29108019f205eb9c333e292d6022b92746b396069033e083f',)


def valid_capability(value):
    return (isinstance(value, dict) and {'schema', 'policy', 'fingerprints'} <= set(value) <= {'schema', 'policy', 'fingerprints', 'descriptor_prologue', 'descriptor_parameters'} and
            value['schema'] == 1 and type(value['schema']) is int and
            value['policy'] == 'arm64_fixed_stack_v1' and
            isinstance(value['fingerprints'], dict) and set(value['fingerprints']) == set(_POLICIES) and
            all(type(v) is str and v in _REVIEWED[k] for k, v in value['fingerprints'].items()) and
            ('descriptor_prologue' not in value or value['descriptor_prologue'] in _PROLOGUE_REVIEWED) and
            ('descriptor_parameters' not in value or value['descriptor_parameters'] in _PARAMETER_REVIEWED))


def inspect_source(directory):
    """Return a capability only when every relevant source policy is recognized."""
    try:
        root = Path(directory) / 'runtime/vm'
        sources = {}
        for path, _ in _POLICIES.values():
            if path in sources:
                continue
            with (root / path).open('rb') as stream:
                raw = stream.read(_MAX_SOURCE_BYTES + 1)
            if len(raw) > _MAX_SOURCE_BYTES:
                return None
            sources[path] = raw.decode('utf-8')
        hashes = {key: fingerprint(function_tokens(sources[path], marker))
                  for key, (path, marker) in _POLICIES.items()}
        result = dict(schema=1, policy='arm64_fixed_stack_v1', fingerprints=hashes)
        if not valid_capability(result):
            return None
        try:
            path, marker = _PROLOGUE_POLICY
            with (root / path).open('rb') as stream:
                body = stream.read(_MAX_SOURCE_BYTES + 1)
            code = fingerprint(function_tokens(body.decode('utf-8'), marker))
            if code in _PROLOGUE_REVIEWED:
                result['descriptor_prologue'] = code
            code = fingerprint(function_tokens(body.decode('utf-8'), _PARAMETER_POLICY[1]))
            if code in _PARAMETER_REVIEWED:
                result['descriptor_parameters'] = code
        except (OSError, ValueError, UnicodeError):
            pass
        return result
    except (OSError, ValueError, UnicodeError):
        return None


def capability_id(value):
    if value is None:
        return None
    if not valid_capability(value):
        raise ValueError('Invalid SDK call-input capability')
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def cmake_options(value):
    enabled = value is not None and valid_capability(value)
    return ['-DBLUTTER_FIXED_STACK_INPUTS=' + ('ON' if enabled else 'OFF'),
            '-DBLUTTER_DESCRIPTOR_PROLOGUE=' + ('ON' if enabled and value.get('descriptor_prologue') in _PROLOGUE_REVIEWED else 'OFF'),
            '-DBLUTTER_DESCRIPTOR_PARAMETERS=' + ('ON' if enabled and value.get('descriptor_parameters') in _PARAMETER_REVIEWED else 'OFF')]
