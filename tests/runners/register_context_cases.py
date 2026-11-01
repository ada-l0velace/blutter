"""Authored ARM64 register/result integration cases for the native harness."""


def exercise_register_contexts(run):
    frame = ['stp x29, x30, [x15, #-16]!', 'mov x29, x15', 'sub x15, x15, #32']
    restore = ['mov x15, x29', 'ldp x29, x30, [x15], #16', 'ret']
    dispatch = ['ldur w0, [x1, #-1]', 'ubfx x0, x0, #8, #16',
                'ldr x30, [x21, x0, lsl #3]', 'blr x30']

    def bound(result):
        return [c for c in result['register_contexts'] if c['payload'] == 0x5000]

    def caller(result):
        return [c for c in result['call_result_contexts'] if c['payload'] == 0x1000]

    result = run('register-input-resolves-helper', ['ldr x1, [x27, #40]', 'bl 0x5000'], {0x5000: dispatch})
    assert len(bound(result)) == 1 and len(bound(result)[0]['resolutions']) == 1
    assert bound(result)[0]['resolutions'][0]['snapshot_target'] == 0x2004

    result = run('register-input-unknown-call-kills-binding', ['ldr x1, [x27, #40]', 'bl 0x5000'],
                 {0x5000: ['bl 0x5100'] + dispatch, 0x5100: ['svc #0', 'ret']})
    assert not bound(result)

    result = run('register-result-conditional-caller', ['ldr x1, [x27, #40]', 'bl 0x5000', 'mov x1, x0'] + dispatch,
                 {0x5000: ['mov x0, x1', 'ret']})
    assert bound(result)[0]['normal_return_class'] == 1
    assert 0x5000 not in dict(result['receiver_metadata']['machine_return_classes'])
    assert caller(result)[0]['return_bindings'][0]['basis'] == 'register_context'
    assert caller(result)[0]['resolutions'][0]['snapshot_target'] == 0x2004

    result = run('machine-result-consumed-at-caller', ['bl 0x5000', 'mov x1, x0'] + dispatch,
                 {0x5000: ['ldr x0, [x27, #40]', 'ret']})
    assert dict(result['receiver_metadata']['machine_return_classes'])[0x5000] == 1
    assert caller(result)[0]['return_bindings'][0]['basis'] == 'machine_return_summary'
    assert caller(result)[0]['resolutions'][0]['snapshot_target'] == 0x2004

    result = run('machine-result-unknown-call-kills-value', ['bl 0x5000', 'bl 0x5100', 'mov x1, x0'] + dispatch,
                 {0x5000: ['ldr x0, [x27, #40]', 'ret'], 0x5100: ['svc #0', 'ret']})
    assert not caller(result)

    make_array = ['stur x0, [x29, #-8]', 'mov x2, #2', 'bl 0x6000', 'ldur x1, [x29, #-8]',
                  'stur w1, [x0, #15]', 'str x0, [x15]', 'bl 0x5100']
    for name, prefix, helper, basis in (
            ('machine-result-array-element', [], ['ldr x0, [x27, #40]', 'ret'], 'machine_return_summary'),
            ('register-result-array-element', ['ldr x1, [x27, #40]'], ['mov x0, x1', 'ret'], 'register_context')):
        result = run(name, frame + prefix + ['bl 0x5000'] + make_array + restore,
                     {0x5000: helper, 0x5100: ['svc #0', 'ret']})
        context = caller(result)[0]
        assert context['return_bindings'][0]['basis'] == basis
        arrays = [v for observation in context['array_observations'] for v in observation['values']]
        assert len(arrays) == 1 and arrays[0]['length'] == 1 and arrays[0]['elements'] == [[0, 1]]
        assert not any(e['array_arguments'] for e in result['edges'] if e['source'] == 0x1000)

    result = run('machine-result-does-not-grant-frame-effect',
                 frame + ['ldr x0, [x27, #40]', 'stur x0, [x29, #-8]', 'bl 0x5000', 'ldur x1, [x29, #-8]'] + dispatch,
                 {0x5000: frame + ['bl 0x5200', 'ldr x0, [x27, #40]'] + restore, 0x5200: ['svc #0', 'ret']})
    assert dict(result['receiver_metadata']['machine_return_classes'])[0x5000] == 1
    assert not caller(result)
    assert all(c['payload'] != 0x5000 for c in result['call_effects'])

    result = run('machine-result-tail-path-stays-unproved', ['bl 0x5000', 'mov x1, x0'] + dispatch,
                 {0x5000: ['ldr x0, [x27, #40]', 'b 0x5200'], 0x5200: ['ret']})
    assert 0x5000 not in dict(result['receiver_metadata']['machine_return_classes']) and not caller(result)

    result = run('register-input-demands-late-frame-proof', ['ldr x1, [x27, #40]', 'bl 0x40000'],
                 {0x40000: frame + ['stur x1, [x29, #-8]', 'bl 0x40100', 'ldur x1, [x29, #-8]'] + dispatch,
                  0x40100: ['ret']}, late_helper=True)
    assert all(c['payload'] != 0x40100 for c in result['call_effects'])
    assert any(c['payload'] == 0x40100 for c in result['register_call_effects'])
    context = next(c for c in result['register_contexts'] if c['payload'] == 0x40000)
    assert context['resolutions'][0]['snapshot_target'] == 0x2004
