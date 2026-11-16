"""Authored completion paths, metadata failures and forged-proof controls."""
import copy


def run_cases(run):
    helpers = {v: ['ret'] for v in (0x11000, 0x12000, 0x13000, 0x14000, 0x15000, 0x16000)}
    helpers.update({0x17000: ['brk #0', 'nop'], 0x17100: ['nop', 'ret']})
    direct = ['bl 0x11000', 'bl 0x6000', 'b 0x14000']
    fork = ['bl 0x11000', 'cbz x1, 0x1010', 'bl 0x6000', 'b 0x14000', 'bl 0x6000', 'b 0x14000']
    cases = [
        ('direct', direct, 'valid', 'exact_heap_class'),
        ('allocated-ldtr', ['bl 0x11000', 'ldtr x8, [x8]', 'bl 0x6000', 'b 0x14000'], 'valid', 'exact_heap_class'),
        ('allocated-ldtr-null', ['bl 0x11000', 'ldtr x8, [x8]', 'mov x0, x22', 'b 0x14000'], 'valid', 'null_only'),
        ('allocated-ldtr-null-clobber', ['bl 0x11000', 'ldtr x22, [x22]', 'mov x0, x22', 'b 0x14000'], 'valid', 'unknown_value'),
        ('null', ['bl 0x11000', 'mov x0, x22', 'b 0x14000'], 'valid', 'null_only'),
        ('zero', ['bl 0x11000', 'mov x0, #0', 'b 0x14000'], 'valid', 'unknown_value'),
        ('forward', direct[:-1]+['b 0x15000'], 'valid', 'value_or_future'),
        ('await', ['bl 0x11000', 'bl 0x12000', 'b 0x14000'], 'valid', 'unknown_value'),
        ('typed-await', ['bl 0x11000', 'bl 0x13000', 'b 0x14000'], 'valid', 'unknown_value'),
        ('opaque-result', ['bl 0x11000', 'bl 0x4000', 'b 0x14000'], 'valid', 'unknown_value'),
        ('agreement', fork, 'valid', 'exact_heap_class'),
        ('conflict', fork[:4]+['bl 0x7000', 'b 0x14000'], 'valid', 'mixed_classes'),
        ('nullable', fork[:4]+['mov x0, x22', 'b 0x14000'], 'valid', 'nullable_class'),
        ('missing', direct, 'missing', 'missing_exception_metadata'),
        ('mismatched-body', direct, 'limited', 'missing_exception_metadata'),
        ('handler-bypass', ['bl 0x11000', 'nop', 'bl 0x6000', 'nop', 'b 0x14000'], 'handler', 'unknown_value'),
        ('no-init', direct[1:], 'valid', 'no_matched_initialization'),
        ('escape', fork[:4]+['b 0x19000'], 'valid', 'open_control_flow'),
        ('return', fork[:4]+['ret'], 'valid', 'open_control_flow'),
        ('indirect', fork[:4]+['br x9'], 'valid', 'open_control_flow'),
        ('fallthrough', fork[:4]+['nop'], 'valid', 'open_control_flow'),
        ('trap', fork[:4]+['brk #0'], 'valid', 'open_control_flow'),
        ('error-call', fork[:4]+['bl 0x17000'], 'valid', 'exact_heap_class'),
        ('error-tail', fork[:4]+['b 0x17000'], 'valid', 'exact_heap_class'),
        ('async-error-tail', fork[:4]+['b 0x17100'], 'valid', 'exact_heap_class'),
        ('async-error-call', fork[:4]+['bl 0x17100', 'ret'], 'valid', 'open_control_flow'),
        ('nonnull-register-clobber', ['bl 0x11000', 'mov x22, #0', 'mov x0, x22', 'b 0x14000'], 'valid', 'unknown_value'),
        ('copy', ['bl 0x11000', 'bl 0x6000', 'mov x8, x0', 'mov x0, x8', 'b 0x14000'], 'valid', 'exact_heap_class'),
        ('spill', ['bl 0x11000', 'bl 0x6000', 'stur x0, [x29, #-8]', 'ldur x0, [x29, #-8]', 'b 0x14000'], 'valid', 'exact_heap_class'),
        ('spill-alias', ['bl 0x11000', 'bl 0x6000', 'stur x0, [x29, #-8]', 'str x3, [x4]', 'ldur x0, [x29, #-8]', 'b 0x14000'], 'valid', 'unknown_value'),
        ('null-spill', ['bl 0x11000', 'stur x22, [x29, #-8]', 'ldur x0, [x29, #-8]', 'b 0x14000'], 'valid', 'null_only'),
    ]
    for name, instructions, mode, status in cases:
        graph = run('completion-'+name, instructions, helpers, async_contracts=True, completions=mode)
        row = next(v for v in graph['completion_summaries'] if v['payload'] == 0x1000)
        assert row['status'] == status, (name, row)
        assert (row['exact_class'] == 2) if status == 'exact_heap_class' else row['exact_class'] is None
