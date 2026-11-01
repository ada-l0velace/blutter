"""Authored selection controls using the ordinary native annotation runner."""


def exercise_targeted_callers(run):
    helper = {0x4000: ['ldr x0, [x27, #40]', 'ret']}
    caller = ['bl 0x4000', 'ret']
    ordinary = run('selection-default', caller, helper)
    selected = run('selection-already-recorded', caller, helper, selected_caller=0x1000)
    assert 'targeted_call_result_analysis' not in ordinary and ordinary['format'] == 24
    assert selected['format'] == 25
    assert selected['targeted_call_result_analysis']['status'] == 'already_recorded'
    assert selected['call_result_contexts'] == ordinary['call_result_contexts']
    assert selected['call_result_analysis'] == ordinary['call_result_analysis']
    empty = run('selection-without-producer', ['ret'], selected_caller=0x1000)
    assert empty['targeted_call_result_analysis']['status'] == 'no_return_bindings'
    assert empty['targeted_call_result_analysis']['attempted_payloads'] == 0
    overwritten = run('selection-overwritten-result',
                      ['bl 0x4000', 'mov x0, x22', 'ret'], helper, selected_caller=0x1000)
    assert overwritten['targeted_call_result_analysis']['status'] == 'no_new_facts'
    assert not any(c['payload'] == 0x1000 for c in overwritten['call_result_contexts'])

