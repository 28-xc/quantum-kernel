"""Required serialized-service facts for successful pooled observations.

Shared by the public validator and private producers; no archive or host access.
The legacy mean schema is intentionally unaffected.
"""
from .pooled_block_model import need

SEMANTICS={
    'provider':'default',
    'property_query':'provider=default',
    'fresh_serialized_key_every_call':True,
    'lattice_context_init_inside_call':True,
    'openssl_key_context_lifecycle_inside_call':True,
    'message_encoding':1,
    'mu':0,
}

RETAINED_BOUNDARY='openssl_retained_key_lattice_serialized_key_service'

def validate_metadata(metadata,boundary='fresh_serialized_key_service',operation=None):
    need(boundary in ('fresh_serialized_key_service',RETAINED_BOUNDARY),'Unknown service boundary')
    expected=dict(SEMANTICS)
    if boundary==RETAINED_BOUNDARY:
        expected.pop('fresh_serialized_key_every_call')
        expected.update(openssl_key_context_lifecycle_inside_call=False,
                        openssl_operation_context_lifecycle_inside_call=True,
                        key_generation_boundary_unchanged=True)
        need('fresh_serialized_key_every_call' not in metadata,'Contradictory retained-key boundary')
        for key in ('openssl_key_reused_across_batch','key_import_pct_uses_system_rng_at_setup'):
            need(type(metadata.get(key)) is bool,'Missing retained-key condition: '+key)
        need(type(metadata.get('retained_key_import_ticks')) is int and metadata['retained_key_import_ticks']>=0,
             'Missing retained-key setup cost')
        if operation is not None:
            need(metadata['openssl_key_reused_across_batch']==(operation>0),'Key reuse differs from operation')
    else:
        need('openssl_key_reused_across_batch' not in metadata,'Retained-key metadata in serialized study')
    for key,value in expected.items():
        need(key in metadata and type(metadata[key]) is type(value) and metadata[key]==value,
             'Missing or changed serialized-service metadata: '+key)

def validate_success_log(log,configuration,variant,boundary='fresh_serialized_key_service'):
    """Do not infer measured conditions merely from the scheduled command."""
    required={
        'message_bytes':configuration['message_bytes'],
        'context_bytes':configuration['context_bytes'],
        'workspace_reserved':variant['workspace'],
        'entropy_mode':'supplied_test_entropy',
    }
    for key,value in required.items():
        need(key in log and type(log[key]) is type(value) and log[key]==value,
             'Missing or changed successful driver condition: '+key)
    validate_metadata(log,boundary,log.get('operation'))
