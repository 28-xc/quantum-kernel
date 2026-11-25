"""Closed public technical validation records, separate from timing series."""
import re
from .block_model import need,keys,integer,digest,parameter,token
SCHEMA='lattice.validation_observations.v2'
PROBE_FIELDS=['status','parameter','cache_bits','cache_count','matrix_actual_coefficients','q_domain_checks','lowpart_coefficients','lowpart_bits','matrix_struct_bytes','cache_offset','negative_domain_controls','executable_sha256']
MEMORY_FIELDS=['code_and_rodata_load_bytes','data_bytes','bss_excluding_arena_io_stacks_bytes','arena_reservation_with_guards_bytes','caller_io_reservation_with_guards_bytes','test_stack_reservation_bytes','control_stack_reservation_bytes','writable_image_span_bytes','alignment_gap_bytes','emulator_image_occupied_ram_bytes','accounting_note']
CASE_FIELDS=['event','index','parameter','operation','tcId','kind','rc','ok','arena_highwater_bytes','stack_watermark_bytes','allocation_failures']
LAYOUT_FIELDS=['parameter','codec','signed_bits','row_bytes','stride_bytes','original_w0_allocation_bytes','tail_hash_start','row_geometry','post_ct0_max_abs_from_strict_norms','signed_capacity_max','earlier_initial_lowbit_width_is_insufficient']
def text(x):need(type(x) is str and 0<len(x)<=4096 and '\0' not in x,'Invalid technical text')
def hashes(h):
 need(type(h) is dict and h,'Missing source identities')
 for k,v in h.items():need(type(k) is str and re.fullmatch(r'[A-Za-z0-9_./-]+',k) and '..' not in k.split('/') and not k.startswith('/'),'Non-relative source identity');digest(v)
def validate(d):
 keys(d,['schema','dataset_id','representation_probes','signature_differentials','layout_reviews','emulated_targets','failed_attempts','limits']);need(d['schema']==SCHEMA,'Wrong validation schema');token(d['dataset_id'])
 for g in d['representation_probes']:
  keys(g,['id','execution','status','compiler','native_x86','sanitizer','codec','source_sha256','extracted_prefix_sha256','records','scope']);token(g['id']);need(g['execution']=='host_extracted_probe','Probe is not complete library execution');need(g['status'] in ['PASS','FAIL','ERROR'],'Unknown probe status');text(g['compiler']);need(type(g['native_x86']) is bool and g['sanitizer'] in ['none','undefined'] and g['codec'] in [0,1,2],'Unknown probe implementation');hashes(g['source_sha256']);digest(g['extracted_prefix_sha256']);text(g['scope'])
  for r in g['records']:
   keys(r,PROBE_FIELDS);need(r['status'] in ['PASS','FAIL','ERROR'],'Unknown probe result');parameter(r['parameter'],0);need(r['parameter'] in [44,65,87] and r['cache_bits'] in [24,32],'Unknown representation');digest(r['executable_sha256'])
   for k in PROBE_FIELDS:
    if k not in ['status','executable_sha256']:integer(r[k])
 for g in d['signature_differentials']:
  keys(g,['id','execution','status','library_sha256','records','test_sha256','library_loader_source_sha256','limits']);token(g['id']);need(g['execution']=='host_complete_public_api' and g['status'] in ['PASS','FAIL','ERROR'],'Unknown complete-library status');need(len(g['library_sha256'])==2,'Paired actual libraries required')
  for h in g['library_sha256']:digest(h)
  digest(g['test_sha256']);digest(g['library_loader_source_sha256']);text(g['limits'])
  for r in g['records']:
   keys(r,['parameter','count','complete_signatures_byte_equal','same_context_alternating_keys','mutated_signatures_rejected','entropy_bytes_per_signature','signature_aggregate_sha256','cases']);parameter(r['parameter'],1);integer(r['count']);need(r['count']==len(r['cases']),'Signature case count changed');digest(r['signature_aggregate_sha256']);integer(r['entropy_bytes_per_signature'])
   for k in ['complete_signatures_byte_equal','same_context_alternating_keys','mutated_signatures_rejected']:need(type(r[k]) is bool,'Boolean check required')
   for i,c in enumerate(r['cases']):
    keys(c,['case','key_id','message_bytes','domain_bytes','arena_peak_pair']);need(c['case']==i,'Signature case order changed')
    for k in ['key_id','message_bytes','domain_bytes']:integer(c[k])
    need(len(c['arena_peak_pair'])==2,'Paired resource observations missing')
    for x in c['arena_peak_pair']:integer(x)
 for g in d['layout_reviews']:
  keys(g,['kind','status','source_sha256','source_checks','lowpart_layouts','illegal_layout_positive_control','cache_sizes','cache_contract','lifecycle_scope']);need(g['kind']=='source_shape_and_finite_layout_review','Static review cannot become runtime probe');text(g['status']);hashes(g['source_sha256']);text(g['lifecycle_scope'])
  keys(g['source_checks'],['fixed_column_major_index','new_seed_invalidates_cache','cache_hit_requires_ready','fill_before_product_modifies_input','ready_committed_after_traversal','makehint_highpart_only_nonzero','matrix_owner_cleared_on_free','outer_signature_frees_matrix']);need(all(type(v) is bool for v in g['source_checks'].values()),'Source checks must be booleans')
  for r in g['lowpart_layouts']:
   keys(r,LAYOUT_FIELDS)
   for k in LAYOUT_FIELDS:
    if k not in ['row_geometry','earlier_initial_lowbit_width_is_insufficient']:integer(r[k])
   need(type(r['earlier_initial_lowbit_width_is_insufficient']) is bool,'Range warning changed')
   for row in r['row_geometry']:
    keys(row,['row','packed_begin','encoded_begin','encoded_end','unread_next_source_or_hash_start','safe']);need(type(row['safe']) is bool,'Layout outcome changed')
    for k,v in row.items():
     if k!='safe':integer(v)
  r=g['illegal_layout_positive_control'];keys(r,['parameter','hypothetical_signed_bits','compact_end_with_last_w1','tail_hash_start','overlap_bytes','rejected']);need(type(r['rejected']) is bool,'Negative control outcome changed')
  for k,v in r.items():
   if k!='rejected':integer(v)
  for r in g['cache_sizes']:
   keys(r,['count','bits','payload_bytes','extra_allocation_bytes','applies_to_operations']);need(r['applies_to_operations']==['keygen','sign','verify'],'Cache ownership scope changed')
   for k in ['count','bits','payload_bytes','extra_allocation_bytes']:integer(r[k])
  r=g['cache_contract'];keys(r,['q','unsigned24_capacity','required_input','not_supported_without_new_proof']);integer(r['q']);integer(r['unsigned24_capacity']);text(r['required_input'])
  for v in r['not_supported_without_new_proof']:text(v)
 for g in d['emulated_targets']:
  keys(g,['target','codec','execution','source_commit','compiler','qemu','elf_sha256','memory','observed_summary','cases','vectors','limits']);need(g['target'] in ['m4','rv32'] and g['codec'] in [0,1,2] and g['execution']=='instruction_emulation','Emulation scope changed');need(re.fullmatch('[0-9a-f]{40}',g['source_commit']),'Source commit missing');text(g['compiler']);text(g['qemu']);digest(g['elf_sha256'])
  keys(g['memory'],MEMORY_FIELDS)
  for k,v in g['memory'].items():text(v) if k=='accounting_note' else integer(v)
  s=g['observed_summary'];keys(s,['event','cases','failures','maximum_observed_test_stack_bytes','maximum_observed_arena_bytes','timing_collected']);need(s['event']=='summary' and s['timing_collected'] is False and s['cases']==len(g['cases']),'Target observation scope/count changed')
  for k in ['cases','failures','maximum_observed_test_stack_bytes','maximum_observed_arena_bytes']:integer(s[k])
  for r in g['cases']:
   keys(r,CASE_FIELDS);need(r['event']=='case' and type(r['ok']) is bool,'Unknown target event');parameter(r['parameter'],r['operation']);token(r['kind']);integer(r['rc'],-2147483648)
   for k in ['index','tcId','arena_highwater_bytes','stack_watermark_bytes','allocation_failures']:integer(r[k])
  need(sum(not c['ok'] for c in g['cases'])==s['failures'],'Target failures lost')
  keys(g['vectors'],['selected','not_covered'])
  for r in g['vectors']['selected']:
   keys(r,['parameter','operation','accepted','category','tgId','tcId']);parameter(r['parameter'],r['operation']);need(type(r['accepted']) is bool,'Expected result changed');token(r['category']);integer(r['tgId']);integer(r['tcId'])
  text(g['vectors']['not_covered'])
  for v in g['limits']:text(v)
 for r in d['failed_attempts']:
  keys(r,['id','stage','outcome','reason']);token(r['id']);need(r['stage']=='build' and r['outcome']=='ERROR','Initial build error cannot become test success');text(r['reason'])
 for v in d['limits']:text(v)
 return d
