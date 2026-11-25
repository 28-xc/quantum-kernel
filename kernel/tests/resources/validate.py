"""Independently check a completed resource ledger and its fixed-capacity claims.

This validator does not launch the product or turn a dynamic result into a
static/physical-memory claim. It also exercises rejection of corrupted records.
"""
from pathlib import Path
# Shared typed XML persistence; transport JSON remains in memory.
import sys as _record_sys
from pathlib import Path as _RecordPath
for _record_parent in _RecordPath(__file__).resolve().parents:
    _record_candidate = _record_parent / 'record_io.py'
    if not _record_candidate.is_file():
        _record_candidate = _record_parent / '01_源代码/可参数化格运算内核/record_io.py'
    if _record_candidate.is_file():
        _record_sys.path.insert(0, str(_record_candidate.parent))
        break
import argparse, collections, copy, hashlib, record_io as json, re
from run import classify

def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p): return json.loads(p.read_text(encoding='utf-8'))
def require(condition, why):
    if not condition: raise ValueError(why)

def check(root):
    result=read(root/'result.xml'); protocol=read(root/'protocol.xml')
    require(result['status']=='PASS' and result['scope']=='full','Incomplete matrix')
    for name in ('protocol','commands','trials'):
        suffix='.records.xml' if name=='trials' else '.xml'
        require(sha(root/(name+suffix))==result[name+'_sha256'],name+' changed')
    for name,digest in protocol['sources'].items():
        require(sha(root/'sources'/name)==digest,'Changed source '+name)
    executable=root/('resource_probe.exe' if (root/'resource_probe.exe').exists() else 'resource_probe')
    require(sha(executable)==protocol['probe_sha256'],'Changed probe')
    if 'heap_interposer_sha256' in protocol:
        require(sha(root/'heap_audit.so')==protocol['heap_interposer_sha256'],'Changed heap instrument')
    for command in read(root/'commands.xml'):
        require(command['exit_code']==0 and sha(root/command['log'])==command['sha256'],'Changed/failed command')
    trials=list(json.read_records(root/'trials.records.xml'))
    require(len(trials)==result['trials'],'Trial count mismatch')
    require([x['trial'] for x in trials]==list(range(len(trials))),'Missing/reordered trials')
    statuses=collections.Counter()
    for trial in trials:
        events=[json.loads(line) for line in json.record_lines(trial['stdout']) if line.startswith(('{','<record'))]
        # A Windows abnormal exit cannot be reclassified by run.classify on a
        # Linux host; its raw unsigned status and absence of final data are
        # verified separately. It remains unlocated, not a Linux guard hit.
        if trial['classification']=='WINDOWS_ACCESS_OR_STACK_EXIT':
            require(trial['exit_code']&0xffffffff in (0xc0000005,0xc00000fd),'Wrong Windows fault status')
            require(not any(e.get('event')=='trial_result' for e in events),'Final data with fault exit')
            kind='WINDOWS_ACCESS_OR_STACK_EXIT'; parsed=None
        else: kind,parsed=classify(trial['exit_code'],events)
        require(kind==trial['classification'] and parsed==trial['result'],'Stored classification differs')
        starts=[x for x in events if x.get('event')=='trial_start']
        require(len(starts)==1,'Missing/duplicate start identity')
        argv=trial['argv']; identity=list(map(int,argv[2:]))
        require([starts[0][k] for k in ('parameter','operation','arena_bytes','stack_bytes','seed','control')]==identity,'Command identity differs')
        if parsed:
            require(parsed['stack_enforced_bytes']==identity[3] and parsed['arena_reserved_bytes']==identity[2],'Capacity differs')
            require(parsed['context_bytes']==64 and not parsed['context_in_measured_stack'],'Context charge differs')
            require(not parsed['physical_ram_measured'],'Invalid physical RAM claim')
        statuses[kind]+=1
    rows=[]
    for item in result['results']:
        folder=root/item['configuration']; path=folder/'resource_evidence.xml'; evidence=read(path)
        require(sha(path)==item['sha256'],'Changed resource evidence')
        image=read(folder/'image.xml'); build=read(folder/'build.xml')
        require(sha(folder/'build.xml')==evidence['build_manifest_sha256'],'Changed build manifest')
        require(image['sha256']==build['binary']['sha256']==evidence['dll_sha256'],'Binary identity differs')
        require(evidence['protocol_sha256']==result['protocol_sha256'],'Protocol differs')
        require(not evidence['all_input_stack_bound_proved'] and not evidence['whole_process_or_MCU_ram_claim'],'Overstated bound')
        require(evidence['program_bytes']==image['program_non_debug_image_bytes'],'Program charge differs')
        require(len(evidence['cells'])==3*len(protocol['parameters']),'Missing operation cell')
        require(len(evidence['controls'])==4,'Missing instrument controls')
        controls=[trials[x['trial']] for x in evidence['controls']]
        require(controls[0]['classification']=='SUCCESS','Empty control failed')
        require(controls[1]['classification'] in ('PROTECTED_STACK_FAULT','WINDOWS_ACCESS_OR_STACK_EXIT'),'Missing overflow positive')
        require(controls[2]['classification']=='SUCCESS','Large stack overflow control failed')
        require(controls[3]['result']['outside_heap_peak_requested_bytes']==96 and controls[3]['result']['outside_heap_calls']>0,'Heap positive missing')
        for p in evidence['parameters']:
            level=p['parameter']; w=p['workspace_bytes']; s=p['stack_reserved_bytes']
            require(w%32==0 and w==(max(p['arena_discovery_peak_by_operation'])+31)//32*32,'Wrong fixed arena')
            scan=p['stack_scan']; require(len(scan)==3*len(protocol['stack_grid']),'Incomplete stack grid')
            minima=[]
            for op in range(3):
                samples=[x for x in scan if x['operation']==op]
                require([x['stack_bytes'] for x in samples]==protocol['stack_grid'],'Changed grid')
                for x in samples:
                    t=trials[x['trial']]
                    require(t['classification']==x['classification'] and int(t['argv'][2])==level and int(t['argv'][3])==op and int(t['argv'][4])==w and int(t['argv'][5])==x['stack_bytes'],'Wrong scan binding')
                good=[x['classification']=='SUCCESS' for x in samples]
                last_failure=max((i for i,x in enumerate(good) if not x),default=-1)
                require(last_failure<len(good)-1,'No successful suffix')
                minima.append(samples[last_failure+1]['stack_bytes'])
            require(minima==p['stack_minimum_contiguous_success_by_operation'] and s==max(minima)+256,'Wrong shared fixed stack')
            confirms=p['confirmation_sequences'];require(len(confirms)==protocol['validation_seeds']>=24,'Missing confirmation seeds')
            require(len({x['seed'] for x in confirms})==len(confirms),'Repeated seed')
            for c in confirms:
                t=trials[c['trial']];r=t['result']
                require(t['classification']=='SUCCESS' and r['step_rc']==[0,0,0] and r['step_outputs_match']==[1,1,1],'Confirmation failed')
                require(list(map(int,t['argv'][2:7]))==[level,3,w,s,c['seed']],'Wrong fixed sequence binding')
            small=trials[p['workspace_lower_oom_trial']]
            require(small['classification']=='WORKSPACE_OOM' and int(small['argv'][4])==w-32 and small['result']['recovery_full_sequence_ok'],'Missing real OOM/recovery')
            global_bytes=image['writable_image_plus_single_thread_tls_bytes']
            full=None if p['outside_heap_bytes'] is None else w+s+64+global_bytes+p['outside_heap_bytes']
            require(p['full_core_budget_bytes']==full,'Incomplete RAM addition')
            family='ML-KEM' if level>100 else 'ML-DSA'; ops=('keygen','encaps','decaps') if level>100 else ('keygen','sign','verify')
            for op in ops:
                cell=evidence['cells'][f'{family}/{level}/{op}']
                require([cell[k] for k in ('workspace_bytes','stack_bytes','external_context_bytes','globals_bytes','outside_heap_bytes','full_ram_bytes')]==[w,s,64,global_bytes,p['outside_heap_bytes'],full],'Operation does not share parameter capacity')
            budget64=next(x for x in p['budget_trials'] if x['budget_bytes']==65536)
            for b in p['budget_trials']:
                if b['trial'] is not None:
                    t=trials[b['trial']]
                    require(t['classification']==b['status'] and int(t['argv'][4])==b['arena_bytes'] and b['charged_ram_bytes']<=b['budget_bytes'],'Invalid explicit budget witness')
            rows.append({'configuration':item['configuration'],'parameter':level,'workspace_bytes':w,'stack_bytes':s,'context_bytes':64,'globals_bytes':global_bytes,'outside_heap_bytes':p['outside_heap_bytes'],'full_core_budget_bytes':full,'program_bytes':evidence['program_bytes'],'64KiB_trial':budget64['status']})
    # These are intentionally corrupt records, never edited raw evidence.
    positive=next(t['result'] for t in trials if t['classification']=='SUCCESS' and t['result']['control']==0)
    negative=[]
    for key,value in [('canaries_ok',False),('recovery_full_sequence_ok',False),('guard_error',1),('init_rc',1),('heap_audit_errors',1),('arena_high_water_bytes',positive['arena_reserved_bytes']+1),('released_prefix_changed_nonzero_bytes',1)]:
        bad=copy.deepcopy(positive);bad[key]=value
        try:classify(0,[bad])
        except ValueError:negative.append(key)
        else:raise ValueError('Corrupt record accepted: '+key)
    for code,events,label in [(139,[{'event':'stack_fault','protected_region_hit':False}],'fault_outside_guard'),(0,[{'event':'stack_fault','protected_region_hit':True}],'fault_with_success_exit'),(1,[positive],'final_with_error_exit'),(0,[positive,positive],'duplicate_result')]:
        try:classify(code,events)
        except ValueError:negative.append(label)
        else:raise ValueError('Corrupt fault accepted: '+label)
    disassembly=(root/'probe_disassembly.txt').read_text(encoding='utf-8')
    body=re.search(r'<lc_memory_call_at>:\n(.*?)(?:\n\s*\n)',disassembly,re.S)
    require(body is not None,'Trampoline missing from actual disassembly')
    instructions=body.group(1)
    if protocol['machine'].lower() in ('aarch64','arm64'):
        actual=re.findall(r'^\s*[0-9a-f]+:\s+([0-9a-f]{8})\s',instructions,re.M)
        require(actual==['a9bf7bf3','910003f3','9100003f','d63f0040','9100027f','a8c17bf3','d65f03c0'],'Unexpected AAPCS64 trampoline instruction bytes')
        abi='AAPCS64 exact seven-instruction audit'
    else:
        require('call' in instructions and 'ret' in instructions and ('%r12' in instructions or 'r12' in instructions),'Missing stack-call/restore instructions')
        abi='x86-64 actual disassembly retained; source/ABI reviewed'
    return {'status':'PASS','source_result_sha256':sha(root/'result.xml'),'measurement_root':str(root.resolve()),'trials':len(trials),'classification_counts':dict(statuses),'negative_rejections':negative,'trampoline_audit':abi,'trampoline_disassembly':instructions,'rows':rows,'physical_ram_claim':False,'static_all_input_stack_bound':False}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('measurement',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if a.output.exists():raise ValueError('Fresh audit output required')
    obj=check(a.measurement.resolve());a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_bytes((json.dumps(obj,ensure_ascii=False,indent=2)+'\n').encode())
    print(json.dumps({'status':obj['status'],'trials':obj['trials'],'rows':len(obj['rows']),'negative_tests':len(obj['negative_rejections']),'sha256':sha(a.output)}))

if __name__=='__main__':main()
