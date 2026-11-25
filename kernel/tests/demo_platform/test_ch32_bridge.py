"""Bounded offline adapter fixtures. Never imports/opens a real serial port."""
from pathlib import Path
import copy
import hashlib
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
import record_io as json
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from demo.ch32_bridge import Ch32Exchange,TIMER_STRUCT
from demo import platform_protocol as wire

ELF='a'*64;BUILD='b'*64


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        values=[0x5354494d,1,15,5,0xfffffff0,0x100000010,20,400,0,128]+[12]*8+[1,8001,1,1001,1024,0]
        data=TIMER_STRUCT.pack(*values);(self.root/'timer-selftest.bin').write_bytes(data)
        keys=['magic','version','pass_mask','final_ctlr','carry_written','carry_read','monotonic_first','monotonic_last','monotonic_failures','monotonic_reads']
        timer=dict(zip(keys,values[:10]));timer['empty_read_ticks']=values[10:18]
        timer.update(zip(['hclk_start','hclk_end','div8_start','div8_end','nop_iterations','reserved'],values[18:]))
        p=self.root/'result.xml';p.write_text(json.dumps(dict(status='HARDWARE_TIMER_SELFTEST_PASS',elf_sha256=ELF,timer=timer,
            timer_binary_sha256=hashlib.sha256(data).hexdigest())),encoding='utf8')
        self.descriptor={'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
        self.expected=dict(build_id=BUILD,clock_hz=96000000,systick_control=5,flash_capacity_bytes=196608,
            ram_capacity_bytes=131072,flash_load_bytes=53856,ram_reserved_bytes=45632,workspace_bytes=16384,
            test_stack_bytes=8192,control_stack_bytes=2048,caller_io_bytes=18304,
            rcc_control=0x03038f83,rcc_config=0x0029040a,usart1_brr=833)
        self.devices=[];self.hello_change=None;self.flow_change=None

    def tearDown(self):self.tmp.cleanup()

    def factory(self):
        owner=self
        class Device:
            def __init__(self):self.closed=False;self.records=[];self.calls=[]
            def handshake(self):
                self.info=dict(owner.expected,version=1,status=0,flags=3,detail=0,request_sequence=1,
                    run_sequence=10,session_nonce=len(owner.devices),maximum_payload_bytes=1391,maximum_message_bytes=1024,
                    maximum_context_bytes=255,operation_mask=0x3ffff,kem_entropy_bytes=96,dsa_entropy_bytes=64)
                self.records.append({'fixture':'hello'})
                if owner.hello_change:owner.hello_change(self.info)
                return copy.deepcopy(self.info)
            # Deliberately only these three positional parameters: no entropy override.
            def flow(self,parameter,message,domain):
                self.calls.append((parameter,message,domain));self.records.append({'fixture':'flow'})
                rows=[dict(operation_id=i,return_code=-6 if parameter<100 and i==3 else 0,ticks=100+i,
                      arena_high_water_bytes=1024+i,stack_watermark_bytes=64+i,allocations=2,allocation_failures=0) for i in range(4)]
                value=dict(version=1,status=0,flags=3,detail=0,request_sequence=2,run_sequence=11,
                    session_nonce=self.info['session_nonce'],build_id=BUILD,clock_hz=96000000,parameter=parameter,
                    message_bytes=len(message),context_bytes=len(domain),record_count=4,operations=rows,
                    maximum_arena_bytes=1027,maximum_stack_watermark_bytes=67,pass_mask=255,entropy_consumed=96 if parameter>100 else 64)
                if owner.flow_change:owner.flow_change(value)
                return value
            def close(self):self.closed=True
        value=Device();self.devices.append(value);return value

    def bridge(self):
        return Ch32Exchange(self.factory,expected_elf_sha256=ELF,expected_hello=self.expected,
                            timer_receipt=self.descriptor,records_directory=self.root/'records')

    def request(self,action='run',parameter=512,mode='normal'):
        return dict(schema=wire.SCHEMA,request_id='c'*32,action=action,payload={} if action=='catalog' else dict(
            library='ch32_compact',parameter=parameter,message_bytes=1024 if parameter<100 else 0,
            context_bytes=255 if parameter<100 else 0,mode=mode))

    def test_each_catalog_and_flow_opens_closes_separately(self):
        bridge=self.bridge();catalog=bridge(self.request('catalog'))
        self.assertEqual(catalog['body']['libraries'][0]['run_presets'],dict(message_lengths=[0,32,1024],context_lengths=[0,1,255],modes=['normal']))
        for parameter in wire.PARAMETERS:
            reply=bridge(self.request(parameter=parameter));body=reply['body']
            self.assertTrue(body['functional_checks_passed']);self.assertEqual(body['binary_sha256'],ELF)
            self.assertEqual(body['device_metrics']['resources']['static_ram_bytes'],45632)
            self.assertNotIn('secret_key',body);self.assertNotIn('public_key_sha3_256',body)
        self.assertEqual(len(self.devices),7);self.assertTrue(all(d.closed for d in self.devices))
        self.assertEqual(self.devices[-1].calls[0][1],bytes((i*29+7)&255 for i in range(1024)))
        self.assertEqual(self.devices[-1].calls[0][2],bytes((i*17+3)&255 for i in range(255)))
        records=[json.loads(p.read_text()) for p in (self.root/'records').glob('*.xml')]
        self.assertEqual(len(records),7);self.assertTrue(all(x['closed'] for x in records))
        self.assertTrue(all(x['entropy_source']=='host_os_csprng;not_board_trng' for x in records))

    def test_unsupported_mode_rejected_before_open(self):
        with self.assertRaises(ValueError):self.bridge()(self.request(mode='insufficient'))
        self.assertEqual(self.devices,[])

    def test_wrong_firmware_closed_without_flow(self):
        self.hello_change=lambda x:x.update(build_id='d'*64)
        with self.assertRaises(ValueError):self.bridge()(self.request())
        self.assertTrue(self.devices[0].closed);self.assertEqual(self.devices[0].calls,[])

    def test_changed_clock_registers_rejected_before_flow(self):
        for field in ('rcc_control','rcc_config','usart1_brr'):
            self.hello_change=lambda x,key=field:x.update({key:x[key]^1})
            with self.subTest(field=field),self.assertRaises(ValueError):self.bridge()(self.request())
            self.assertTrue(self.devices[-1].closed);self.assertEqual(self.devices[-1].calls,[])
        old=dict(self.expected);old.pop('rcc_control')
        with self.assertRaises(ValueError):Ch32Exchange(self.factory,expected_elf_sha256=ELF,expected_hello=old,
            timer_receipt=self.descriptor,records_directory=self.root/'records')

    def test_mismatched_input_or_timer_record_rejected(self):
        bridge=self.bridge();self.flow_change=lambda x:x.update(parameter=768)
        with self.assertRaises(ValueError):bridge(self.request())
        self.assertTrue(self.devices[0].closed)
        (self.root/'timer-selftest.bin').write_bytes(b'X'*160)
        with self.assertRaises(ValueError):bridge(self.request())
        self.assertEqual(len(self.devices),1)

    def test_timer_for_another_elf_rejected(self):
        with self.assertRaises(ValueError):Ch32Exchange(self.factory,expected_elf_sha256='d'*64,expected_hello=self.expected,
            timer_receipt=self.descriptor,records_directory=self.root/'records')
        self.assertEqual(self.devices,[])

    def test_early_api_failure_retains_not_run_metrics(self):
        def change(x):
            x.update(status=-105,pass_mask=96,maximum_arena_bytes=1024,maximum_stack_watermark_bytes=64)
            x['operations'][0]['return_code']=-5
            for row in x['operations'][1:]:row.update(return_code=-127,ticks=0,arena_high_water_bytes=0,stack_watermark_bytes=0)
        self.flow_change=change;result=self.bridge()(self.request())['body']
        self.assertFalse(result['functional_checks_passed']);self.assertEqual(len(result['operations']),1)
        self.assertEqual([x['return_code'] for x in result['device_metrics']['operations']],[-5,-127,-127,-127])
        self.assertTrue(self.devices[0].closed)

    def test_provider_adds_uart_identity_without_changing_device_run(self):
        provider=self.bridge().provider();result=provider.run(self.request()['payload'])
        self.assertEqual(result['execution']['transport'],'serial-uart')
        self.assertEqual(result['execution']['device_run_id'],result['run_id'])
        self.assertGreater(result['execution']['host_round_trip_ns'],0)
        self.assertTrue(all(d.closed for d in self.devices))


if __name__=='__main__':unittest.main()
