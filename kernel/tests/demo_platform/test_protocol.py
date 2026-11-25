"""Offline protocol tests. Fakes are not hardware or cryptographic measurements."""
from pathlib import Path
import copy
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
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from demo import platform_protocol as wire
from demo import platform_providers as providers
from demo.platform_server import UnifiedApplication

PIN = 'a' * 64
RUN = dict(library='test-arm', parameter=512, message_bytes=0, context_bytes=0, mode='normal')


def result():
    return dict(operations=[dict(operation=n, return_code=0, outcome='SUCCESS', arena_high_water_bytes=16)
                            for n in ('keygen', 'encaps', 'decaps', 'decaps_modified_ciphertext')],
                checks={'shared_secret_equal': True, 'implicit_rejection': True}, functional_checks_passed=True,
                workspace_bytes=32, observed_arena_high_water_bytes=16, canaries_ok=True, failure_output_zero=None,
                schema=1, kind='local_functional_observation', run_id='device-run-1', algorithm='ML-KEM',
                binary_sha256=PIN, performance_measurement=False, **RUN)


class FakeApplication:
    def catalog(self):
        return {'libraries': [dict(id='test-arm', binary_sha256=PIN, parameters=[512], execution_available=True)]}

    def run(self, value):
        return result()


class ProtocolTests(unittest.TestCase):
    def test_discrete_workspace_forwarding_and_response_binding(self):
        class CapacityFixture(FakeApplication):
            def catalog(self):
                value=super().catalog();value['libraries'][0].update(workspace_bytes=57024,workspace_options=[42944,57024]);return value
            def run(self,request):
                value=result();value.update(workspace_bytes=request['workspace_bytes'],requested_workspace_bytes=request['workspace_bytes']);return value
        runner=wire.FunctionalRunner(CapacityFixture(),'arm','workspace-fixture');calls=[]
        def exchange(sent):calls.append(copy.deepcopy(sent));return runner.dispatch(sent)
        provider=providers.ExchangeProvider('arm',exchange,{'test-arm':PIN},'offline-fixture')
        provider.catalog()
        for capacity in (42944,57024):
            request=dict(RUN,workspace_bytes=capacity);observed=provider.run(request)
            self.assertEqual(observed['workspace_bytes'],capacity);self.assertEqual(calls[-1]['payload'],request)
        before=len(calls)
        with self.assertRaises(ValueError):provider.run(dict(RUN,workspace_bytes=65536))
        self.assertEqual(len(calls),before)
        for capacity in (True,42943,'42944'):
            with self.assertRaises(ValueError):wire.run_request(dict(RUN,workspace_bytes=capacity))
        request=dict(RUN,workspace_bytes=42944);observed=CapacityFixture().run(request);observed['workspace_bytes']=57024
        with self.assertRaises(ValueError):wire.functional_result(observed,request)

    def test_closed_device_metrics_and_not_host_latency(self):
        observed = result()
        metrics = dict(schema='lattice.device_metrics.v1',
                       timer=dict(source='systick-hclk', frequency_hz=144000000, counter_bits=64, validated=True),
                       resources=dict(flash_bytes=53856, static_ram_bytes=45632, workspace_bytes=32,
                                      test_stack_reserved_bytes=8192, control_stack_reserved_bytes=2048, caller_io_bytes=18304),
                       scope='public-api-including-internal-cleanup;excluding-outer-cleanup-hash-uart',
                       operations=[dict(operation=x['operation'], return_code=0, ticks=100,
                                        observed_stack_bytes=64, observed_arena_high_water_bytes=16) for x in observed['operations']])
        observed.update(device_metrics=metrics, performance_measurement=True)
        wire.functional_result(observed, RUN)
        for field, value in [('ticks', -1), ('return_code', -127), ('observed_stack_bytes', 8193)]:
            changed = copy.deepcopy(observed); changed['device_metrics']['operations'][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                wire.functional_result(changed, RUN)
        changed = copy.deepcopy(observed); changed['device_metrics']['timer']['validated'] = False
        with self.assertRaises(ValueError): wire.functional_result(changed, RUN)
        changed = copy.deepcopy(observed); changed['device_metrics']['secret_key'] = 'never-forwarded'
        with self.assertRaises(ValueError): wire.functional_result(changed, RUN)
        changed = copy.deepcopy(observed); changed.pop('device_metrics')
        with self.assertRaises(ValueError): wire.functional_result(changed, RUN)

    def provider(self, change=None):
        runner = wire.FunctionalRunner(FakeApplication(), 'ch32', 'fake-session')
        def exchange(sent):
            reply = runner.dispatch(sent)
            if change and sent['action'] == 'run':
                change(reply)
            return reply
        return providers.BoardProvider(exchange, {'test-arm': PIN})

    def test_delegated_result_keeps_original_identity(self):
        provider = self.provider()
        self.assertEqual(provider.catalog()['libraries'][0]['id'], 'test-arm')
        observed = provider.run(dict(RUN))
        self.assertEqual(observed['run_id'], 'device-run-1')
        self.assertEqual(observed['execution']['image_sha256'], PIN)
        self.assertEqual(observed['execution']['sequence'], 2)
        self.assertTrue(observed['execution']['live'])

    def test_input_fields_and_types(self):
        for value in (dict(RUN, command='x'), dict(RUN, parameter=True), dict(RUN, message_bytes=32),
                      dict(RUN, mode='retry'), dict(RUN, library='x;command')):
            with self.subTest(value=value), self.assertRaises(ValueError):
                wire.run_request(value)

    def test_duplicate_trailing_and_nonfinite_json(self):
        for raw in (b'{"a":1,"a":2}', b'{}{}', b'{"a":NaN}', b'x' * (wire.MAX_REQUEST + 1)):
            with self.subTest(raw=raw[:20]), self.assertRaises((ValueError, json.JSONDecodeError)):
                wire.decode(raw, wire.MAX_REQUEST)

    def test_wrong_transport_id_and_image_rejected(self):
        modifiers = [lambda r: r.update(request_id='0' * 32), lambda r: r.update(platform_id='arm'),
                     lambda r: r['body'].update(binary_sha256='b' * 64),
                     lambda r: r['body'].update(parameter=768),
                     lambda r: r['body'].update(secret_key='forbidden'),
                     lambda r: r['body'].update(functional_checks_passed=True, canaries_ok=False),
                     lambda r: r['body'].update(operations=[])]
        for change in modifiers:
            provider = self.provider(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                provider.run(dict(RUN))
            self.assertEqual(provider.state, 'disconnected')

    def test_catalog_image_change(self):
        runner = wire.FunctionalRunner(FakeApplication(), 'ch32', 'fake-session')
        def exchange(sent):
            reply = runner.dispatch(sent)
            reply['body']['libraries'][0]['binary_sha256'] = 'b' * 64
            return reply
        provider = providers.BoardProvider(exchange, {'test-arm': PIN})
        with self.assertRaises(ValueError):
            provider.catalog()
        self.assertEqual(provider.state, 'disconnected')

    def test_busy_is_not_resent(self):
        exchange = mock.Mock()
        provider = providers.BoardProvider(exchange, {'test-arm': PIN})
        provider.lock.acquire()
        try:
            with self.assertRaisesRegex(providers.ProviderError, 'BUSY'):
                provider.run(dict(RUN))
            exchange.assert_not_called()
        finally:
            provider.lock.release()

    def test_driver_failure_is_not_retried(self):
        exchange = mock.Mock(side_effect=TimeoutError('fixture'))
        provider = providers.BoardProvider(exchange, {'test-arm': PIN})
        with self.assertRaises(TimeoutError):
            provider.run(dict(RUN))
        self.assertEqual(exchange.call_count, 1)
        self.assertEqual(provider.state, 'disconnected')

    def test_repeated_sequence_rejected(self):
        provider = self.provider(lambda r: r.update(sequence=2))
        provider.run(dict(RUN))
        with self.assertRaises(ValueError):
            provider.run(dict(RUN))

    def test_board_presets_reject_before_execution(self):
        runner = wire.FunctionalRunner(FakeApplication(), 'ch32', 'fake-session')
        called = []
        def exchange(sent):
            called.append(sent['action'])
            reply = runner.dispatch(sent)
            if sent['action'] == 'catalog':
                reply['body']['libraries'][0]['run_presets'] = dict(message_lengths=[0,32,1024], context_lengths=[0,1,255], modes=['normal'])
            return reply
        provider = providers.BoardProvider(exchange, {'test-arm': PIN})
        provider.catalog()
        with self.assertRaises(ValueError):
            provider.run(dict(RUN, mode='insufficient'))
        self.assertEqual(called, ['catalog'])

    def test_fixed_ssh_command_does_not_contain_request(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name in ('ssh.exe', 'key with space', 'known_hosts'):
                (root / name).write_text('offline fixture')
            config = dict(ssh_executable=str(root/'ssh.exe'), identity_file=str(root/'key with space'),
                          known_hosts_file=str(root/'known_hosts'), host='arm.example.invalid', user='operator', port=22,
                          remote_python='python3', remote_runner='/srv/demo source/tools/demo_remote.py',
                          remote_config='/srv/functional.xml', timeout_seconds=10, image_pins={'test-arm': PIN})
            provider = providers.SshProvider(config)
            command = provider.command()
            self.assertIn('StrictHostKeyChecking=yes', command)
            self.assertNotIn(RUN['library'], ' '.join(command))
            self.assertEqual(command[-1], "python3 -B '/srv/demo source/tools/demo_remote.py' --config /srv/functional.xml --platform arm")
            config['host'] = 'bad;hostname'
            with self.assertRaises(ValueError):
                providers.SshProvider(config)

    def test_bounded_child_echo_timeout_and_overflow(self):
        # Local Python fixtures exercise the transport helper; they do not invoke SSH.
        echoed = providers._bounded_command([sys.executable, '-B', '-c', 'import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())'], b'{}', 5)
        self.assertEqual(echoed, b'{}')
        with self.assertRaisesRegex(providers.ProviderError, 'TRANSPORT_TIMEOUT'):
            providers._bounded_command([sys.executable, '-B', '-c', 'import time;time.sleep(5)'], b'{}', .1)
        with self.assertRaises(providers.ProviderError):
            providers._bounded_command([sys.executable, '-B', '-c', 'import sys;sys.stdout.buffer.write(b"x"*1100000)'], b'{}', 5)

    def test_unified_router_preserves_device_result_identity(self):
        base = FakeApplication()
        base.runs = {}
        base.descriptors = {}
        base.catalog = lambda: {'libraries': []}
        router = UnifiedApplication(base, {'ch32': self.provider()})
        self.assertFalse(router.platform_catalog()['platforms'][1]['configured'])
        with self.assertRaisesRegex(providers.ProviderError, 'NOT_CONNECTED'):
            router.run(dict(RUN))
        router.connect('ch32')
        self.assertEqual(router.catalog()['libraries'][0]['platform_id'], 'ch32')
        record = router.run(dict(RUN))
        self.assertNotEqual(record['run_id'], 'device-run-1')
        self.assertEqual(record['execution']['device_run_id'], 'device-run-1')
        self.assertEqual(router.runs[record['run_id']], record)
        self.assertEqual(router.public_results('test-arm')['views'], [])

    def test_same_id_cannot_connect_different_image(self):
        base = FakeApplication()
        base.runs = {}
        base.descriptors = {}
        base.catalog = lambda: {'libraries': [dict(id='test-arm', platform='ch32v307', binary_sha256='b'*64)]}
        router = UnifiedApplication(base, {'ch32': self.provider()})
        with self.assertRaises(ValueError):
            router.connect('ch32')
        self.assertEqual(router.providers['ch32'].state, 'disconnected')
        self.assertEqual(router.providers['ch32'].capabilities, {})
        self.assertNotIn('ch32', router.remote_rows)


if __name__ == '__main__':
    unittest.main()
