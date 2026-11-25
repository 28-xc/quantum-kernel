"""Offline regression checks for the WinUSB warm-up and LEAVE boundary."""
import hashlib
import unittest
from unittest.mock import Mock,patch
import engine

class StagingTests(unittest.TestCase):
    def setUp(self):
        self.data=b'example SRAM image'
        self.sha=hashlib.sha256(self.data).hexdigest()
        self.first=Mock()
        self.second=Mock()
        for dev in (self.first,self.second):
            dev.status.return_value=(0,0,2)
            dev.read.return_value=self.data
        self.ident=patch.object(engine.dfu,'identify').start()
        self.make=patch.object(engine.dfu,'Device',side_effect=[self.first,self.second]).start()
        self.select=patch.object(engine,'_wait',return_value={'serial':'1234','path':'DFU'}).start()
        patch.object(engine.time,'sleep').start()
        self.addCleanup(patch.stopall)
    def test_rom_busy_then_ready(self):
        self.first.status.side_effect=OSError(22,'not ready')
        engine._upload_sram('1234',self.data,self.sha)
        self.assertEqual(self.make.call_count,2)
        self.assertTrue(all(x.args[:2]==('dfu','1234') for x in self.select.call_args_list))
        self.first.close.assert_called_once();self.first.leave.assert_not_called()
        self.second.close.assert_called_once();self.second.leave.assert_called_once()
    def test_incomplete_read_is_replaced_and_reverified(self):
        self.first.read.side_effect=OSError(1167,'device detached')
        engine._upload_sram('1234',self.data,self.sha)
        self.first.leave.assert_not_called();self.second.leave.assert_called_once()
        self.second.write.assert_called_once_with(engine.dfu.BASE,self.data)
    def test_jump_is_never_repeated(self):
        self.first.leave.side_effect=OSError(22,'USB detached at jump')
        with self.assertRaises(OSError):engine._upload_sram('1234',self.data,self.sha)
        self.assertEqual(self.make.call_count,1);self.first.leave.assert_called_once()
    def test_identity_failure_is_not_retried(self):
        self.select.return_value={'serial':'OTHER','path':'DFU'}
        with self.assertRaises(engine.EngineError) as caught:engine._upload_sram('1234',self.data,self.sha)
        self.assertEqual(caught.exception.code,'identity');self.make.assert_not_called()
    def test_changed_bytes_are_never_started(self):
        self.first.read.return_value=b'other'
        with self.assertRaises(engine.EngineError) as caught:engine._upload_sram('1234',self.data,self.sha)
        self.assertEqual(caught.exception.code,'image_invalid');self.first.leave.assert_not_called()
if __name__=='__main__':unittest.main()

