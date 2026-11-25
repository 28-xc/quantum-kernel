"""SYNTHETIC data tests; no project timing/security PASS is inferred."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
import numpy as np

spec=importlib.util.spec_from_file_location('release_timing',Path(__file__).with_name('run.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class SyntheticStatistics(unittest.TestCase):
    def test_prespecified_detector_and_rejection(self):
        root=m.ROOT/'results/release_timing/synthetic_statistics';root.mkdir(exist_ok=True,parents=True)
        p=dict(samples_per_job=10000,checkpoints=[1000,5000,10000],threshold_abs_t=4.5)
        rng=np.random.Generator(np.random.PCG64(202609241723));x=rng.integers(500,1000,size=5000)
        labels=np.tile([0,1],5000);y=np.repeat(x,2).astype(float)
        def save(name,values):
            f=root/name;np.savetxt(f,np.column_stack([labels,values,np.zeros(10000)]),delimiter=',',header='class,tsc_ticks,norm_result',comments='',fmt=['%d','%.1f','%d']);return f
        exact=m.statistics(save('synthetic_equal.csv',y),p)
        self.assertFalse(exact['detected']);self.assertEqual(exact['retained_samples'],10000)
        self.assertTrue(m.statistics(save('synthetic_shift.csv',y+labels*2000),p)['detected'])
        spread=y+1250;spread[labels==1]=2000+(y[labels==1]-750)*4
        result=m.statistics(save('synthetic_spread.csv',spread),p)
        self.assertTrue(any(h['statistic']=='centered_second_moment' and abs(h['welch_t'])>=4.5 for h in result['history']))
        bad=y.copy();bad[5]=np.nan
        with self.assertRaises(ValueError):m.statistics(save('synthetic_nonfinite.csv',bad),p)
        f=save('synthetic_wrong_count.csv',y);lines=f.read_text().splitlines();f.write_text('\n'.join(lines[:-1]))
        with self.assertRaises(ValueError):m.statistics(f,p)

if __name__=='__main__':unittest.main()
