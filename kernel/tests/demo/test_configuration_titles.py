"""Public technical labels preserve configuration identity and observations."""
from pathlib import Path
import copy,csv,io,sys,unittest
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from demo import presentation as view

TITLES={
 'lattice-packed-secret-fused-sparse':'紧凑秘密系数 · 融合范数检查',
 'lattice-packed-secret-xof-reuse':'融合范数检查 · SHAKE 状态复用',
 'lattice-direct-matrix-sampling':'矩阵系数直接采样',
 'lattice-direct-matrix-sampling-xof-reuse':'矩阵直接采样 · SHAKE 状态复用',
 'lattice-native':'原生统一实现',
 'lattice-unified-previous':'原生统一实现 · 前一镜像',
 'lattice-neon-mixed-sampling':'NEON 矩阵与噪声混合采样',
 'lattice-neon-base':'NEON 矩阵与噪声分别采样',
 'lattice-expanded-secret-original-lowbits':'展开秘密系数 · 65/87 低位 19 位',
 'lattice-packed-secret-original-lowbits':'紧凑秘密系数 · 65/87 低位 19 位',
 'lattice-packed-secret-windows-unwind':'紧凑秘密系数 · Windows 栈回溯',
 'lattice-expanded-secret-polyz-lowbits':'展开秘密系数 · 65/87 低位 20 位',
 'lattice-packed-secret-polyz-lowbits':'紧凑秘密系数 · 65/87 低位 20 位',
 'lattice-packed-secret-aligned32':'紧凑秘密系数 · 32 字节函数对齐',
}

class Titles(unittest.TestCase):
    def setUp(self):
        self.data=dict(schema='lattice.pooled_median_statistics.v1',dataset_id='technical-label-fixture',platform='windows_x86_64',configurations=[dict(id=k) for k in TITLES],cells=[dict(configuration=k,parameter=65,operation=1,pooled_samples=9,pooled_mean_ns=123.5,pooled_median_ns=122,pooled_p95_ns=130,pooled_p99_ns=140) for k in TITLES])
    def test_exact_titles_and_parameter_scope(self):
        for name,title in TITLES.items():self.assertEqual(view.configuration_title(name),title)
        for name in TITLES:
            if 'lowbits' in name:self.assertIn('65/87',view.configuration_title(name))
    def test_catalog_keeps_all_configuration_ids(self):
        result=view.catalog({'fixture':self.data});self.assertEqual(result['configurations'],TITLES)
    def test_json_view_preserves_all_observations(self):
        original=copy.deepcopy(self.data);result=view.result_export(self.data)
        self.assertEqual(self.data,original);self.assertEqual(result['configuration_titles'],TITLES)
        for key in self.data:self.assertEqual(result['measurement'][key],self.data[key])
    def test_csv_keeps_ids_and_numeric_values(self):
        rows=list(csv.DictReader(io.StringIO(view.result_csv(self.data))))
        self.assertEqual(len(rows),len(TITLES))
        for row,name in zip(rows,TITLES):
            self.assertEqual(row['配置编号'],name);self.assertEqual(row['配置'],TITLES[name]);self.assertEqual(float(row['均值_ns']),123.5);self.assertEqual(float(row['p99_ns']),140)
    def test_existing_and_unknown_labels_remain(self):
        self.assertEqual(view.configuration_title('pqclean-reference'),'PQClean C 参考（GCC）')
        self.assertEqual(view.configuration_title('future-configuration'),'future-configuration')

if __name__=='__main__':unittest.main()
