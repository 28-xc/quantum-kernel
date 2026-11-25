"""Replay the public output predicates on Windows and POSIX path shapes without writes."""
from pathlib import Path,PureWindowsPath,PurePosixPath
import ast,unittest
ROOT=Path(__file__).resolve().parents[2]
class WindowsPath(PureWindowsPath):
    def exists(self):return self.name=='existing'
class PosixPath(PurePosixPath):
    def exists(self):return self.name=='existing'

class OutputPaths(unittest.TestCase):
    def test_fresh_disjoint_paths_are_drive_independent(self):
        entries=[('tools/reproduce.py','main','out','fresh output'),('tools/deploy.py','execute','output','Fresh independent'),
          ('tools/build.py','build','output','fresh build'),('tools/build.py','bundle','output','Fresh independent'),
          ('tools/build_variants.py','main','out','fresh dedicated'),('tools/size_variants.py','main','out','Fresh output')]
        for file,function,variable,message in entries:
            source=(ROOT/file).read_text(encoding='utf-8');tree=ast.parse(source)
            self.assertNotIn("drive.upper()",source,file)
            fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name==function)
            tests=[n.test for n in ast.walk(fn) if isinstance(n,ast.If) and any(isinstance(s,ast.Raise) and message in ast.unparse(s) for s in n.body)]
            self.assertEqual(len(tests),1,file);expression=compile(ast.Expression(tests[0]),file,'eval')
            for kind,root,values in [(WindowsPath,'D:/source',[('C:/artifacts/new',False),('E:/new',False),('D:/outputs/new',False),('D:/source/sub/new',True),('D:/source',True),('C:/existing',True)]),
                                     (PosixPath,'/work/source',[('/tmp/new',False),('/work/source/sub/new',True),('/work/source',True),('/tmp/existing',True)])]:
                for value,expected in values:
                    with self.subTest(file=file,path=value):self.assertEqual(bool(eval(expression,{'ROOT':kind(root),variable:kind(value)})),expected)
if __name__=='__main__':unittest.main()
