"""Live workspace plans for the selected armv7e-m backends."""
import secrets
import xml.etree.ElementTree as ET
from . import unified_engine as base
from .unified_engine import EngineError,PROFILE,PARAMETERS,decode_i32,read_manifest

class Session(base.Session):
    def __enter__(self):
        super().__enter__()
        try:
            from pathlib import Path
            file=Path(self.image)
            if file.is_dir():file=file/'stm32f407-unified.xml'
            self.contract={(int(x.get('parameter')),x.get('strategy')):[int(x.get(f'bound{i}')) for i in range(3)] for x in ET.parse(file).getroot() if x.get('bound0')}
        except BaseException:self.close();raise
        return self
    def query(self,parameter,strategy,operation,address_mod_32=0,workspace_bytes=None,nonce=None):
        if (parameter,strategy) not in self.contract or operation not in (0,1,2) or type(address_mod_32) is not int or not 0<=address_mod_32<32:raise EngineError('invalid_request','unsupported workspace selection')
        cap=self.cells[parameter,strategy]
        budget=cap if workspace_bytes is None else workspace_bytes
        if type(budget) is not int or not 0<=budget<1<<32:raise EngineError('invalid_request','invalid supplied capacity')
        n=nonce or secrets.token_hex(16)
        r=self.port.command(13,n,parameter,PROFILE[strategy],budget,operation,address_mod_32,0,0,timeout=10)
        self._validate_chip(r)
        if (r[12],r[13],r[23],r[24],r[38],r[41],r[43],r[49],r[50],r[52])!=(parameter,PROFILE[strategy],1,0,cap,self.contract[parameter,strategy][operation],32,int(self.meta['full_reserved_ram_bytes']),int(self.meta['stack_capacity']),1):
            raise EngineError('identity','workspace plan disagrees with selected resident build')
        return dict(parameter=parameter,strategy=strategy,operation=operation,request_id=n,address_mod_32=address_mod_32,caller_bytes=budget,plan_code=decode_i32(r[25]),aligned_workspace_bound=r[41],front_padding=r[44],usable_bytes=r[45],required_usable_bytes=r[46],required_total_bytes=r[47],io_bytes=r[48],full_ram_bytes=r[49],stack_capacity=r[50],active_transaction_bytes=r[51],context_bytes=r[54],plan_bytes=r[57],union_bytes=r[61],flash_bytes=r[62],raw_words=r)
    def run(self,parameter,strategy='compact',mode='normal',message_len=32,context_len=8,nonce=None,workspace_bytes=None,*,entropy='hardware',command='run'):
        response=super().run(parameter,strategy,mode,message_len,context_len,nonce,workspace_bytes,entropy=entropy,command=command)
        if command=='run' and (parameter,strategy) in self.contract:
            budget=self.cells[parameter,strategy] if mode=='insufficient' else response['workspace_bytes']
            plans=[self.query(parameter,strategy,j,0,budget) for j in range(3)]
            for i,(peak,plan) in enumerate(zip(response['workspace_peaks'],plans)):
                if plan['plan_code'] or peak>plan['aligned_workspace_bound']:raise EngineError('identity','observed workspace exceeds selected production plan')
            response['resource_plans']=plans
        return response

