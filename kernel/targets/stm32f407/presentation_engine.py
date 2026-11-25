"""Select the running board backend at connect time; legacy SRAM images remain available."""
from pathlib import Path
import atexit
from . import engine as legacy
from . import qualified_engine as unified
from . import resident_dfu,deployments

class PresentationEngine:
    def __init__(self):
        self.selected=None
        self.manifest=None
        self.rom_serial=None
        self.uid=None
        self.resident=None
        atexit.register(self.close)

    def close(self):
        if self.resident is not None:
            self.resident.close()
            self.resident=None

    def devices(self):
        rows=legacy.devices()
        if self.resident is not None and not any(x['mode']=='cdc' and x['serial']==self.uid for x in rows):
            self.close()
        return rows

    def _attach(self,serial):
        self.close()
        self.resident=unified.Session(self.manifest,serial).__enter__()
        self.uid=self.resident.uid
        return self.resident.identity

    def probe(self,image_dir=None):
        self.close()
        self.selected=None;self.uid=None;self.rom_serial=None
        identity=legacy.probe(image_dir=image_dir)
        if not identity.get('connected'):return identity
        self.manifest=legacy.image_folder(image_dir)/'stm32f407-unified.xml'
        if identity['mode']=='cdc' and (identity.get('parameter'),identity.get('profile'))==(0,240):
            if not self.manifest.is_file():raise legacy.EngineError('image_missing','unified firmware manifest')
            self.manifest=deployments.select_cdc(self.manifest.parent,identity)
            with legacy._device_lock():active=self._attach(identity['serial'])
            self.selected='resident';self.uid=active['uid'];self.rom_serial=legacy._rom_serial(self.uid)
            return active
        if identity['mode']=='dfu' and self.manifest.is_file():
            with legacy._device_lock():found=deployments.select_rom(self.manifest.parent,identity['serial'])
            if found:
                self.manifest=found
                self.selected='resident-rom';self.rom_serial=identity['serial']
                return dict(identity,installed_application='unified',verified_application=False)
        self.selected='legacy'
        return identity

    def deploy(self, profile, records, *, image_dir=None):
        from . import maintenance

        if not self.rom_serial or self.selected not in ('resident', 'resident-rom'):
            raise maintenance.DeploymentError('请先连接已登记正式固件的 STM32F407。')
        images = {}
        for image in deployments.manifests(legacy.image_folder(image_dir)):
            metadata, _ = unified.read_manifest(image)
            images[str(int(metadata['ram_budget_bytes']) // 1024)] = image
        requested = images.get(profile)
        current = self.manifest.resolve()
        if requested is None or current not in images.values():
            raise maintenance.DeploymentError('未找到已登记的 STM32 正式固件。')
        with legacy._device_lock():
            device = legacy._select()
            if device['serial'] != (self.uid if device['mode'] == 'cdc' else self.rom_serial):
                raise maintenance.DeploymentError('STM32 设备身份已变化，请重新连接。')
            if requested == current:
                if device['mode'] == 'dfu':
                    maintenance.boot_deployment(current, self.rom_serial, self.uid)
                return
            try:
                cli = maintenance.find_cli()
            except FileNotFoundError:
                raise maintenance.DeploymentError('本机未找到 STM32CubeProgrammer。', can_reconnect=True) from None
            self.close()
            uid = device['serial']
            if device['mode'] == 'dfu':
                uid = maintenance.boot_deployment(current, self.rom_serial, self.uid)
            maintenance.switch_deployment(current, requested, cli, uid, records)

    def capabilities(self,image_dir=None):
        if self.selected not in ('resident','resident-rom'):
            return legacy.capabilities(image_dir)
        m,cells=unified.read_manifest(self.manifest)
        images=[dict(parameter=p,strategy=st,profile=unified.PROFILE[st],workspace_capacity=cap,image_bytes=int(m['image_bytes']),clock_hz=int(m['clock_hz']),build_tag=m['tag'],sha256=m['sha256']) for (p,st),cap in cells.items()]
        return dict(deployment_kib=int(m['ram_budget_bytes'])//1024,strategies=['compact','cached'],images=images,parameters=list(unified.PARAMETERS),message_lengths=[0,32,256],context_lengths=[0,8,32],modes=['normal','insufficient'])

    def _launch_resident(self):
        if not resident_dfu.check_installed(self.manifest,self.rom_serial,launch=True):
            raise legacy.EngineError('identity','the installed firmware changed')
        live=legacy._wait('cdc',self.rom_serial,timeout=18)
        uid=live['serial']
        if (self.uid and self.uid!=uid) or self.rom_serial!=legacy._rom_serial(uid):
            raise legacy.EngineError('identity','different device after ROM GO')
        identity=self._attach(uid)
        self.selected='resident'
        return identity

    def boot_resident(self):
        if self.selected!='resident-rom':
            raise legacy.EngineError('identity','no verified resident firmware in ROM')
        with legacy._device_lock():
            return self._launch_resident()

    def run(self,**options):
        if self.selected=='legacy':
            # Replacing a board between connecting and running must not evict a new unified firmware.
            identity=legacy.probe(image_dir=options.get('image_dir'),serial=options.get('serial'))
            if not identity.get('connected') or (identity.get('parameter'),identity.get('profile'))==(0,240):
                raise legacy.EngineError('identity','board mode changed; reconnect')
            return legacy.run(**options)
        if self.selected not in ('resident','resident-rom'):raise legacy.EngineError('no_device','connect the board')
        with legacy._device_lock():
            if self.selected=='resident-rom':
                self._launch_resident()
            if self.resident is None:raise legacy.EngineError('no_device','reconnect the board')
            options=dict(options)
            options.pop('image_dir',None);options.pop('serial',None)
            try:return self.resident.run(**options)
            except BaseException:
                self.close()
                raise

