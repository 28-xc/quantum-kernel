"""Small offline XLSX exports for demonstration results; no third-party runtime."""
import csv
import io
import re
import zipfile
import math
from xml.sax.saxutils import escape

def column(n):
    value=''
    while n:n,r=divmod(n-1,26);value=chr(65+r)+value
    return value

def workbook(tables, *, widths=None, filters=()):
    out=io.BytesIO()
    types=['<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>',
           '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>']
    sheets=[];relations=[]
    with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:
        for ordinal,(name,rows) in enumerate(tables,1):
            rows=list(rows);maximum=max((len(r) for r in rows),default=1)
            sheet_widths = (widths or {}).get(name, [44] + [30]*(maximum-1))
            types.append(f'<Override PartName="/xl/worksheets/sheet{ordinal}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>')
            sheets.append(f'<sheet name="{escape(name)}" sheetId="{ordinal}" r:id="rId{ordinal}"/>')
            relations.append(f'<Relationship Id="rId{ordinal}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{ordinal}.xml"/>')
            body=[]
            for r,values in enumerate(rows,1):
                cells=[]
                line_count=1
                for c,value in enumerate(values,1):
                    ref=f'{column(c)}{r}';style=1 if r==1 else 0
                    if value is not None:
                        line_widths=[sum(2 if ord(ch)>255 else 1 for ch in part) for part in str(value).split('\n')]
                        line_count=max(line_count,sum(max(1,math.ceil(n/(sheet_widths[c-1]-4))) for n in line_widths))
                    if value is None:cells.append(f'<c r="{ref}" s="{style}"/>');continue
                    if isinstance(value,bool):
                        cells.append(f'<c r="{ref}" s="{style}" t="b"><v>{int(value)}</v></c>');continue
                    if isinstance(value,(int,float)) and len(str(value).replace('.','').replace('-',''))<=15:
                        cells.append(f'<c r="{ref}" s="{style}"><v>{value}</v></c>');continue
                    text=escape(str(value)).replace('\r','&#13;')
                    cells.append(f'<c r="{ref}" s="{style}" t="inlineStr"><is><t xml:space="preserve">{text}</t></is></c>')
                body.append(f'<row r="{r}" ht="{max(30,line_count*16+6)}" customHeight="1">'+''.join(cells)+'</row>')
            cols=''.join(f'<col min="{c}" max="{c}" width="{width}" customWidth="1"/>' for c,width in enumerate(sheet_widths,1))
            auto_filter=f'<autoFilter ref="A1:{column(maximum)}{len(rows)}"/>' if name in filters and len(rows)>1 else ''
            z.writestr(f'xl/worksheets/sheet{ordinal}.xml','<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews><cols>'+cols+'</cols><sheetData>'+''.join(body)+'</sheetData>'+auto_filter+'</worksheet>')
        relations.append(f'<Relationship Id="rId{len(sheets)+1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>')
        z.writestr('[Content_Types].xml','<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>'+''.join(types)+'</Types>')
        z.writestr('_rels/.rels','<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>')
        z.writestr('xl/workbook.xml','<?xml version="1.0" encoding="UTF-8"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>'+''.join(sheets)+'</sheets></workbook>')
        z.writestr('xl/_rels/workbook.xml.rels','<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'+''.join(relations)+'</Relationships>')
        z.writestr('xl/styles.xml','<?xml version="1.0" encoding="UTF-8"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="2"><font><sz val="11"/><color rgb="FF000000"/><name val="宋体"/></font><font><b/><sz val="11"/><color rgb="FF000000"/><name val="宋体"/></font></fonts><fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills><borders count="1"><border><left style="thin"><color rgb="FFB0B0B0"/></left><right style="thin"><color rgb="FFB0B0B0"/></right><top style="thin"><color rgb="FFB0B0B0"/></top><bottom style="thin"><color rgb="FFB0B0B0"/></bottom><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" applyAlignment="1"><alignment vertical="center" wrapText="1"/></xf><xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyAlignment="1"><alignment vertical="center" wrapText="1"/></xf></cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>')
    return out.getvalue()

def csv_workbook(blob):
    if isinstance(blob,bytes):blob=blob.decode('utf-8-sig')
    rows=[]
    for row in csv.reader(io.StringIO(blob)):
        values=[]
        for value in row:
            if re.fullmatch(r'-?(0|[1-9][0-9]{0,14})',value):values.append(int(value))
            else:values.append(value if value!='' else None)
        rows.append(values)
    return workbook([('实验结果',rows)])

def functional_workbook(result):
    if result.get('kind') == 'stm32f407_live_observation':
        parameters = [['项目', '值'], ['来源', '本次实板运行'], ['设备', result['platform']],
                      ['算法', result['algorithm']], ['参数', result['parameter']], ['策略', {'compact':'低内存','cached':'高性能'}.get(result['strategy'],result['strategy'])],
                      ['测试', '容量不足与恢复' if result['mode'] == 'insufficient' else '完整流程'],
                      ['时钟（Hz）', result['clock_hz']], ['Flash 固件（B）' if result.get('image_storage')=='flash' else 'SRAM 固件（B）', result['image_bytes']],
                      ['固定 RAM（B）', result['static_ram_bytes']], ['观测栈峰值（B）', result['stack_peak']]]
        plans=all('workspace_bound_bytes' in item for item in result['operations'])
        if plans:parameters.append(['预留栈（B）',result['stack_capacity']])
        if result['mode'] == 'insufficient':
            parameters.extend([['容量不足返回码', result.get('insufficient_code')], ['恢复返回码', result.get('recovery_code')]])
        if result['parameter'] < 100:
            parameters.extend([['消息（B）', result['message_bytes']], ['上下文（B）', result['context_bytes']]])
        operations = [['阶段', '操作', '返回码', '周期', '耗时（μs）', *(['工作区上界（B）'] if plans else []), '工作区峰值（B）', '观测栈峰值（B）']]
        checks = [['阶段', '检查', '结果']]
        for phase, data in [('本次调用', result), ('恢复容量', result.get('recovery'))]:
            if not data:
                continue
            for item in data['operations']:
                operations.append([phase, item['operation_title'], item['return_code'], item['cycles'],
                                   item['microseconds'], *([item['workspace_bound_bytes']] if plans else []), item['arena_high_water_bytes'], item['stack_bytes']])
            checks.extend([phase, key, '通过' if value else '失败'] for key, value in data['checks'].items())
        return workbook([('运行参数', parameters), ('操作结果', operations), ('功能检查', checks)])
    from demo.presentation import CHECKS
    platform = result.get('execution', {}).get('platform_id')
    platforms = {'windows': 'Windows', 'arm': 'Linux AArch64', 'ch32': 'CH32V307'}
    strategies = {'low-memory': '低内存', 'performance': '高性能', 'arm-low-memory': '低内存',
                  'arm-performance': '高性能', 'ch32-partial64': '64 KiB 高性能'}
    if result.get('operations'):
        parameters = [['项目','值'], ['来源', '本次运行'], ['平台', platforms.get(platform,platform)],
                      ['算法',result.get('algorithm')], ['参数',result.get('parameter')],
                      ['策略',strategies.get(result.get('library'),result.get('library'))],
                      ['工作区（B）',result.get('workspace_bytes')]]
        if (result.get('parameter') or 0) < 100:
            parameters.extend([['消息（B）',result.get('message_bytes')], ['上下文（B）',result.get('context_bytes')]])
    else:
        parameters = [['项目','值']]+[[k,v] for k,v in result.items() if not isinstance(v,(dict,list))]
    operations=[['阶段','操作','返回码','状态','工作区峰值（字节）']]
    checks=[['阶段','检查','结果']]
    for title,value in [('本次调用',result),('恢复容量',result.get('recovery',{}))]:
        for row in value.get('operations',[]):
            operations.append([title,row.get('operation_title',row['operation']),row['return_code'],row.get('result_description', row['outcome']),row['arena_high_water_bytes']])
        for k,v in value.get('checks',{}).items():
            checks.append([title,CHECKS.get(k,k),'通过' if v else '失败'])
        for k in ('functional_checks_passed','canaries_ok','failure_output_zero'):
            labels = {'functional_checks_passed': '正常流程', 'canaries_ok': '缓冲区边界', 'failure_output_zero': '失败输出清零'}
            if value.get(k) is not None and not (k == 'functional_checks_passed' and value.get('mode') == 'insufficient'):
                checks.append([title,labels[k],'通过' if value[k] else '失败'])
    if len(operations)==1:
        operations=[['操作','完成次数']]+[[k,v] for k,v in result.get('operation_counts',{}).items()]
    sheets = [('运行参数',parameters),('密码操作',operations),('检查结果',checks)]
    metrics = result.get('device_metrics')
    if metrics:
        from demo.presentation import OPERATIONS
        hz = metrics['timer']['frequency_hz']
        table = [['操作', '设备周期', '耗时（μs）', '观测栈（B）']]
        for entry in metrics['operations']:
            ticks = entry['ticks'] if entry['return_code'] != -127 else None
            table.append([OPERATIONS.get(entry['operation'], entry['operation']), ticks,
                          round(ticks * 1_000_000 / hz, 3) if ticks is not None else None,
                          entry['observed_stack_bytes'] if ticks is not None else None])
        sheets.append(('实板测量', table))
    return workbook(sheets)
