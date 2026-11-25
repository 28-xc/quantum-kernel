def once(source, before, after):
    if source.count(before) != 1:
        raise ValueError('Pinned source changed near '+before[:75])
    return source.replace(before,after,1)

def section(source, start, end, replacement):
    a=source.index(start)
    b=source.index(end,a)
    return source[:a]+replacement+'\n'+source[b:]

def adapt(out):
    dist=out/'dist/src'
    extract=dist/'extract.js'
    source=extract.read_text(encoding='utf8')
    source=once(source,'return exports.BenchmarkResults.parse(JSON.parse(output));',
        "return exports.BenchmarkResults.parse(require('../../publish.cjs').readRows(output));")
    extract.write_text(once(source,'must be JSON file containing an array of entries in BenchmarkResult format',
        'must contain benchmark TSV rows (name, unit, value)'),encoding='utf8')
    config=dist/'config.js'
    source=config.read_text(encoding='utf8').replace('external-data-json-path','external-data-xml-path')
    source=once(source,"let externalDataJsonPath = core.getInput('external-data-xml-path');",
        """let externalDataJsonPath = core.getInput('external-data-xml-path');
    const previousName = core.getInput('external-data-json-path');
    if (previousName && externalDataJsonPath && previousName !== externalDataJsonPath) throw Error('Conflicting external history paths');
    externalDataJsonPath = externalDataJsonPath || previousName;""")
    source=once(source,'const p = resolvePath(path);\n        if (await isDir(p))',
        "const p = resolvePath(path);\n        if (!p.toLowerCase().endsWith('.xml')) throw Error('Expected an XML history path');\n        if (await isDir(p))")
    config.write_text(source.replace('given JSON file','given XML file'),encoding='utf8')
    page=dist/'default_index_html.js'
    original=page.read_text(encoding='utf8')
    html=original.replace('#3273dc','#222').replace('#3298dc','#444').replace('#2793da','#222')
    html=section(html,'        // Colors from','        function init()', '')
    html=once(html,'const color = toolColors[dataset.length > 0 ? dataset[0].tool : \'_\'];',"const color = '#333333';")
    html=html.replace('Download data as JSON','Download XML').replace('(function() {','(async function() {',1)
    html=once(html,'const data = window.BENCHMARK_DATA;', 'const data = await loadBenchmarkHistory();')
    html=once(html,'function init() {','async function init() {')
    html=once(html,'renderAllChars(init());','renderAllChars(await init());')
    html=once(html,"const dataUrl = 'data:,' + JSON.stringify(data, null, 2);","const dataUrl = 'data.xml';")
    html=once(html,"a.download = 'benchmark_data.json';","a.download = 'benchmark_data.xml';")
    page.write_text(html,encoding='utf8')
    writer=dist/'write.js'
    src=writer.read_text(encoding='utf8')
    src=once(src,'const fs_1 = require("fs");','const fs_1 = require("fs");\nconst history = require("../../history.cjs");')
    src=section(src,'async function loadDataJs(', 'function biggerIsBetter(',
        '''async function addIndexHtmlIfNeeded(args, dir, base) {
    return history.updatePage(git,args,dir,base,default_index_html_1.DEFAULT_INDEX_HTML);
}''')
    src=once(src,"path.join(benchmarkDataDirFullPath, 'data.js')","path.join(benchmarkDataDirFullPath, 'data.xml')")
    src=once(src,'const data = await loadDataJs(dataPath);','history.verifyPage(benchmarkDataDirFullPath,default_index_html_1.DEFAULT_INDEX_HTML);\n    const data = history.read(dataPath,true);')
    src=once(src,'await storeDataJs(dataPath, data);','history.write(dataPath,data);')
    src=once(src,"path.join(benchmarkDataRelativeDirPath, 'data.js')","path.join(benchmarkDataRelativeDirPath, 'data.xml')")
    src=section(src,'async function loadDataJson(', 'async function writeBenchmarkToExternalJson(', '')
    src=once(src,'const data = await loadDataJson(jsonFilePath);','const data = history.read(jsonFilePath);')
    src=once(src,"await fs_1.promises.writeFile(jsonFilePath, JSON.stringify(data, null, 2), 'utf8');",
        'history.write(jsonFilePath,data);')
    writer.write_text(src.replace('benchmark data as JSON','benchmark data as XML'),encoding='utf8')
