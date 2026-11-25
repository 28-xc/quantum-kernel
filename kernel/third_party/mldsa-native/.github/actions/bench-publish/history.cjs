'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {execFileSync} = require('node:child_process');
const prefix = 'window.BENCHMARK_DATA = ';
function xml(operation, data) {
    return execFileSync(process.platform === 'win32' ? 'python' : 'python3',
        ['-B',path.join(__dirname,'xml_bridge.py'),operation], {input:data,maxBuffer:512*1024*1024});
}
function check(data) {
    if (!data || typeof data !== 'object' || !Number.isFinite(data.lastUpdate) ||
        typeof data.repoUrl !== 'string' || !data.entries || Array.isArray(data.entries) ||
        typeof data.entries !== 'object') throw new Error('Invalid benchmark history');
    return data;
}
function read(file, legacyPage=false) {
    if (fs.existsSync(file)) return check(JSON.parse(xml('decode',fs.readFileSync(file))));
    const legacy = path.join(path.dirname(file),'data.js');
    if (legacyPage && fs.existsSync(legacy)) {
        const script = fs.readFileSync(legacy,'utf8');
        if (!script.startsWith(prefix)) throw new Error('Missing XML history for an existing custom page');
        return check(JSON.parse(script.slice(prefix.length)));
    }
    return {lastUpdate:0,repoUrl:'',entries:{}};
}
function write(file, data) {
    if (path.extname(file).toLowerCase() !== '.xml') throw new Error('Benchmark history must use .xml');
    const contents = xml('encode',JSON.stringify(check(data)));
    const tmp = file + '.' + crypto.randomUUID() + '.tmp';
    try { fs.writeFileSync(tmp,contents,{flag:'wx'}); fs.renameSync(tmp,file); }
    finally { fs.rmSync(tmp,{force:true}); }
}
function verifyPage(folder,current) {
    const index = path.join(folder,'index.html');
    if (!fs.existsSync(index)) return true;
    const old = fs.readFileSync(index,'utf8').replace(/\r\n/g,'\n');
    const hash = crypto.createHash('sha256').update(old).digest('hex');
    if (old === current || hash === '05821906bc0c97f2c0ac9f68b5d233fcb94eb89710575829e2eb77ed0142f423') return true;
    if (old.includes('loadBenchmarkHistory(') && !/benchmark_data\.json|window\.BENCHMARK_DATA/.test(old)) return false;
    throw new Error('Existing custom benchmark page requires an XML-compatible template before migration');
}
async function updatePage(git,args,rel,base,current) {
    const indexName = path.join(rel,'index.html');
    const index = path.join(base,indexName);
    if (verifyPage(path.dirname(index),current)) fs.writeFileSync(index,current);
    fs.copyFileSync(path.join(__dirname,'page-data.js'),path.join(base,rel,'data.js'));
    await git.cmd(args,'add',indexName,path.join(rel,'data.js'));
}
module.exports={read,write,verifyPage,updatePage};
