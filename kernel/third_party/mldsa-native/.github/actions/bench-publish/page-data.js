'use strict';
function benchmarkText(node) {
    const text = node.textContent;
    if (!node.hasAttribute('encoding')) return text;
    if (node.getAttribute('encoding') !== 'base64-utf8-surrogatepass') throw Error('Unknown XML string encoding');
    const bytes = Uint8Array.from(atob(text), c => c.charCodeAt(0));
    const decoder = new TextDecoder('utf-8',{fatal:true,ignoreBOM:true});
    let start=0, result='';
    for (let i=0;i+2<bytes.length;i++) {
        if (bytes[i]===0xed && (bytes[i+1]&0xe0)===0xa0 && (bytes[i+2]&0xc0)===0x80) {
            result += decoder.decode(bytes.subarray(start,i)) + String.fromCharCode(
                ((bytes[i]&15)<<12) | ((bytes[i+1]&63)<<6) | (bytes[i+2]&63));
            i+=2; start=i+1;
        }
    }
    return result + decoder.decode(bytes.subarray(start));
}
function benchmarkValue(node) {
    switch (node.tagName) {
    case 'string': return benchmarkText(node);
    case 'null': return null;
    case 'integer':
    case 'number': return Number(node.textContent);
    case 'boolean': return node.textContent === 'true';
    case 'list': return Array.from(node.children,benchmarkValue);
    case 'object': return Object.fromEntries(Array.from(node.children, field =>
        [benchmarkText(field.children[0]),benchmarkValue(field.children[1])]));
    default: throw Error('Unknown history element: '+node.tagName);
    }
}
async function loadBenchmarkHistory() {
    const response = await fetch('data.xml',{cache:'no-cache'});
    if (!response.ok) throw Error('Benchmark history HTTP '+response.status);
    const doc = new DOMParser().parseFromString(await response.text(),'application/xml');
    if (doc.documentElement.tagName !== 'record' || doc.documentElement.getAttribute('format') !== 'typed-xml-v1') {
        throw Error('Invalid benchmark XML document');
    }
    return benchmarkValue(doc.documentElement.firstElementChild);
}
