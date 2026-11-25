'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { promisify } = require('node:util');
const { createRequire } = require('node:module');
const checkLinks = promisify(require('markdown-link-check'));
const { create } = createRequire(require.resolve('markdown-link-check'))('xmlbuilder2');

function valueOf(element) {
    const children = Array.from(element.childNodes).filter(node => node.nodeType === 1);
    switch (element.localName) {
        case 'object':
            return Object.fromEntries(children.map(field => {
                const [name, value] = Array.from(field.childNodes).filter(node => node.nodeType === 1);
                if (field.localName !== 'field' || name?.localName !== 'name' || !value) {
                    throw new Error('Invalid configuration field');
                }
                return [name.textContent, valueOf(value)];
            }));
        case 'list': return children.map(valueOf);
        case 'string': return element.textContent;
        case 'integer':
        case 'number': return Number(element.textContent);
        case 'boolean': return element.textContent === 'true';
        case 'null': return null;
        default: throw new Error(`Unsupported configuration value: ${element.localName}`);
    }
}

function readConfig(filename) {
    const record = create(fs.readFileSync(filename, 'utf8')).root().node;
    if (record.localName !== 'record' || record.getAttribute('format') !== 'typed-xml-v1') {
        throw new Error('Invalid configuration record');
    }
    return valueOf(record.firstElementChild);
}

async function checkFile(configPath, filename) {
    const config = readConfig(configPath);
    const directory = path.dirname(path.resolve(filename)).replaceAll('\\', '/');
    const project = process.cwd().replaceAll('\\', '/');
    const results = await checkLinks(fs.readFileSync(filename, 'utf8'), {
        ...config,
        baseUrl: 'file://' + directory,
        projectBaseUrl: (process.platform === 'win32' ? 'file:///' : 'file://') + project,
        quiet: true,
    });
    const dead = results.filter(result => result.status === 'dead');
    for (const result of dead) console.error(`${filename}: ${result.link} (${result.statusCode})`);
    return { results, exitCode: dead.length ? 1 : 0 };
}

if (require.main === module) {
    checkFile(process.argv[2], process.argv[3])
        .then(result => { process.exitCode = result.exitCode; })
        .catch(error => { console.error(error.message); process.exitCode = 1; });
}
module.exports = { readConfig, checkFile };
