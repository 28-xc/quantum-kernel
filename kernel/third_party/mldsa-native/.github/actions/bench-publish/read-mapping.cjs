'use strict';
const fs = require('node:fs');
const lines = fs.readFileSync(require('node:path').join(__dirname, 'mapping.tsv'), 'utf8').trimEnd().split('\n');
if (lines.shift() !== 'first\tlast\tstatus\tmapping\tflag') throw new Error('Invalid IDNA table header');
module.exports = lines.map(line => {
    const [first,last,status,mapping,flag] = line.split('\t');
    const item = [[Number(first), Number(last)], status];
    if (mapping !== '-') item.push(mapping ? mapping.split(',').map(Number) : []);
    if (flag) item.push(flag);
    return item;
});
