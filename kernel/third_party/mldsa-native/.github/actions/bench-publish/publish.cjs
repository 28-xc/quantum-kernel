'use strict';
const fs = require('node:fs');
const path = require('node:path');
const {execFileSync} = require('node:child_process');

function readRows(text) {
    const lines = text.split(/\r?\n/);
    if (lines.at(-1) === '') lines.pop();
    if (lines.shift() !== 'name\tunit\tvalue') throw new Error('Unexpected benchmark TSV header');
    return lines.map((line, index) => {
        const fields = line.split('\t');
        if (fields.length !== 3 || !fields[0] || fields[1] !== 'cycles' || !/^\d+$/.test(fields[2])) {
            throw new Error('Invalid benchmark TSV row ' + (index + 2));
        }
        const value = Number(fields[2]);
        if (!Number.isSafeInteger(value)) throw new Error('Cycle count exceeds the safe integer range on row ' + (index + 2));
        return {name: fields[0], unit: fields[1], value};
    });
}

function main() {
    if (!process.env.RUNNER_TEMP) throw new Error('RUNNER_TEMP is required');
    const dest = fs.mkdtempSync(path.join(process.env.RUNNER_TEMP, 'ml-dsa-benchmark-'));
    execFileSync(process.platform === 'win32' ? 'python' : 'python3',
        ['-B', path.join(__dirname, 'prepare_publisher.py'), dest], {stdio: 'inherit'});
    require(path.join(dest, 'dist/src/index.js'));
}
module.exports = {readRows};
if (require.main === module) main();
