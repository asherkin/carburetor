'use strict';

if (!String.prototype.padStart) {
    String.prototype.padStart = function padStart(targetLength,padString) {
        targetLength = targetLength>>0; //floor if number or convert non-number to 0;
        padString = String(padString || ' ');
        if (this.length > targetLength) {
            return String(this);
        }
        else {
            targetLength = targetLength-this.length;
            if (targetLength > padString.length) {
                padString += padString.repeat(targetLength/padString.length); //append to original to ensure we are longer than needed
            }
            return padString.slice(0,targetLength) + String(this);
        }
    };
}

if (!String.prototype.padEnd) {
    String.prototype.padEnd = function padEnd(targetLength,padString) {
        targetLength = targetLength>>0; //floor if number or convert non-number to 0;
        padString = String(padString || ' ');
        if (this.length > targetLength) {
            return String(this);
        }
        else {
            targetLength = targetLength-this.length;
            if (targetLength > padString.length) {
                padString += padString.repeat(targetLength/padString.length); //append to original to ensure we are longer than needed
            }
            return String(this) + padString.slice(0,targetLength);
        }
    };
}

function print_memory(region) {
	const base = region.base;
	const memory = Buffer.from(region.data, 'base64');

	if (memory.length !== region.size) {
		throw new Error('size mismatch');
	}

	const kAddressBytes = 4;
	const kHeader = false;
	const kRowBytes = 16;
	const kChunkBytes = 8;
	const kChunkText = false;

	if (kHeader) {
		let line = ' '.repeat(kAddressBytes * 2) + '  ';
		let string = '';
		for (let i = 0; i < kRowBytes; ++i) {
			line += i.toString(16).padStart(2, ' ') + ' ';
			string += ' ';
			//string += i.toString(16).padStart(2, ' ').substr(1, 1);

			if (kChunkBytes > 0 && i < (kRowBytes - 1) && (i % kChunkBytes) === (kChunkBytes - 1)) {
				line += ' ';
				if (kChunkText) {
					string += ' ';
				}
			}
		}
		line += '  ' + string + ' ';
		console.log(line);
	}

	for (let offset = 0; offset < memory.length;) {
		let line = (base + offset).toString(16).padStart(kAddressBytes * 2, '0') + '  ';

		let string = '';
		for (let i = 0; i < kRowBytes; ++i, ++offset) {
			if (offset < memory.length) {
				line += memory[offset].toString(16).padStart(2, '0') + ' ';

				const character = String.fromCharCode(memory[offset]);
				string += (character.length === 1 && character.match(/^[ -~]$/)) ? character : '.';
			} else {
				line += '   ';
				string += ' ';
			}

			if (kChunkBytes > 0 && i < (kRowBytes - 1) && (i % kChunkBytes) === (kChunkBytes - 1)) {
				line += ' ';

				if (kChunkText) {
					string += ' ';
				}
			}
		}

		line += ' |' + string + '|';

		console.log(line);
	}
}

let chunks = [];

process.stdout.on('error', function(err) {
	if (err.code === 'EPIPE') {
		process.exit(0);
		return;
	}

	throw err;
});

process.stdin.resume();
process.stdin.setEncoding('utf-8');

process.stdin.on('data', (chunk) => {
	chunks.push(chunk);
});

process.stdin.on('end', () => {
	let data = {};
	
	try {
		data = JSON.parse(chunks.join(''));
	} catch(e) {
		console.log('Failed to parse input: ' + e);
		process.exit(1);
	}

	const memory = data.memory;
	if (!memory) {
		console.log('No memory regions in input');
		process.exit(1);
	}

	memory.sort((a, b) => (a.base - b.base));

	const start = memory[0].base;
	const end = memory[memory.length - 1].base + memory[memory.length - 1].size;
	const size = end - start;
	const real = memory.map((a) => a.size).reduce((a, b) => (a + b), 0);

	//console.log(start.toString(16), end.toString(16), size, real);
	console.log('Got ' + real + ' bytes of memory covering ' + start.toString(16).padStart(8, '0') + ' to ' + end.toString(16).padStart(8, '0') + ' (' + (real / size) + '% coverage)')
	console.log('');

	for (let i = 0; i < memory.length; ++i) {
		print_memory(memory[i]);
		console.log('');
	}
});
