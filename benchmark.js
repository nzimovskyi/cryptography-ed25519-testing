const nacl = require('tweetnacl');
const ed = require('@noble/ed25519');
const { performance } = require('perf_hooks');

const ITERATIONS = 1000;
const seed = Buffer.alloc(32, 1); 
const message = new Uint8Array(64).fill(101); 

async function runBenchmark() {
    console.log(`\nПорівняння продуктивності Ed25519 (${ITERATIONS} ітерацій)`);
    console.log('--------------------------------------------------');


    const keyPairNacl = nacl.sign.keyPair.fromSeed(seed);
    const startNacl = performance.now();
    for (let i = 0; i < ITERATIONS; i++) {
        nacl.sign.detached(message, keyPairNacl.secretKey);
    }
    const endNacl = performance.now();
    const timeNacl = (endNacl - startNacl).toFixed(2);
    console.log(`tweetnacl: ${timeNacl} мс`);

    const startNoble = performance.now();
    for (let i = 0; i < ITERATIONS; i++) {
        await ed.sign(message, seed);
    }
    const endNoble = performance.now();
    const timeNoble = (endNoble - startNoble).toFixed(2);
    console.log(`@noble/ed25519: ${timeNoble} мс`);

    console.log('--------------------------------------------------');
    
    const diff = (timeNoble / timeNacl).toFixed(2);
    const winner = timeNacl < timeNoble ? 'tweetnacl' : '@noble/ed25519';
    
    console.log(`Результат: ${winner} виявилася швидшою.`);
    console.log(`Відносна різниця: ${diff}x`);
}

runBenchmark().catch(console.error);