const { expect } = require('chai');
const nacl = require('tweetnacl');
const ed = require('@noble/ed25519');

const vector = {
    seed: Buffer.from('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', 'hex'),
    publicKey: 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
    message: new Uint8Array(0)
};

describe('Ed25519 Correctness Testing (Variant 8)', () => {

    describe('Library: tweetnacl', () => {
        it('має згенерувати вірний публічний ключ із seed', () => {
            const keyPair = nacl.sign.keyPair.fromSeed(vector.seed);
            expect(Buffer.from(keyPair.publicKey).toString('hex')).to.equal(vector.publicKey);
        });

        it('має створити коректний 64-байтний цифровий підпис', () => {
            const keyPair = nacl.sign.keyPair.fromSeed(vector.seed);
            const sig = nacl.sign.detached(vector.message, keyPair.secretKey);
            expect(sig).to.have.lengthOf(64);
        });
    });

    describe('Library: @noble/ed25519', () => {
        it('має згенерувати вірний публічний ключ (сумісність з RFC 8032)', async () => {
            const pubKey = await ed.getPublicKey(vector.seed);
            expect(Buffer.from(pubKey).toString('hex')).to.equal(vector.publicKey);
        });

        it('має створити коректний 64-байтний цифровий підпис', async () => {
            const sig = await ed.sign(vector.message, vector.seed);
            expect(sig).to.have.lengthOf(64);
        });
    });
});