const Root = artifacts.require('./Root.sol');
const DNSSEC = artifacts.require('./mocks/DummyDNSSEC.sol');
const ENS = artifacts.require('./ENSRegistry.sol');

const utils = require('./helpers/Utils.js');
const namehash = require('eth-ens-namehash');
const dns = require('../lib/dns.js');
const packet = require('dns-packet');

contract('Root', function(accounts) {

    let node;
    let ens, dnssec, root;

    let now = Math.round(new Date().getTime() / 1000);

    beforeEach(async function() {
        node = namehash.hash('eth');

        ens = await ENS.new();
        dnssec = await DNSSEC.new();
        root = await Root.new(ens.address, dnssec.address);

        await ens.setSubnodeOwner(0, web3.sha3('eth'), root.address, {from: accounts[0]});
        await ens.setOwner(0, root.address);
    });

    describe('setSubnodeOwner', async () => {

        it('should fail when trying to set subnode owner for non root domain', async () => {
            try {
                await root.setSubnodeOwner(web3.sha3('eth'), '0x123', accounts[1], {from: accounts[0]});
            } catch (error) {
                return utils.ensureException(error);
            }
        });

        it('should allow setting subnode when trying to owner for root domain', async () => {
            await root.setSubnodeOwner(0, web3.sha3('eth'), accounts[1], {from: accounts[0]});
            assert.equal(accounts[1], await ens.owner(node));
        });
    });

    it('should allow transferring ownership of the root node', async () => {
        assert.equal(root.address, await ens.owner(0));
        await root.transferRoot(accounts[1]);
        assert.equal(accounts[1], await ens.owner(0));
    });

    describe('registerTLD', async () => {

        it('allows registering a TLD on ENS with a custom address', async () => {
            let proof = dns.hexEncodeTXT({
                name: '_ens.test.',
                klass: 1,
                ttl: 3600,
                text: ['a=' + accounts[0]]
            });

            await dnssec.setData(
                16,
                dns.hexEncodeName('_ens.test.'),
                now,
                now,
                proof
            );

            await root.registerTLD(dns.hexEncodeName('test.'), proof);

            assert.equal(await ens.owner(namehash.hash('test')), accounts[0]);
        });

        it.only('should set TLD owner to default registrar when 0x0 is provided', async () => {

            let text = Buffer.from(`a=0x0000000000000000000000000000000000000000`, 'ascii');

            let proof = packet.encode({
                answers: [
                    { name: '_ens.test', type: 'TXT', class: 'IN',  data: text },
                ]
            });

            proof = '0x' + proof.toString('hex');
            console.log("DNS-Packet:" + proof);

            console.log("DNS.js: " + dns.hexEncodeTXT({
                name: '_ens.test.',
                klass: 1,
                ttl: 3600,
                text: ['a=0x0000000000000000000000000000000000000000']
            }));

            await dnssec.setData(
                16,
                hexEncodeName('_ens.test.'),
                now,
                now,
                proof
            );

            await root.registerTLD(hexEncodeName('test'), proof);

            assert.equal(await ens.owner(namehash.hash('test')), await root.DEFAULT_REGISTRAR.call());
        });

        it('should set TLD owner to default registrar when none is provided', async () => {
            let proof = 0;

            await dnssec.setData(
                16,
                hexEncodeName('_ens.test.'),
                now,
                now,
                proof
            );

            await root.registerTLD(dns.hexEncodeName('test.'), proof);

            assert.equal(await ens.owner(namehash.hash('test')), await root.DEFAULT_REGISTRAR.call());
        });
    });
});

let buffer = new Buffer([]);

function hexEncodeName(name) {
    return '0x' + packet.name.encode(name).toString('hex');
}

function rrsigdata(typeCoverd, signersName, override){
    let obj = {
        "typeCovered": typeCoverd,
        "algorithm": 253,
        "labels": 1,
        "originalTTL": 3600,
        "expiration": 2528174800,
        "inception": 1526834834,
        "keyTag": 1277,
        "signersName": signersName,
        "signature": buffer
    };

    return Object.assign(obj, override);
}

