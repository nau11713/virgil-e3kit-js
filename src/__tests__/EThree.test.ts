import EThree from '../EThree';
import {
    JwtGenerator,
    KeyEntryStorage,
    CardManager,
    VirgilCardVerifier,
    GeneratorJwtProvider,
    IKeyEntry,
    CachingJwtProvider,
} from 'virgil-sdk';
import {
    VirgilCrypto,
    VirgilAccessTokenSigner,
    VirgilCardCrypto,
    VirgilPublicKey,
    VirgilPythiaCrypto,
} from 'virgil-crypto';
import {
    WrongKeyknoxPasswordError,
    EmptyArrayError,
    BootstrapRequiredError,
    LookupError,
    LookupNotFoundError,
} from '../errors';
import VirgilToolbox from '../VirgilToolbox';
import { createBrainKey } from 'virgil-pythia';
import {
    SyncKeyStorage,
    CloudKeyStorage,
    KeyknoxManager,
    KeyknoxCrypto,
} from '@virgilsecurity/keyknox';

const virgilCrypto = new VirgilCrypto();
const cardCrypto = new VirgilCardCrypto(virgilCrypto);
const cardVerifier = new VirgilCardVerifier(cardCrypto);

export const generator = new JwtGenerator({
    appId: process.env.APP_ID!,
    apiKeyId: process.env.API_KEY_ID!,
    apiKey: virgilCrypto.importPrivateKey(process.env.API_KEY!),
    accessTokenSigner: new VirgilAccessTokenSigner(virgilCrypto),
});

const mockProvider = new GeneratorJwtProvider(generator);

const cardManager = new CardManager({
    cardCrypto: cardCrypto,
    cardVerifier: cardVerifier,
    accessTokenProvider: mockProvider,
    retryOnUnauthorized: true,
});

const keyStorage = new KeyEntryStorage({ dir: '.virgil-local-storage' });
const keyknoxStorage = new KeyEntryStorage({ dir: '.virgil-keyknox-storage' });

const createFetchToken = (identity: string) => () =>
    Promise.resolve(generator.generateToken(identity).toString());

const createSyncStorage = async (identity: string, password: string) => {
    const fetchToken = createFetchToken(identity);
    const brainKey = createBrainKey({
        virgilCrypto: virgilCrypto,
        virgilPythiaCrypto: new VirgilPythiaCrypto(),
        accessTokenProvider: new CachingJwtProvider(fetchToken),
    });

    const keyPair = await brainKey.generateKeyPair(password);

    const storage = new SyncKeyStorage(
        new CloudKeyStorage(
            new KeyknoxManager(
                new CachingJwtProvider(fetchToken),
                keyPair.privateKey,
                keyPair.publicKey,
                undefined,
                new KeyknoxCrypto(virgilCrypto),
            ),
        ),
        keyknoxStorage,
    );

    await storage.sync();
    return storage;
};

describe('VirgilE2ee', () => {
    beforeAll(done => keyStorage.clear().then(() => done()));
    const identity = 'virgiltest' + Date.now();
    const fetchToken = () => Promise.resolve(generator.generateToken(identity).toString());

    it('full integration test', async done => {
        const sdk = await EThree.init(fetchToken);
        const password = 'secret_password';
        const cloudStorage = await createSyncStorage(identity, password);
        await sdk.bootstrap();
        const privateKey = await keyStorage.load(identity);
        expect(privateKey).not.toEqual(null);
        await sdk.backupPrivateKey(password);
        const encrypted = (await sdk.encrypt('message')) as string;
        await sdk.cleanup();
        const key = await keyStorage.load(identity);
        expect(key).toBeNull();
        await sdk.bootstrap(password);

        try {
            await sdk.decrypt(encrypted!);
        } catch (e) {
            expect(e).toBeInstanceOf(Error);
        }

        await sdk.resetPrivateKeyBackup(password);
        try {
            await cloudStorage.sync();
            const cloudKey = await cloudStorage.retrieveEntry(identity);
            expect(cloudKey).not.toBeDefined();
        } catch (e) {
            expect(e).toBeInstanceOf(Error);
        }

        done();
    });
});

describe('local bootstrap (without password)', () => {
    it('AUTH-1 has no local key, has no card', async done => {
        const identity = 'virgiltestlocal1' + Date.now();
        const fetchToken = createFetchToken(identity);
        const sdk = await EThree.init(fetchToken);
        await sdk.bootstrap();
        const cards = await cardManager.searchCards(identity);
        expect(cards.length).toEqual(1);
        done();
    });

    it('has local key, has no card', async done => {
        const identity = 'virgiltestlocal2' + Date.now();
        const fetchToken = createFetchToken(identity);
        keyStorage.save({
            name: identity,
            value: virgilCrypto.exportPrivateKey(virgilCrypto.generateKeys().privateKey),
            meta: { isPublished: 'false' },
        });
        const sdk = await EThree.init(fetchToken);
        await sdk.bootstrap();
        const cards = await cardManager.searchCards(identity);
        expect(cards.length).toEqual(1);
        done();
    });

    it('has local key, has card', async done => {
        const identity = 'virgiltestlocal3' + Date.now();
        const keyPair = virgilCrypto.generateKeys();
        await cardManager.publishCard({ identity: identity, ...keyPair });
        await keyStorage.save({
            name: identity,
            value: virgilCrypto.exportPrivateKey(keyPair.privateKey),
            meta: {
                isPublished: 'true',
            },
        });
        const fetchToken = createFetchToken(identity);
        const prevCards = await cardManager.searchCards(identity);

        expect(prevCards.length).toEqual(1);

        const sdk = await EThree.init(fetchToken);
        await sdk.bootstrap();
        const cards = await cardManager.searchCards(identity);

        expect(cards.length).toEqual(1);
        done();
    });

    it('has no local key, has card', async done => {
        await keyStorage.clear();
        const identity = 'virgiltestlocal4' + Date.now();
        const keyPair = virgilCrypto.generateKeys();
        await cardManager.publishCard({ identity: identity, ...keyPair });
        const fetchToken = createFetchToken(identity);
        const sdk = await EThree.init(fetchToken);
        const cards = await cardManager.searchCards(identity);

        expect(cards.length).toEqual(1);

        try {
            await sdk.bootstrap();
        } catch (e) {
            expect(e).toBeDefined();
            return done();
        }
        done('should throw error');
    });

    it('STA-1 has no local key, has no card', async done => {
        const identity = 'virgiltestlocalnokeynocard' + Date.now();
        const fetchToken = createFetchToken(identity);
        const prevCards = await cardManager.searchCards(identity);
        expect(prevCards.length).toBe(0);
        const sdk = await EThree.init(fetchToken);
        await sdk.bootstrap();
        const [cards, key] = await Promise.all([
            cardManager.searchCards(identity),
            keyStorage.load(identity),
        ]);
        expect(cards.length).toBe(1);
        expect(key).not.toBe(null);
        done();
    });
});

describe('remote bootstrap (with password)', () => {
    it('AUTH-2 has no local key, has no card', async done => {
        const identity = 'virgiltestremote1' + Date.now();
        const fetchToken = createFetchToken(identity);
        const prevCards = await cardManager.searchCards(identity);

        expect(prevCards.length).toBe(0);

        const sdk = await EThree.init(fetchToken);
        await sdk.bootstrap('secure_password');
        const [cards, key] = await Promise.all([
            cardManager.searchCards(identity),
            keyStorage.load(identity),
        ]);
        expect(cards.length).toBe(1);
        expect(key).not.toBe(null);
        done();
    });

    it('has no local key, has card', async done => {
        const identity = 'virgiltestremote2' + Date.now();
        const keyPair = virgilCrypto.generateKeys();
        await cardManager.publishCard({ identity: identity, ...keyPair });
        const fetchToken = createFetchToken(identity);
        const prevCards = await cardManager.searchCards(identity);
        const cloudStorage = await createSyncStorage(identity, 'secret_password');
        await cloudStorage.storeEntry(identity, virgilCrypto.exportPrivateKey(keyPair.privateKey));
        expect(prevCards.length).toBe(1);
        const sdk = await EThree.init(fetchToken);
        await sdk.bootstrap('secret_password');
        const [cards, key] = await Promise.all([
            cardManager.searchCards(identity),
            keyStorage.load(identity),
        ]);
        expect(cards.length).toBe(1);
        expect(key).not.toBe(null);
        expect(virgilCrypto.importPrivateKey(key!.value)).toMatchObject(keyPair.privateKey);
        done();
    });

    it('wrong password', async done => {
        const identity = 'virgiltestremote3' + Date.now();
        const fetchToken = createFetchToken(identity);
        const keyPair = virgilCrypto.generateKeys();
        const cloudStorage = await createSyncStorage(identity, 'secret_password');
        await Promise.all([
            cardManager.publishCard({ identity: identity, ...keyPair }),
            cloudStorage.storeEntry(identity, virgilCrypto.exportPrivateKey(keyPair.privateKey)),
        ]);
        const prevCards = await cardManager.searchCards(identity);
        await keyknoxStorage.remove(identity);
        await keyStorage.remove(identity);
        expect(prevCards.length).toBe(1);
        const sdk = await EThree.init(fetchToken);
        try {
            await sdk.bootstrap('not_secret_password');
        } catch (e) {
            expect(e).toBeInstanceOf(WrongKeyknoxPasswordError);
            return done();
        }
        done('should throw error');
    });
});

describe('lookupKeys', () => {
    const identity = 'virgiltestlookup' + Date.now();
    const fetchToken = () => Promise.resolve(generator.generateToken(identity).toString());

    it('STE-1 lookupKeys success', async done => {
        const sdk = await EThree.init(fetchToken);
        const identity1 = 'virgiltestlookup1' + Date.now();
        const identity2 = 'virgiltestlookup2' + Date.now();
        const identity3 = 'virgiltestlookup3' + Date.now();
        const keypair1 = virgilCrypto.generateKeys();
        const keypair2 = virgilCrypto.generateKeys();
        const keypair3 = virgilCrypto.generateKeys();

        await Promise.all([
            cardManager.publishCard({ identity: identity1, ...keypair1 }),
            cardManager.publishCard({ identity: identity2, ...keypair2 }),
            cardManager.publishCard({ identity: identity3, ...keypair3 }),
        ]);
        const publicKeys = await sdk.lookupPublicKeys([identity1, identity2, identity3]);

        expect(publicKeys.length).toBe(3);
        expect(virgilCrypto.exportPublicKey(publicKeys[0]).toString('base64')).toEqual(
            virgilCrypto.exportPublicKey(keypair1.publicKey).toString('base64'),
        );
        expect(virgilCrypto.exportPublicKey(publicKeys[1]).toString('base64')).toEqual(
            virgilCrypto.exportPublicKey(keypair2.publicKey).toString('base64'),
        );
        expect(virgilCrypto.exportPublicKey(publicKeys[2]).toString('base64')).toEqual(
            virgilCrypto.exportPublicKey(keypair3.publicKey).toString('base64'),
        );
        done();
    });

    it('lookupKeys nonexistent identity', async done => {
        const sdk = await EThree.init(fetchToken);
        const identity1 = 'virgiltestlookupnonexist' + Date.now();
        const identity2 = 'virgiltestlookupnonexist' + Date.now();
        try {
            await sdk.lookupPublicKeys([identity1, identity2]);
        } catch (e) {
            expect(e.rejected.length).toBe(2);
            expect(e.rejected[0]).toBeInstanceOf(LookupNotFoundError);
            expect(e.rejected[1]).toBeInstanceOf(LookupNotFoundError);
            return done();
        }

        return done('should throw');
    });

    it('lookupKeys with error', async done => {
        const identity1 = 'virgiltestlookuperror1' + Date.now();
        const keypair1 = virgilCrypto.generateKeys();
        const fnStore = VirgilToolbox.prototype.getPublicKey;
        VirgilToolbox.prototype.getPublicKey = jest
            .fn()
            .mockResolvedValueOnce(keypair1.publicKey as VirgilPublicKey)
            .mockRejectedValueOnce(new Error('something happens'))
            .mockRejectedValueOnce(new LookupNotFoundError('not exists'));

        const provider = new CachingJwtProvider(fetchToken);

        const sdk = new EThree(identity, provider, new VirgilToolbox(provider));

        await Promise.all([cardManager.publishCard({ identity: identity1, ...keypair1 })]);

        try {
            const res = await sdk.lookupPublicKeys([identity1, 'not exists', 'with error']);
            expect(res).not.toBeDefined();
        } catch (e) {
            expect(e).toBeInstanceOf(LookupError);
            expect(e.resolved.length).toBe(1);
            expect(e.rejected.length).toBe(2);
            expect(e.rejected[0]).toBeInstanceOf(Error);
            expect(e.rejected[1]).toBeInstanceOf(LookupNotFoundError);
            VirgilToolbox.prototype.getPublicKey = fnStore;
            return done();
        }
        VirgilToolbox.prototype.getPublicKey = fnStore;
        done('should throw');
    });

    it('STE-2 lookupKeys with empty array of identities', async done => {
        const sdk = await EThree.init(fetchToken);
        try {
            await sdk.lookupPublicKeys([]);
        } catch (e) {
            expect(e).toBeInstanceOf(EmptyArrayError);
            return done();
        }
        done('should throw');
    });
});

describe('change password', () => {
    it('should change password', async done => {
        const identity = 'virgiltest' + Date.now();
        const fetchToken = () => Promise.resolve(generator.generateToken(identity).toString());
        try {
            const sdk = await EThree.init(fetchToken);
            await sdk.changePassword('old_password', 'new_password');
            await sdk.cleanup();
            await sdk.bootstrap('new_password');
        } catch (e) {
            expect(e).not.toBeDefined();
            return done(e);
        }
        done();
    });

    it('should change password faster if already bootstraped', async done => {
        const identity = 'virgiltest' + Date.now();
        const fetchToken = () => Promise.resolve(generator.generateToken(identity).toString());
        try {
            const sdk = await EThree.init(fetchToken);
            await sdk.bootstrap('old_password');
            await sdk.changePassword('old_password', 'new_password');
            await sdk.cleanup();
            await sdk.bootstrap('new_password');
        } catch (e) {
            expect(e).not.toBeDefined();
            return done(e);
        }
        done();
    });
});

describe('backupPrivateKey', () => {
    const identity = 'virgiltestbackup' + Date.now();
    const fetchToken = () => Promise.resolve(generator.generateToken(identity).toString());

    it('success', async done => {
        const sdk = await EThree.init(fetchToken);
        const storage = await createSyncStorage(identity, 'secret_password');

        try {
            await storage.retrieveEntry(identity);
        } catch (e) {
            expect(e).toBeInstanceOf(Error);
        }

        try {
            await sdk.bootstrap();
            await sdk.backupPrivateKey('secret_password');
        } catch (e) {
            expect(e).not.toBeDefined();
        }
        const key = await storage.retrieveEntry(identity);
        expect(key).not.toBeNull();
        done();
    });

    it('fail', async done => {
        const sdk = await EThree.init(fetchToken);
        try {
            await sdk.bootstrap('secret_pass');
            await sdk.backupPrivateKey('secret_pass');
        } catch (e) {
            expect(e).toBeDefined();
            return done();
        }
        return done('should throw');
    });
});

describe('encrypt and decrypt', () => {
    const identity = 'virgiltestencrypt' + Date.now();
    const fetchToken = () => Promise.resolve(generator.generateToken(identity).toString());

    it('STE-3 ', async done => {
        const identity1 = 'virgiltestencrypt1' + Date.now();
        const identity2 = 'virgiltestencrypt2' + Date.now();

        const fetchToken1 = () => Promise.resolve(generator.generateToken(identity1).toString());
        const fetchToken2 = () => Promise.resolve(generator.generateToken(identity2).toString());

        const [sdk1, sdk2] = await Promise.all([
            EThree.init(fetchToken1),
            EThree.init(fetchToken2),
        ]);

        const unusedKeypair = virgilCrypto.generateKeys();

        await Promise.all([sdk1.bootstrap(), sdk2.bootstrap()]);
        const message = 'encrypt, decrypt, repeat';
        const sdk1PublicKeys = await sdk1.lookupPublicKeys([identity1]);
        const sdk2PublicKeys = await sdk2.lookupPublicKeys([identity2]);
        const encryptedMessage = await sdk1.encrypt(message, sdk2PublicKeys);
        try {
            await sdk2.decrypt(encryptedMessage, [unusedKeypair.publicKey]);
        } catch (e) {
            expect(e).toBeInstanceOf(Error);
        }
        const decryptedMessage = await sdk2.decrypt(encryptedMessage, sdk1PublicKeys);
        expect(decryptedMessage).toEqual(message);
        done();
    });

    it('STE-4 encrypt for empty public keys', async done => {
        const sdk = await EThree.init(fetchToken);
        await sdk.bootstrap();
        try {
            await sdk.encrypt('privet', []);
        } catch (e) {
            expect(e).toBeInstanceOf(EmptyArrayError);
            return done();
        }
        done('should throw');
    });

    it('STE-5 decrypt for empty public keys', async done => {
        const sdk = await EThree.init(fetchToken);
        await sdk.bootstrap();
        const keyPair = virgilCrypto.generateKeys();
        const message = await sdk.encrypt('privet', [keyPair.publicKey]);
        try {
            await sdk.decrypt(message, []);
        } catch (e) {
            expect(e).toBeInstanceOf(EmptyArrayError);
            return done();
        }
        done('should throw');
    });

    it('STE-6 encrypt and decrypt without public keys', async done => {
        const sdk = await EThree.init(fetchToken);
        await sdk.bootstrap();
        const message = 'secret message';
        const encryptedMessage = await sdk.encrypt(message);
        const decryptedMessage = await sdk.decrypt(encryptedMessage);
        expect(decryptedMessage).toEqual(message);
        done();
    });

    it('STE-7 decrypt message without sign', async done => {
        const sdk = await EThree.init(fetchToken);
        await sdk.bootstrap();
        const receiverPublicKey = await sdk.lookupPublicKeys([identity]);
        const { publicKey: senderPublicKey } = virgilCrypto.generateKeys();
        const message = 'encrypted, but not signed :)';
        const encryptedMessage = await virgilCrypto
            .encrypt(message, receiverPublicKey)
            .toString('base64');
        try {
            await sdk.decrypt(encryptedMessage, [senderPublicKey]);
        } catch (e) {
            expect(e).toBeDefined();
            return done();
        }
        done('should throw');
    });

    it('STE-8 no decrypt/encrypt before bootstrap', async done => {
        await keyStorage.clear();
        const sdk = await EThree.init(fetchToken);
        try {
            await sdk.encrypt('message');
        } catch (e) {
            expect(e).toBeInstanceOf(BootstrapRequiredError);
        }
        try {
            await sdk.decrypt('message');
        } catch (e) {
            expect(e).toBeInstanceOf(BootstrapRequiredError);
        }
        done();
    });

    it('should return buffer', async done => {
        const identity = 'virgiltestencryptbuffer' + Date.now();
        const fetchToken = () => Promise.resolve(generator.generateToken(identity).toString());

        const buf = new Buffer('123');

        const recipient = virgilCrypto.generateKeys();
        const sdk = await EThree.init(fetchToken);
        await sdk.bootstrap();
        const publicKeys = await sdk.lookupPublicKeys([identity]);
        const encryptedMessage = await sdk.encrypt(buf, [recipient.publicKey]);
        expect(encryptedMessage).toBeInstanceOf(Buffer);

        const resp = await sdk.decrypt(encryptedMessage, publicKeys);
        expect(resp).toBeInstanceOf(Buffer);
        done();
    });
});

describe('cleanup()', () => {
    it('should delete key on logout', async done => {
        const identity = 'virgiltestlogout' + Date.now();
        const fetchToken = () => Promise.resolve(generator.generateToken(identity).toString());

        const sdk = await EThree.init(fetchToken);
        await sdk.bootstrap('secure_password');
        const isDeleted = await sdk.cleanup();
        const privateKeyFromLocalStorage = await keyStorage.load(identity);
        const privateKeyFromKeyknox = await keyknoxStorage.load(identity);
        expect(privateKeyFromLocalStorage).toEqual(null);
        expect(privateKeyFromKeyknox).toEqual(null);
        expect(isDeleted).toBe(true);
        done();
    });

    it('reset backup private key', async done => {
        const identity = 'virgiltestlogout' + Date.now();
        const fetchToken = () => Promise.resolve(generator.generateToken(identity).toString());

        const sdk = await EThree.init(fetchToken);
        await sdk.bootstrap('secure_password');
        await sdk.resetPrivateKeyBackup('secure_password');
        try {
            await sdk.backupPrivateKey('secure_password');
        } catch (e) {
            expect(e).not.toBeDefined();
        }

        return done();
    });
});
