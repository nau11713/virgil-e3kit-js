import PrivateKeyLoader from './PrivateKeyLoader';
import {
    CachingJwtProvider,
    KeyEntryAlreadyExistsError,
    CardManager,
    VirgilCardVerifier,
} from 'virgil-sdk';
import {
    VirgilPublicKey,
    Data,
    VirgilCrypto,
    VirgilCardCrypto,
    VirgilPrivateKey,
} from 'virgil-crypto';
import {
    RegisterRequiredError,
    EmptyArrayError,
    IdentityAlreadyExistsError,
    PrivateKeyAlreadyExistsError,
    MultipleCardsError,
    LookupNotFoundError,
    LookupError,
    DUPLICATE_IDENTITIES,
} from './errors';
import { isArray, isString } from './utils/typeguards';
import { hasDuplicates, getObjectValues } from './utils/array';

interface IEThreeOptions {
    provider: CachingJwtProvider;
    keyLoader?: PrivateKeyLoader;
}

const throwIllegalInvocationError = (method: string) => {
    throw new Error(`Calling ${method} two or more times in a row is not allowed.`);
};

export type KeyPair = {
    privateKey: VirgilPrivateKey;
    publicKey: VirgilPublicKey;
};

export type LookupResult = {
    [identity: string]: VirgilPublicKey;
};

type EncryptVirgilPublicKeyArg = LookupResult | VirgilPublicKey;

const _inProcess = Symbol('inProccess');
const _keyLoader = Symbol('keyLoader');

export default class EThree {
    identity: string;
    virgilCrypto = new VirgilCrypto();
    cardCrypto = new VirgilCardCrypto(this.virgilCrypto);
    cardVerifier = new VirgilCardVerifier(this.cardCrypto);
    cardManager: CardManager;
    jwtProvider: CachingJwtProvider;

    private [_keyLoader]: PrivateKeyLoader;
    private [_inProcess]: boolean = false;

    static async initialize(getToken: () => Promise<string>) {
        const provider = new CachingJwtProvider(getToken);
        const token = await provider.getToken({ operation: 'get' });
        const identity = token.identity();
        return new EThree(identity, { provider });
    }

    constructor(identity: string, options: IEThreeOptions) {
        this.identity = identity;
        this.jwtProvider = options.provider;
        this[_keyLoader] = new PrivateKeyLoader(this.identity, {
            jwtProvider: this.jwtProvider,
            virgilCrypto: this.virgilCrypto,
        });

        this.cardManager = new CardManager({
            cardCrypto: this.cardCrypto,
            cardVerifier: this.cardVerifier,
            accessTokenProvider: this.jwtProvider,
            retryOnUnauthorized: true,
        });
    }

    async register() {
        if (this[_inProcess]) throwIllegalInvocationError('register');
        this[_inProcess] = true;
        try {
            const [cards, privateKey] = await Promise.all([
                this.cardManager.searchCards(this.identity),
                this[_keyLoader].loadLocalPrivateKey(),
            ]);
            if (cards.length > 1) throw new MultipleCardsError(this.identity);
            if (cards.length > 0) throw new IdentityAlreadyExistsError();
            if (privateKey && cards.length === 0) await this[_keyLoader].resetLocalPrivateKey();
            const keyPair = this.virgilCrypto.generateKeys();
            await this._publishCard(keyPair);
            await this[_keyLoader].savePrivateKeyLocal(keyPair.privateKey);
        } finally {
            this[_inProcess] = false;
        }
        return;
    }

    async rotatePrivateKey(): Promise<void> {
        if (this[_inProcess]) throwIllegalInvocationError('rotatePrivateKey');
        this[_inProcess] = true;
        try {
            const [cards, privateKey] = await Promise.all([
                this.cardManager.searchCards(this.identity),
                this[_keyLoader].loadLocalPrivateKey(),
            ]);
            if (cards.length === 0) throw new RegisterRequiredError();
            if (cards.length > 1) throw new MultipleCardsError(this.identity);
            if (privateKey) throw new PrivateKeyAlreadyExistsError();
            const keyPair = this.virgilCrypto.generateKeys();
            await this._publishCard(keyPair, cards[0].id);
            await this[_keyLoader].savePrivateKeyLocal(keyPair.privateKey);
        } finally {
            this[_inProcess] = false;
        }
    }

    async restorePrivateKey(pwd: string): Promise<void> {
        try {
            await this[_keyLoader].restorePrivateKey(pwd);
        } catch (e) {
            if (e instanceof KeyEntryAlreadyExistsError) {
                throw new PrivateKeyAlreadyExistsError();
            }
            throw e;
        }
    }

    async cleanup() {
        await this[_keyLoader].resetLocalPrivateKey();
    }

    async resetPrivateKeyBackup(password: string) {
        return this[_keyLoader].resetBackupPrivateKey(password);
    }

    async encrypt(message: string, publicKeys?: EncryptVirgilPublicKeyArg): Promise<string>;
    async encrypt(message: Buffer, publicKey?: EncryptVirgilPublicKeyArg): Promise<Buffer>;
    async encrypt(message: ArrayBuffer, publicKey?: EncryptVirgilPublicKeyArg): Promise<Buffer>;
    async encrypt(message: Data, publicKeys?: EncryptVirgilPublicKeyArg): Promise<Data> {
        const isString = typeof message === 'string';

        let argument: VirgilPublicKey[];

        if (publicKeys == null) argument = [];
        else if (publicKeys instanceof VirgilPublicKey) argument = [publicKeys];
        else argument = getObjectValues(publicKeys) as VirgilPublicKey[];

        const privateKey = await this[_keyLoader].loadLocalPrivateKey();
        if (!privateKey) throw new RegisterRequiredError();

        const ownPublicKey = this.virgilCrypto.extractPublicKey(privateKey);

        if (!this._isOwnPublicKeysIncluded(ownPublicKey, argument)) {
            argument.push(ownPublicKey);
        }

        let res: Data = this.virgilCrypto.signThenEncrypt(message, privateKey, argument);
        if (isString) res = res.toString('base64');
        return res;
    }

    async decrypt(message: string, publicKey?: VirgilPublicKey): Promise<string>;
    async decrypt(message: Buffer, publicKey?: VirgilPublicKey): Promise<Buffer>;
    async decrypt(message: ArrayBuffer, publicKey?: VirgilPublicKey): Promise<Buffer>;
    async decrypt(message: Data, publicKey?: VirgilPublicKey): Promise<Data> {
        const isMessageString = isString(message);
        const privateKey = await this[_keyLoader].loadLocalPrivateKey();
        if (!privateKey) throw new RegisterRequiredError();
        if (!publicKey) publicKey = this.virgilCrypto.extractPublicKey(privateKey);
        let res: Data = this.virgilCrypto.decryptThenVerify(message, privateKey, publicKey);
        if (isMessageString) return res.toString('utf8') as string;
        return res as Buffer;
    }

    async lookupPublicKeys(identities: string): Promise<VirgilPublicKey>;
    async lookupPublicKeys(identities: string[]): Promise<LookupResult>;
    async lookupPublicKeys(identities: string[] | string): Promise<LookupResult | VirgilPublicKey> {
        const argument = isArray(identities) ? identities : [identities];
        if (argument.length === 0) throw new EmptyArrayError('lookupPublicKeys');
        if (hasDuplicates(argument)) throw new Error(DUPLICATE_IDENTITIES);

        const cards = await this.cardManager.searchCards(argument);

        let result: LookupResult = {},
            resultWithErrors: { [identity: string]: Error } = {};

        for (let identity of argument) {
            const filteredCards = cards.filter(card => card.identity === identity);
            if (filteredCards.length === 0) {
                resultWithErrors[identity] = new LookupNotFoundError(identity);
            } else if (filteredCards.length > 1) {
                resultWithErrors[identity] = new MultipleCardsError(identity);
            } else {
                result[identity] = filteredCards[0].publicKey as VirgilPublicKey;
            }
        }

        if (getObjectValues(resultWithErrors).length !== 0) {
            throw new LookupError({ ...resultWithErrors, ...result });
        }

        if (Array.isArray(identities)) return result;

        return result[identities];
    }

    async changePassword(oldPwd: string, newPwd: string) {
        return await this[_keyLoader].changePassword(oldPwd, newPwd);
    }

    async backupPrivateKey(pwd: string): Promise<void> {
        const privateKey = await this[_keyLoader].loadLocalPrivateKey();
        if (!privateKey) throw new RegisterRequiredError();
        await this[_keyLoader].savePrivateKeyRemote(privateKey, pwd);
        return;
    }

    hasLocalPrivateKey(): Promise<Boolean> {
        return this[_keyLoader].hasPrivateKey();
    }

    private async _publishCard(keyPair: KeyPair, previousCardId?: string) {
        const card = await this.cardManager.publishCard({
            privateKey: keyPair.privateKey,
            publicKey: keyPair.publicKey,
            previousCardId,
        });

        return { keyPair, card };
    }

    private _isOwnPublicKeysIncluded(ownPublicKey: VirgilPublicKey, publicKeys: VirgilPublicKey[]) {
        const selfPublicKey = this.virgilCrypto.exportPublicKey(ownPublicKey).toString('base64');

        const stringKeys = publicKeys.map(key =>
            this.virgilCrypto.exportPublicKey(key).toString('base64'),
        );
        return stringKeys.some((key, i) => key === selfPublicKey);
    }
}
