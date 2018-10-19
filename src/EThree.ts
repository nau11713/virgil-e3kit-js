import PrivateKeyLoader from './PrivateKeyLoader';
import VirgilToolbox from './virgilToolbox';
import { CachingJwtProvider } from 'virgil-sdk';
import { VirgilPublicKey, VirgilPrivateKey } from 'virgil-crypto/dist/virgil-crypto-pythia.cjs';
import { BootstrapRequiredError, PasswordRequiredError } from './errors';

export default class EThree {
    private identity: string;
    private toolbox: VirgilToolbox;
    private keyLoader: PrivateKeyLoader;

    static async init(getToken: () => Promise<string>) {
        const provider = new CachingJwtProvider(getToken);
        const token = await provider.getToken({ operation: 'get' });
        const identity = token.identity();
        return new EThree(identity, provider);
    }

    constructor(identity: string, provider: CachingJwtProvider) {
        this.identity = identity;
        this.toolbox = new VirgilToolbox(provider);
        this.keyLoader = new PrivateKeyLoader(identity, this.toolbox);
    }

    async bootstrap(password?: string) {
        const publicKeys = await this.getPublicKeys(this.identity);
        const privateKey = await this.localBootstrap(publicKeys);
        if (privateKey) return;
        if (publicKeys.length > 0) {
            if (!password) {
                throw new PasswordRequiredError();
            } else {
                await this.keyLoader.loadRemotePrivateKey(password);
                return;
            }
        } else {
            const keyPair = this.toolbox.virgilCrypto.generateKeys();
            if (password) await this.keyLoader.savePrivateKeyRemote(keyPair.privateKey, password);
            else await this.keyLoader.savePrivateKeyLocal(keyPair.privateKey);
            await this.toolbox.createCard(keyPair);
            return;
        }
    }

    async localBootstrap(publicKeys: VirgilPublicKey[]) {
        const privateKey = await this.keyLoader.loadLocalPrivateKey();
        if (!privateKey) return null;
        if (publicKeys.length > 0) return privateKey;
        const publicKey = this.toolbox.virgilCrypto.extractPublicKey(privateKey);
        await this.toolbox.createCard({ privateKey, publicKey });
        return privateKey;
    }

    async logout() {
        this.keyLoader.deleteKeys();
    }

    async encrypt(message: string, publicKeys: VirgilPublicKey[]) {
        const privateKey = await this.keyLoader.loadLocalPrivateKey();
        if (!privateKey) throw new BootstrapRequiredError();
        const publicKey = this.toolbox.virgilCrypto.extractPublicKey(privateKey);
        return this.toolbox.virgilCrypto
            .encrypt(message, [publicKey, ...publicKeys] as VirgilPublicKey[])
            .toString('base64');
    }

    async decrypt(message: string) {
        const privateKey = await this.keyLoader.loadLocalPrivateKey();
        if (!privateKey) throw new BootstrapRequiredError();
        return this.toolbox.virgilCrypto
            .decrypt(message, privateKey as VirgilPrivateKey)
            .toString('utf8');
    }

    getPublicKeys(username: string) {
        return this.toolbox.getPublicKeys(username);
    }
}