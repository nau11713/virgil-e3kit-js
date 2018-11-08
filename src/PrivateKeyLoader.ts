import { createBrainKey } from 'virgil-pythia';
import {
    SyncKeyStorage,
    CloudKeyStorage,
    KeyknoxManager,
    KeyknoxCrypto,
} from '@virgilsecurity/keyknox';
import { VirgilPythiaCrypto, VirgilPublicKey, VirgilPrivateKey } from 'virgil-crypto';
import VirgilToolbox from './VirgilToolbox';
import { KeyEntryStorage } from 'virgil-sdk';
import { WrongKeyknoxPasswordError, BootstrapRequiredError } from './errors';

const LOCAL_STORAGE_NAME = 'virgil-local-storage';
const LOCAL_DIR_NAME = '.' + LOCAL_STORAGE_NAME;
const REMOTE_STORAGE_NAME = 'virgil-keyknox-storage';
const REMOTE_DIR_NAME = '.' + REMOTE_STORAGE_NAME;

type KeyPair = {
    privateKey: VirgilPrivateKey;
    publicKey: VirgilPublicKey;
};
export interface IBrainKey {
    generateKeyPair(password: string, id?: string): Promise<KeyPair>;
}

export interface IPrivateKeyLoaderParams {
    dbName: string;
}

export interface PrivateKeyEntry {
    privateKey: VirgilPrivateKey;
    meta: {
        isPublished: boolean;
    };
}

export default class PrivateKeyLoader {
    private pythiaCrypto = new VirgilPythiaCrypto();
    private brainKey: IBrainKey;
    private syncStorage?: Promise<SyncKeyStorage>;
    localStorage: KeyEntryStorage;
    keyknoxStorage: KeyEntryStorage;

    constructor(private identity: string, public toolbox: VirgilToolbox) {
        this.brainKey = createBrainKey({
            virgilCrypto: this.toolbox.virgilCrypto,
            virgilPythiaCrypto: this.pythiaCrypto,
            accessTokenProvider: this.toolbox.jwtProvider,
        });
        this.localStorage = new KeyEntryStorage({
            name: LOCAL_STORAGE_NAME,
            dir: LOCAL_DIR_NAME,
        });
        this.keyknoxStorage = new KeyEntryStorage({
            name: REMOTE_STORAGE_NAME,
            dir: REMOTE_DIR_NAME,
        });
    }

    async savePrivateKeyRemote(privateKey: VirgilPrivateKey, password: string, id?: string) {
        const storage = await this.initStorage(password);
        return await storage.storeEntry(
            this.identity,
            this.toolbox.virgilCrypto.exportPrivateKey(privateKey),
        );
    }

    async savePrivateKeyLocal(privateKey: VirgilPrivateKey, isPublished?: boolean) {
        return await this.localStorage.save({
            name: this.identity,
            value: this.toolbox.virgilCrypto.exportPrivateKey(privateKey),
            meta: {
                isPublished: isPublished ? isPublished.toString() : 'false',
            },
        });
    }

    async updatePrivateKeyLocal(isPublished: boolean) {
        return await this.localStorage.update({
            name: this.identity,
            meta: {
                isPublished: isPublished.toString(),
            },
        });
    }

    async loadLocalPrivateKey() {
        const privateKeyData = await this.localStorage.load(this.identity);
        if (!privateKeyData) return { privateKey: null, isPublished: false };
        return {
            privateKey: this.toolbox.virgilCrypto.importPrivateKey(
                privateKeyData.value,
            ) as VirgilPrivateKey,
            isPublished: privateKeyData.meta ? privateKeyData.meta.isPublished === 'true' : false,
        };
    }

    async resetLocalPrivateKey() {
        this.syncStorage = undefined;
        await Promise.all([
            this.localStorage.remove(this.identity),
            this.keyknoxStorage.remove(this.identity),
        ]);
        return true;
    }

    async resetBackupPrivateKey(password: string) {
        const storage = await this.initStorage(password);

        return await storage.deleteEntry(this.identity);
    }

    async loadRemotePrivateKey(password: string, id?: string) {
        const storage = await this.initStorage(password);
        const rawKey = await storage.retrieveEntry(this.identity);
        await this.localStorage.save({ name: this.identity, value: rawKey.value });
        return this.toolbox.virgilCrypto.importPrivateKey(rawKey.value);
    }

    async changePassword(newPassword: string) {
        if (!this.syncStorage) throw new BootstrapRequiredError();
        const storage = await this.syncStorage;
        const keyPair = await this.generateBrainPair(newPassword);

        const update = await storage.updateRecipients({
            newPrivateKey: keyPair.privateKey,
            newPublicKeys: [keyPair.publicKey],
        });
        return update;
    }

    private async createSyncStorage(password: string) {
        const { privateKey, publicKey } = await this.generateBrainPair(password);
        const storage = new SyncKeyStorage(
            new CloudKeyStorage(
                new KeyknoxManager(
                    this.toolbox.jwtProvider,
                    privateKey,
                    publicKey,
                    undefined,
                    new KeyknoxCrypto(this.toolbox.virgilCrypto),
                ),
            ),
            this.keyknoxStorage,
        );
        try {
            await storage.sync();
        } catch (e) {
            throw new WrongKeyknoxPasswordError();
        }

        return storage;
    }

    private async initStorage(password: string) {
        if (!this.syncStorage) this.syncStorage = this.createSyncStorage(password);
        try {
            await this.syncStorage;
        } catch (e) {
            this.syncStorage = undefined;
            throw e;
        }
        return this.syncStorage;
    }

    private generateBrainPair = (password: string) =>
        this.brainKey.generateKeyPair(password).catch(e => {
            if (typeof e === 'object' && e.code === 60007) {
                const promise = new Promise((resolve, reject) => {
                    const repeat = () =>
                        this.brainKey
                            .generateKeyPair(password)
                            .then(resolve)
                            .catch(reject);
                    setTimeout(repeat, 2000);
                });
                return promise as Promise<KeyPair>;
            }
            throw e;
        });
}
