// Copyright 2017-2023 @polkadot/ui-keyring authors & contributors
// SPDX-License-Identifier: Apache-2.0

import type { KeyringPair, KeyringPair$Json, KeyringPair$Meta } from '@polkadot/keyring/types';
import type { BN } from '@polkadot/util';
import type { EncryptedJson } from '@polkadot/util-crypto/json/types';
import type { KeypairType } from '@polkadot/util-crypto/types';
import type { AddressSubject, SingleAddress } from './observable/types.js';
import type { CreateResult, KeyringAddress, KeyringAddressType, KeyringItemType, KeyringJson, KeyringJson$Meta, KeyringOptions, KeyringPairs$Json, KeyringStruct } from './types.js';

import { createPair } from '@polkadot/keyring';
import { chains } from '@polkadot/ui-settings';
import { bnToBn, hexToU8a, isFunction, isHex, isString, objectSpread, stringify, stringToU8a, u8aSorted, u8aToString } from '@polkadot/util';
import { base64Decode, createKeyMulti, jsonDecrypt, jsonEncrypt } from '@polkadot/util-crypto';

import { env } from './observable/env.js';
import { KeyringOption } from './options/index.js';
import { Base } from './Base.js';
import { accountKey, accountRegex, addressKey, addressRegex, contractKey, contractRegex } from './defaults.js';

const RECENT_EXPIRY = 24 * 60 * 60;

// No accounts (or test accounts) should be loaded until after the chain determination.
// Chain determination occurs outside of Keyring. Loading `keyring.loadAll({ type: 'ed25519' | 'sr25519' })` is triggered
// from the API after the chain is received
export class Keyring extends Base implements KeyringStruct {
  public readonly keyringOption = new KeyringOption();

  #stores = {
    account: (): AddressSubject => this.accounts,
    address: (): AddressSubject => this.addresses,
    contract: (): AddressSubject => this.contracts
  };

  public async addExternal (address: string | Uint8Array, meta: KeyringPair$Meta = {}): Promise<CreateResult> {
    const pair = this.keyring.addFromAddress(address, objectSpread<KeyringJson$Meta>({}, meta, { isExternal: true }), null);
    const json = await this.saveAccount(pair);

    return {
      json,
      pair
    };
  }

  public async addHardware (address: string | Uint8Array, hardwareType: string, meta: KeyringPair$Meta = {}): Promise<CreateResult> {
    return await this.addExternal(address, objectSpread<KeyringPair$Meta>({}, meta, { hardwareType, isHardware: true }));
  }

  public async addMultisig (addresses: (string | Uint8Array)[], threshold: bigint | BN | number, meta: KeyringPair$Meta = {}): Promise<CreateResult> {
    let address = createKeyMulti(addresses, threshold);

    // For Ethereum chains, the first 20 bytes of the hash indicates the actual address
    // Testcases via creation and on-chain events:
    // -  input: 0x7a1671a0224c8927b08f978027d586ab6868de0d31bb5bc956b625ced2ab18c4
    // - output: 0x7a1671a0224c8927b08f978027d586ab6868de0d
    if (this.isEthereum) {
      address = address.slice(0, 20);
    }

    // we could use `sortAddresses`, but rather use internal encode/decode so we are 100%
    const who = u8aSorted(
      addresses.map((who) => this.decodeAddress(who))
    ).map((who) => this.encodeAddress(who));

    return await this.addExternal(address, objectSpread<KeyringPair$Meta>({}, meta, { isMultisig: true, threshold: bnToBn(threshold).toNumber(), who }));
  }

  public async addPair (pair: KeyringPair, password: string): Promise<CreateResult> {
    this.keyring.addPair(pair);
    const json = await this.saveAccount(pair, password);

    return {
      json,
      pair
    };
  }

  public async addUri (suri: string, password?: string, meta: KeyringPair$Meta = {}, type?: KeypairType): Promise<CreateResult> {
    const pair = this.keyring.addFromUri(suri, meta, type);
    const json = await this.saveAccount(pair, password);

    return {
      json,
      pair
    };
  }

  public backupAccount (pair: KeyringPair, password: string): KeyringPair$Json {
    if (!pair.isLocked) {
      pair.lock();
    }

    pair.decodePkcs8(password);

    return pair.toJson(password);
  }

  public async backupAccounts (addresses: string[], password: string): Promise<KeyringPairs$Json> {
    const accountPromises = addresses.map((address) => {
      return new Promise<KeyringJson>(async (resolve) => {
        const data = await this._forageStore.get(accountKey(address));
        resolve(data);
      });
    });

    const accounts = await Promise.all(accountPromises);

    return objectSpread({}, jsonEncrypt(stringToU8a(JSON.stringify(accounts)), ['batch-pkcs8'], password), {
      accounts: accounts.map((account) => ({
        address: account.address,
        meta: account.meta
      }))
    });
  }

  public createFromJson (json: KeyringPair$Json, meta: KeyringPair$Meta = {}): KeyringPair {
    return this.keyring.createFromJson(
      objectSpread({}, json, {
        meta: objectSpread({}, json.meta, meta)
      })
    );
  }

  public createFromUri (suri: string, meta: KeyringPair$Meta = {}, type?: KeypairType): KeyringPair {
    return this.keyring.createFromUri(suri, meta, type);
  }

  public async encryptAccount (pair: KeyringPair, password: string): Promise<void> {
    const json = pair.toJson(password);

    json.meta.whenEdited = Date.now();

    this.keyring.addFromJson(json);
    await this.accounts.add(this._forageStore, pair.address, json, pair.type);
  }

  public async forgetAccount (address: string): Promise<void> {
    this.keyring.removePair(address);
    await this.accounts.remove(this._forageStore, address);
  }

  public async forgetAddress (address: string): Promise<void> {
    await this.addresses.remove(this._forageStore, address);
  }

  public async forgetContract (address: string): Promise<void> {
    await this.contracts.remove(this._forageStore, address);
  }

  public getAccount (address: string | Uint8Array): KeyringAddress | undefined {
    return this.getAddress(address, 'account');
  }

  public getAccounts (): KeyringAddress[] {
    const available = this.accounts.subject.getValue();

    return Object
      .keys(available)
      .map((address): KeyringAddress => this.getAddress(address, 'account') as KeyringAddress)
      .filter((account) => env.isDevelopment() || account.meta.isTesting !== true);
  }

  public getAddress (_address: string | Uint8Array, type: KeyringItemType | null = null): KeyringAddress | undefined {
    const address = isString(_address)
      ? _address
      : this.encodeAddress(_address);
    const publicKey = this.decodeAddress(address);
    const stores = type
      ? [this.#stores[type]]
      : Object.values(this.#stores);

    const info = stores.reduce<SingleAddress | undefined>((lastInfo, store): SingleAddress | undefined =>
      (store().subject.getValue()[address] || lastInfo), undefined);

    return info && {
      address,
      meta: info.json.meta,
      publicKey
    };
  }

  public getAddresses (): KeyringAddress[] {
    const available = this.addresses.subject.getValue();

    return Object
      .keys(available)
      .map((address): KeyringAddress => this.getAddress(address) as KeyringAddress);
  }

  public getContract (address: string | Uint8Array): KeyringAddress | undefined {
    return this.getAddress(address, 'contract');
  }

  public getContracts (): KeyringAddress[] {
    const available = this.contracts.subject.getValue();

    return Object
      .entries(available)
      .filter(([, { json: { meta: { contract } } }]): boolean =>
        !!contract && contract.genesisHash === this.genesisHash
      )
      .map(([address]) => this.getContract(address) as KeyringAddress);
  }

  private async rewriteKey (json: KeyringJson, key: string, hexAddr: string, creator: (addr: string) => string): Promise<void> {
    if (hexAddr.substring(0, 2) === '0x') {
      return;
    }

    await this._forageStore.remove(key);
    await this._forageStore.set(creator(hexAddr), json);
  }

  private async loadAccount (json: KeyringJson, key: string): Promise<void> {
    if (!json.meta.isTesting && (json as KeyringPair$Json).encoded) {
      const pair = this.keyring.addFromJson(json as KeyringPair$Json, true);
      await this.accounts.add(this._forageStore, pair.address, json, pair.type);
    }

    const [, hexAddr] = key.split(':');

    await this.rewriteKey(json, key, hexAddr.trim(), accountKey);
  }

  private async loadAddress (json: KeyringJson, key: string): Promise<void> {
    const { isRecent, whenCreated = 0 } = json.meta;

    if (isRecent && (Date.now() - whenCreated) > RECENT_EXPIRY) {
      await this._forageStore.remove(key);
      return;
    }

    // We assume anything hex that is not 32bytes (64 + 2 bytes hex) is an Ethereum-like address
    // (this caters for both H160 addresses as well as full or compressed publicKeys) - in the case
    // of both ecdsa and ethereum, we keep it as-is
    const address = isHex(json.address) && json.address.length !== 66
      ? json.address
      : this.encodeAddress(
        isHex(json.address)
          ? hexToU8a(json.address)
          // FIXME Just for the transition period (ignoreChecksum)
          : this.decodeAddress(json.address, true)
      );
    const [, hexAddr] = key.split(':');

    await this.addresses.add(this._forageStore, address, json);
    await this.rewriteKey(json, key, hexAddr, addressKey);
  }

  private async loadContract (json: KeyringJson, key: string): Promise<void> {
    const address = this.encodeAddress(
      this.decodeAddress(json.address)
    );
    const [, hexAddr] = key.split(':');

    // move genesisHash to top-level (TODO Remove from contracts section?)
    json.meta.genesisHash = json.meta.genesisHash || (json.meta.contract && json.meta.contract.genesisHash);

    await this.contracts.add(this._forageStore, address, json);
    await this.rewriteKey(json, key, hexAddr, contractKey);
  }

  private async loadInjected (address: string, meta: KeyringJson$Meta, type?: KeypairType): Promise<void> {
    const json = {
      address,
      meta: objectSpread<KeyringJson$Meta>({}, meta, { isInjected: true })
    };
    const pair = this.keyring.addFromAddress(address, json.meta, null, type);

    await this.accounts.add(this._forageStore, pair.address, json, pair.type);
  }

  private allowGenesis (json?: KeyringJson | { meta: KeyringJson$Meta } | null): boolean {
    if (json && json.meta && this.genesisHash) {
      const hashes: (string | null | undefined)[] = Object.values(chains).find((hashes): boolean =>
        hashes.includes(this.genesisHash || '')
      ) || [this.genesisHash];

      if (json.meta.genesisHash) {
        return hashes.includes(json.meta.genesisHash) || this.genesisHashes.includes(json.meta.genesisHash);
      } else if (json.meta.contract) {
        return hashes.includes(json.meta.contract.genesisHash);
      }
    }

    return true;
  }

  public async loadAll (options: KeyringOptions, injected: { address: string; meta: KeyringJson$Meta, type?: KeypairType }[] = []): Promise<void> {
    await super.initKeyring(options);

    this._forageStore.all(async (key: string, json: KeyringJson): Promise<void> => {
      if (!isFunction(options.filter) || options.filter(json)) {
        try {
          if (this.allowGenesis(json)) {
            if (accountRegex.test(key)) {
              await this.loadAccount(json, key);
            } else if (addressRegex.test(key)) {
              await this.loadAddress(json, key);
            } else if (contractRegex.test(key)) {
              await this.loadContract(json, key);
            }
          }
        } catch {
          console.warn(`Keyring: Unable to load ${key}:${stringify(json)}`);
        }
      }
    });

    injected.forEach(async (account): Promise<void> => {
      if (this.allowGenesis(account)) {
        try {
          await this.loadInjected(account.address, account.meta, account.type);
        } catch {
          console.warn(`Keyring: Unable to inject ${stringify(account)}`);
        }
      }
    });

    this.keyringOption.init(this);
  }

  public restoreAccount (json: KeyringPair$Json, password: string): KeyringPair {
    const cryptoType = Array.isArray(json.encoding.content) ? json.encoding.content[1] : 'ed25519';
    const encType = Array.isArray(json.encoding.type) ? json.encoding.type : [json.encoding.type];
    const pair = createPair(
      { toSS58: this.encodeAddress, type: cryptoType as KeypairType },
      { publicKey: this.decodeAddress(json.address, true) },
      json.meta,
      isHex(json.encoded) ? hexToU8a(json.encoded) : base64Decode(json.encoded),
      encType
    );

    // unlock, save account and then lock (locking cleans secretKey, so needs to be last)
    pair.decodePkcs8(password);
    this.addPair(pair, password);
    pair.lock();

    return pair;
  }

  public restoreAccounts (json: EncryptedJson, password: string): void {
    const accounts: KeyringJson[] = JSON.parse(u8aToString(jsonDecrypt(json, password))) as KeyringJson[];

    accounts.forEach(async (account) => {
      await this.loadAccount(account, accountKey(account.address));
    });
  }

  public async saveAccount (pair: KeyringPair, password?: string): Promise<KeyringPair$Json> {
    this.addTimestamp(pair);

    const json = pair.toJson(password);

    this.keyring.addFromJson(json);
    await this.accounts.add(this._forageStore, pair.address, json, pair.type);

    return json;
  }

  public async saveAccountMeta (pair: KeyringPair, meta: KeyringPair$Meta): Promise<void> {
    const address = pair.address;

    const json: KeyringJson = await this._forageStore.get(accountKey(address));

    pair.setMeta(meta);
    json.meta = pair.meta;

    await this.accounts.add(this._forageStore, address, json, pair.type);
  }

  public async saveAddress (address: string, meta: KeyringPair$Meta, type: KeyringAddressType = 'address'): Promise<KeyringPair$Json> {
    const available = this.addresses.subject.getValue();

    const json = (available[address] && available[address].json) || {
      address,
      meta: {
        isRecent: undefined,
        whenCreated: Date.now()
      }
    };

    Object.keys(meta).forEach((key): void => {
      json.meta[key] = meta[key];
    });

    delete json.meta.isRecent;

    await this.#stores[type]().add(this._forageStore, address, json);

    return json as KeyringPair$Json;
  }

  public async saveContract (address: string, meta: KeyringPair$Meta): Promise<KeyringPair$Json> {
    return await this.saveAddress(address, meta, 'contract');
  }

  public async saveRecent (address: string): Promise<SingleAddress> {
    const available = this.addresses.subject.getValue();

    if (!available[address]) {
      await this.addresses.add(this._forageStore, address, {
        address,
        meta: {
          genesisHash: this.genesisHash,
          isRecent: true,
          whenCreated: Date.now()
        }
      });
    }

    return this.addresses.subject.getValue()[address];
  }
}
