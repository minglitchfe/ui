// Copyright 2017-2023 @polkadot/ui-keyring authors & contributors
// SPDX-License-Identifier: Apache-2.0

import type { BrowserStorageArea, KeyringJson, StorageOptions } from '../../types.js';

import LocalForage from './local-forage.js';

class ForageStorage {
  namespace: string;

  private storage: BrowserStorageArea;

  constructor (namespace: string, options: StorageOptions) {
    if (!options.storage) {
      options.storage = new LocalForage(namespace);
    }

    this.namespace = namespace;
    this.storage = options.storage;
  }

  async all (fn: (key: string, value: KeyringJson) => void) {
    const allValues = await this.storage.getWholeStorage();
    const keyringValues = allValues?.keyring

    if (keyringValues) {
      Object.keys(keyringValues).forEach((key) => {
        fn && fn(key, keyringValues[key])
      });
    }
  }

  async get (key: string) {
    const vals = await this.storage.get(this.namespace);

    if (vals[this.namespace] && vals[this.namespace][key]) {
      return vals[this.namespace][key];
    }

    return null;
  }

  async set (key: string, val: Record<string, any>) {
    let vals = await this.storage.get(this.namespace);
    vals = vals[this.namespace] ? vals[this.namespace] : {};
    vals[key] = val;

    await this.storage.set({
      [this.namespace]: vals
    });
  }

  async remove (key: string) {
    let vals = await this.storage.get(this.namespace);

    vals = vals[this.namespace] ? vals[this.namespace] : {};

    console.log('remove', {vals, key})

    delete vals[key];

    console.log('afterRemove', {vals, key})

    return await this.storage.set({
      [this.namespace]: vals
    })
  }

  async clear () {
    await this.storage.remove(this.namespace);
  }
}

export default ForageStorage;
