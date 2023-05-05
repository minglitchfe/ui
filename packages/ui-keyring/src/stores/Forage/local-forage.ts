// Copyright 2017-2023 @polkadot/ui-keyring authors & contributors
// SPDX-License-Identifier: Apache-2.0

import type { BrowserStorageArea } from '../../types.js';

import * as LocalForageLib from 'localforage';

class LocalForage implements BrowserStorageArea {
  namespace: string;

  private storage: globalThis.LocalForage;

  constructor (
    namespace: string,
    drivers: Array<string> = [
      LocalForageLib.INDEXEDDB,
      LocalForageLib.LOCALSTORAGE
    ]
  ) {
    this.namespace = namespace;
    this.storage = LocalForageLib.createInstance({
      name: this.namespace,
      driver: drivers,
      storeName: 'glitch_db'
    });
  }

  async set (items: Record<string, any>): Promise<void> {
    const promises: Record<string, any>[] = Object.keys(items).map((key) => this.storage.setItem(key, items[key]));
    await Promise.all(promises)
  }

  async remove (key: string): Promise<void> {
    return await this.storage.removeItem(key);
  }

  async clear (): Promise<void> {
    return await this.storage.clear();
  }

  async get (key: string): Promise<Record<string, any>> {
    const item = await this.storage.getItem(key)

    if (!item) {
      return {}
    }

    return {
      [key]: item
    }
  }

  async getWholeStorage (): Promise<Record<string, any>> {
    const storeOb: Record<string, any> = {};

    return await this.storage
      .iterate((value, key) => {
        storeOb[key] = value;
      })
      .then(() => storeOb);
  }
}

export default LocalForage;
