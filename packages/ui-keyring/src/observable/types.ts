// Copyright 2017-2023 @polkadot/ui-keyring authors & contributors
// SPDX-License-Identifier: Apache-2.0

import type { BehaviorSubject } from 'rxjs';
import type { KeypairType } from '@polkadot/util-crypto/types';
import type { KeyringSectionOption } from '../options/types.js';
import type { ForageStorage } from '../stores/index.js';
import type { KeyringJson } from '../types.js';

export interface SingleAddress {
  json: KeyringJson;
  option: KeyringSectionOption;
  type?: KeypairType | undefined;
}

export interface SubjectInfo {
  [index: string]: SingleAddress;
}

export interface AddressSubject {
  add: (store: ForageStorage, address: string, json: KeyringJson, type?: KeypairType) => Promise<SingleAddress>;
  remove: (store: ForageStorage, address: string) => Promise<void>;
  subject: BehaviorSubject<SubjectInfo>;
}
