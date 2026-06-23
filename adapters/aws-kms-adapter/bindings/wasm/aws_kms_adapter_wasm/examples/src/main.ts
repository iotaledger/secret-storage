// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { testStorage } from "./0_basic/storage";
import { useNewKeys } from "./1_integration/0_use_new_keys";
import { useExistingKey } from "./1_integration/1_use_existing_key";
import { scheduleKeyDeletion } from "./1_integration/2_schedule_key_deletion";

export async function main(example?: string) {
    const argument = example ?? process.argv?.[2]?.toLowerCase();
    if (!argument) {
        throw "Please specify an example name, e.g. 'storage'";
    }

    switch (argument) {
        case "storage":
            return await testStorage();
        case "0_use_new_keys":
            return await useNewKeys();
        case "1_use_existing_key":
            return await useExistingKey();
        case "2_schedule_key_deletion":
            return await scheduleKeyDeletion();
        default:
            throw "Unknown example name: '" + argument + "'";
    }
}

main()
    .catch((error) => {
        console.log("Example error:", error);
    });
