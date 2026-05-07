// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { greet } from "@iota/multi-signature-scheme-to-iota-wasm/node/multi_signature_scheme_to_iota_wasm";


import { testSigning } from "./signing";

export async function main(example?: string) {
    // Extract example name.
    const argument = example ?? process.argv?.[2]?.toLowerCase();
    if (!argument) {
        throw "Please specify an example name, e.g. 'storage'";
    }

    switch (argument) {
        case "storage":
            await testSigning();
            break;
        case "greet":
            console.log(greet("ts"));
            break;
default:
            throw "Unknown example name: '" + argument + "'";
    }
}

main()
    .catch((error) => {
        console.log("Example error:", error);
    });