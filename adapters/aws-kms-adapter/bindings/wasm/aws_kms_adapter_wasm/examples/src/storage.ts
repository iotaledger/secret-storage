// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { helloTs } from "@iota/aws_kms_adapter_wasm/node";
import { AwsKmsStorage } from "@iota/aws_kms_adapter_wasm/node/aws_kms_adapter_wasm";

const ACCESS_KEY = process.env.ACCESS_KEY || "foo";
const SECRET_ACCESS_KEY = process.env.SECRET_ACCESS_KEY || "bar";

export async function testStorage() {
    console.log(helloTs());

    const storage = await AwsKmsStorage.create("eu-west-1", ACCESS_KEY, SECRET_ACCESS_KEY);

    const pk = await storage.public_key("7a1b6dfb-df9c-4a6b-b3c4-29c028c82817");
    console.dir(pk);
}

