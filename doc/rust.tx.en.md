#### IOTA Transfer Example with Rust and MoveVM

This example illustrates how to create a simple IOTA coin transfer transaction using IOTA's Rust SDK (based on MoveVM). We'll follow all key steps: prepare the transaction object, serialize it in BCS format for external signing, inject the external signature (for example signed via AWS KMS) and send the transaction on-chain. IOTA indeed adopts Binary Canonical Serialization (BCS) format to serialize transaction data (TransactionData), and the signature must be provided separately as concatenation of flag || signature || publicKey. Below we present the complete Rust code, with explanations for each phase.

#### Transaction Object Preparation

First, we initialize an IOTA client and prepare the transaction data. We'll create a transfer of 1 IOTA from a sender address to a recipient address using MoveVM APIs. It's necessary to select an IOTA coin owned by the sender to use both as input (value to transfer) and as gas coin to pay execution fees. In the following example, we get the sender's first available coin and use it for both purposes. We then build a Programmable Transaction Block (PTB) with a pay_iota command towards the recipient address, and define the gas budget (e.g., 5_000_000) and current network gas price (client APIs provide the current reference). Finally we compose the complete TransactionData of the programmable transaction, including sender, gas coin reference, PTB and gas parameters:

```rust
use iota_sdk::IotaClientBuilder;
use iota_types::{
    base_types::IotaAddress,
    programmable_transaction_builder::ProgrammableTransactionBuilder,
    transaction::TransactionData,
};
use shared_crypto::intent::{Intent, IntentMessage};
use blake2::{Blake2b, Digest};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. Connect to an IOTA node (e.g., testnet)
    let iota_client = IotaClientBuilder::default().build_testnet().await?;
    
    // 2. Set sender and recipient (in practice get address from own keypair)
    // **Note:** Here for example we generate deterministic keypairs for demo; in real case use secure keys.
    use rand::{SeedableRng, rngs::StdRng};
    use iota_sdk::types::cryptography::key_pairs::{Ed25519KeyPair, IotaKeyPair};
    let sender_kp = IotaKeyPair::Ed25519(Ed25519KeyPair::generate(&mut StdRng::from_seed([0; 32])));
    let sender_address = IotaAddress::from(&sender_kp.public());
    // (Example recipient - could be another user)
    let recipient_kp = IotaKeyPair::Ed25519(Ed25519KeyPair::generate(&mut StdRng::from_seed([1; 32])));
    let recipient_address = IotaAddress::from(&recipient_kp.public());
    
    // 3. Get a gas coin owned by the sender (here we take the first available)
    let coins = iota_client.read_api().get_coins(&sender_address, None, None).await?;
    let gas_coin = coins.first().expect("No coin available for sender");
    let gas_object_ref = gas_coin.object_ref();  // contains (ObjectID, version, digest)
    
    // 4. Build programmable transaction (PTB) that transfers 1 IOTA to recipient
    let mut builder = ProgrammableTransactionBuilder::new();
    builder.pay_iota(vec![recipient_address.clone()], vec![1])?;  // send 1 IOTA to recipient
    let ptb = builder.finish();
    
    // 5. Set gas parameters
    let gas_budget = 5_000_000;
    let gas_price = iota_client.read_api().get_reference_gas_price().await?;
    
    // 6. Create TransactionData object of the transaction (sender, gas coin, PTB, gas budget, gas price)
    let tx_data = TransactionData::new_programmable(
        sender_address,
        vec![gas_object_ref],  // coin used as input and for gas
        ptb,
        gas_budget,
        gas_price,
    );
```

In the above code we built a complete TransactionData for the transfer. The builder's pay_iota function adds an IOTA payment operation towards the specified address with the indicated amount. We passed the input coin (here unique, also used for gas) and gas parameters to TransactionData creation.

#### Serialization for External Signing (BCS format)

Once the transaction object is prepared, we must obtain the BCS serialized bytes to be signed externally (for example via AWS KMS). IOTA indeed requires signing the Blake2b256 hash of an intent message composed of a 3-byte prefix (specific intent for IOTA transactions) concatenated to BCS bytes of TransactionData. We use the SDK to generate such signable payload:

```rust
    // 7. Prepare intent message and serialize it to BCS bytes
    // Intent message with IOTA transaction intent
    let intent_msg = IntentMessage::new(Intent::iota_transaction(), tx_data);
    let bcs_bytes = bcs::to_bytes(&intent_msg)?;  // serialized bytes (BCS) of transaction with intent
    
    // 8. Calculate digest (32 bytes) Blake2b of intent message BCS, to be signed externally
    type Blake2b256 = Blake2b<typenum::U32>;
    let digest = Blake2b256::digest(&bcs_bytes);
    
    // (At this point 'digest' contains the message to sign with sender's private key)
```

In step 7 we create an IntentMessage using Intent::iota_transaction() (identifier for IOTA L1 transactions) and our tx_data, then obtain BCS bytes to sign. As indicated in documentation, the BCS serialized transaction represents TransactionData, while signature will be provided separately later. In step 8 we calculate Blake2b-256 hash of these serialized bytes (which include intent) – this is the value to be signed externally (AWS KMS in this case). Indeed, IOTA requires committing signature on Blake2b hash of intent message before digital signing.

At this point, outside Rust code, you should use AWS KMS (or another HSM) to sign the calculated digest. For example, using a compatible key (Ed25519 or ECDSA) kept in KMS, you'd make a signing call passing the digest value to sign. KMS will return the signature (64 bytes for Ed25519 or ECDSA, not in DER format but as concatenation [r, s] if ECDSA). Make sure to use correct algorithm (e.g., SHA-256 internally for ECDSA, as required above). This step happens externally and isn't shown in code (varies depending on AWS SDK), but expected result is binary signature and possibly recovery of used public key.

#### External Signature Injection

After obtaining external signature, we can insert it in the transaction. IOTA SDK represents signatures in generic format that also includes scheme (flag) and public key. For single user signature, we use GenericSignature::Signature passing user signature. Expected serialized signature structure is flag || sig || pk as mentioned above, where flag (1 byte) identifies scheme (0x00 for Ed25519, 0x01 for ECDSA secp256k1, etc.). If we have signature in raw bytes format, we'll also need to include flag and sender's public key. However, SDK offers types that simplify this step: for example we can use keypair's .sign() method (as done here for demo) which directly produces a signature object including everything. In practice, to use KMS signature, we'll manually build an IOTA signature object with its components.

In following code, we simulate external signing using local keypair (as if it were KMS) and then create signed transaction:

```rust
    // 9. [Simulation] Sign digest with sender's key (in practice, here we use local key instead of KMS)
    use iota_sdk::types::cryptography::traits::Signer;
    let iota_signature = sender_kp.sign(&digest);
    // (In real scenario, 'iota_signature' should be built from bytes returned by AWS KMS 
    // including scheme flag and pubkey. E.g.: Ed25519 -> flag 0x00, signature 64 bytes, pubkey 32 bytes.)
    
    // 10. Insert user signature in transaction and build final structure to send
    use iota_sdk::types::transaction::SignedTransactionData;
    use iota_sdk::types::transaction::signature::GenericSignature;
    use iota_sdk::types::transaction::Transaction;
    
    // Create GenericSignature from single signer
    let user_sig = GenericSignature::Signature(iota_signature);
    // Combine transaction data (intent_msg.value contains original TransactionData) with signature
    let signed_tx = Transaction::from_generic_sig_data(
        intent_msg.value,               // original TransactionData without signature
        Intent::iota_transaction(),     // same intent used before
        vec![user_sig],                 // signature list (here only user's)
    );
```

In point 9 we obtained iota_signature via .sign(&digest) function of our Ed25519 keypair (internally adds flag and other details). In real case, you should manually build signature structure: for example, for Ed25519, concatenate 0x00 || [64-byte signature] || [32-byte public_key]. IOTA documentation clearly specifies these expected formats and lengths for each scheme. In code, signature is encapsulated in GenericSignature::Signature. Then we create complete Transaction object using Transaction::from_generic_sig_data(...), passing original TransactionData (from intent message) and signature list to apply. This builds signed transaction ready for transmission.

#### On-chain Transaction Submission

Finally, we send signed transaction to IOTA network. Rust SDK exposes quorum_driver_api().execute_transaction_block(...) API to execute a transaction block. This call forwards transaction bytes and signatures to full node, waiting for transaction to be finalized on-chain. We can then print or verify outcome (for example getting confirmed transaction digest):

```rust
    // 11. Send signed transaction to IOTA network
    let response = iota_client
        .quorum_driver_api()
        .execute_transaction_block(
            signed_tx,
            iota_sdk::types::api::core::IOTATransactionResponseOptions::default(),
            None,  // No request timeout override
        )
        .await?;
    
    println!("Transaction sent with digest: {:?}", response.transaction_digest);
    Ok(())
}
```

If all steps were executed correctly, the transfer transaction will be finalized on-chain, transferring 1 IOTA from sender to recipient (on appropriate network we're operating on, for example testnet). Response will contain identifying digest of confirmed transaction.

Summary: We showed complete cycle in Rust: payment TransactionData construction, BCS serialization for external signing, signed transaction object creation and on-chain submit via IOTA SDK. These steps exactly follow workflow recommended by official documentation, where in CLI you'd use --serialize-unsigned-transaction to get bytes, then offline signature, and finally execute-signed-tx to send transaction with signature. Rust SDK encapsulates these operations in calls shown.

Sources: We referenced official IOTA documentation for MoveVM and provided examples (GitHub and docs) to ensure code is updated and correct. For example, IOTA specifies transaction data must be BCS serialized and signed out-of-band, then sent together with signature to node. Reported code uses latest IOTA SDK and follows these official guidelines, showing simple end-to-end IOTA coin transfer transaction.

#### References
Signing and Submitting Transactions (IOTA)
https://docs.iota.org/developer/iota-101/transactions/sign-and-send-transactions

Intent Signing (IOTA)
https://docs.iota.org/developer/cryptography/transaction-auth/intent-signing

Keys and Addresses
https://docs.iota.org/developer/cryptography/transaction-auth/keys-addresses

IOTA Rust SDK – Reference (docs)
https://iotaledger.github.io/iota/iota_sdk/index.html

IOTA Rust SDK – Repository
https://github.com/iotaledger/iota-sdk

Simple Token Transfer Tutorial (MoveVM)
https://docs.iota.org/developer/getting-started/simple-token-transfer

Signing and Submitting Transactions
https://docs.iota.org/developer/iota-101/transactions/sign-and-send-transactions#:~:text=After%20constructing%20a%20transaction%E2%80%94typically,match%20the%20sender's%20blockchain%20address.