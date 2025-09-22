use near_sdk::{
    AccountId, CurveType, NearToken, PanicOnDefault, Promise, PublicKey,
    env::{self, sha256},
    json_types::{Base64VecU8, U64},
    near, require,
    store::LookupMap,
};

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct SlimeDrop {
    pub accounts: LookupMap<PublicKey, DropContents>,
}

#[near(serializers=[borsh, json])]
#[derive(Clone)]
pub struct DropContents {
    pub near: NearToken,
}

impl Default for DropContents {
    fn default() -> Self {
        Self {
            near: NearToken::from_near(0),
        }
    }
}

#[near]
impl SlimeDrop {
    /// Initializes the contract with an empty map for the accounts
    #[init]
    pub fn new() -> Self {
        Self {
            #[allow(deprecated)]
            accounts: LookupMap::new(b"a"),
        }
    }

    /// Allows given public key to claim sent balance.
    #[payable]
    pub fn add_near(&mut self, public_key: PublicKey) {
        assert!(
            env::attached_deposit() > NearToken::from_near(0),
            "Attached deposit must be at least 1 yoctoNEAR"
        );
        let drop = self.accounts.get(&public_key).cloned().unwrap_or_default();
        let new_value = DropContents {
            near: drop.near.saturating_add(env::attached_deposit()),
        };
        self.accounts.insert(public_key, new_value);
    }

    /// Claim tokens for specific account that are attached to the public key this tx is signed with.
    pub fn claim(
        &mut self,
        account_id: Option<AccountId>,
        signature: Base64VecU8,
        public_key: PublicKey,
        nonce: U64,
        callback_url: Option<String>,
    ) -> Promise {
        let current_timestamp_ms = env::block_timestamp_ms();
        const NONCE_MAX_AGE_MS: u64 = 60 * 5 * 1000;
        require!(
            current_timestamp_ms <= nonce.0.saturating_add(NONCE_MAX_AGE_MS),
            "Nonce has expired"
        );
        require!(current_timestamp_ms >= nonce.0, "Nonce is in the future");

        let nonce = nonce.0.to_be_bytes();
        let Ok(nonce) = [vec![0; 32 - nonce.len()], nonce.to_vec()]
            .concat()
            .try_into()
        else {
            env::panic_str("unreachable");
        };

        #[near(serializers=[borsh])]
        struct Nep413Message {
            message: String,
            nonce: [u8; 32],
            recipient: String,
            callback_url: Option<String>,
        }

        let message = Nep413Message {
            message: if let Some(account_id) = account_id.as_ref() {
                format!("I want to claim this Slimedrop and send it to {account_id}")
            } else {
                "I want to claim this Slimedrop".to_string()
            },
            nonce,
            recipient: env::current_account_id().to_string(),
            callback_url,
        };
        const NEP413_413_SIGN_MESSAGE_PREFIX: u32 = (1u32 << 31u32) + 413u32;
        let mut bytes = NEP413_413_SIGN_MESSAGE_PREFIX.to_le_bytes().to_vec();
        if let Err(e) = near_sdk::borsh::to_writer(&mut bytes, &message) {
            env::panic_str(&format!("nep413 message borsh serialization failed: {e}"));
        };
        let hash = sha256(&bytes);
        let verified = match public_key.curve_type() {
            CurveType::ED25519 => env::ed25519_verify(
                &signature
                    .0
                    .try_into()
                    .unwrap_or_else(|_| env::panic_str("Invalid ED25519 signature size")),
                &hash,
                &public_key.as_bytes()[1..]
                    .try_into()
                    .unwrap_or_else(|_| env::panic_str("Invalid ED25519 public key size")),
            ),
            CurveType::SECP256K1 => {
                env::ecrecover(
                    &hash,
                    &signature.0[..signature.0.len() - 1],
                    *signature
                        .0
                        .last()
                        .unwrap_or_else(|| env::panic_str("Invalid SECP256K1 signature size")),
                    false,
                ) == Some(
                    public_key.as_bytes()[1..]
                        .try_into()
                        .unwrap_or_else(|_| env::panic_str("Invalid SECP256K1 public key size")),
                )
            }
        };
        require!(verified, "Failed to verify signature");

        let receiver_id = account_id.unwrap_or_else(env::signer_account_id);
        let drop = self
            .accounts
            .remove(&public_key)
            .expect("Unexpected public key");
        Promise::new(receiver_id).transfer(drop.near)
    }

    /// Returns the balance associated with given key.
    pub fn get_key_balance(&self, key: PublicKey) -> DropContents {
        self.accounts.get(&key).cloned().expect("Key is missing")
    }
}
