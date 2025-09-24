use near_sdk::{
    AccountId, CurveType, NearToken, PanicOnDefault, Promise, PublicKey,
    env::{self, sha256},
    json_types::{Base64VecU8, U64},
    near,
    store::{IterableMap, LookupMap, Vector},
};

macro_rules! require {
    (let $p: pat = $e:expr, $message:expr $(,)?) => {
        let $p = $e else {
            $crate::env::panic_str(&$message)
        };
    };
    ($cond:expr, $message:expr $(,)?) => {
        if cfg!(debug_assertions) {
            assert!($cond, "{}", &$message)
        } else if !$cond {
            $crate::env::panic_str(&$message)
        }
    };
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct SlimedropContract {
    /// Map of all drops
    pub drops: LookupMap<PublicKey, Slimedrop>,
    /// Map of all drops an account has created
    pub drops_owned_by_account: IterableMap<AccountId, Vector<PublicKey>>,
}

#[near(serializers=[borsh])]
pub struct Slimedrop {
    pub contents: DropContents,
    pub created_at_ms: U64,
    pub created_by: AccountId,
    pub claims: Vector<Claim>,
    pub status: DropStatus,
}

#[near(serializers=[borsh, json])]
#[derive(Clone, Copy, PartialEq)]
pub enum DropStatus {
    Active,
    Cancelled,
}

#[near(serializers=[json])]
pub struct SlimedropView {
    pub contents: DropContents,
    pub created_at_ms: U64,
    pub created_by: AccountId,
    pub claims: Vec<Claim>,
    pub status: DropStatus,
}

impl From<&Slimedrop> for SlimedropView {
    fn from(drop: &Slimedrop) -> Self {
        Self {
            contents: drop.contents.clone(),
            created_at_ms: drop.created_at_ms,
            created_by: drop.created_by.clone(),
            claims: drop.claims.into_iter().cloned().collect(),
            status: drop.status,
        }
    }
}

#[near(serializers=[borsh, json])]
#[derive(Clone)]
pub struct Claim {
    pub account_id: AccountId,
    pub claimed_at_ms: U64,
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
impl SlimedropContract {
    /// Initializes the contract with an empty map for the accounts
    #[init]
    pub fn new() -> Self {
        Self {
            drops: LookupMap::new(b"a"),
            drops_owned_by_account: IterableMap::new(b"b"),
        }
    }

    /// Allows given public key to claim sent balance. If the drop already
    /// exists, it will add to the existing balance.
    #[payable]
    pub fn add_near(&mut self, public_key: PublicKey) {
        assert!(
            env::attached_deposit() > NearToken::from_near(0),
            "Attached deposit must be at least 1 yoctoNEAR"
        );
        if let Some(drop) = self.drops.get_mut(&public_key) {
            require!(
                drop.created_by == env::predecessor_account_id(),
                "You can only add NEAR to drops you created"
            );
            require!(drop.claims.is_empty(), "Drop already claimed");
            require!(
                drop.status == DropStatus::Active,
                "Cannot add to cancelled drop"
            );
            let contents = DropContents {
                near: drop.contents.near.saturating_add(env::attached_deposit()),
            };
            drop.contents = contents;
        } else {
            let drop = Slimedrop {
                contents: DropContents {
                    near: env::attached_deposit(),
                },
                created_at_ms: U64(env::block_timestamp_ms()),
                created_by: env::predecessor_account_id(),
                claims: Vector::new([b"d", public_key.as_bytes()].concat()),
                status: DropStatus::Active,
            };
            self.drops.insert(public_key.clone(), drop);
            self.drops_owned_by_account
                .entry(env::predecessor_account_id())
                .or_insert_with(|| {
                    Vector::new(format!("c{}", env::predecessor_account_id()).as_bytes())
                })
                .push(public_key);
        }
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
        require!(let Ok(nonce) = [vec![0; 32 - nonce.len()], nonce.to_vec()]
            .concat()
            .try_into(),
            "Invalid nonce",
        );

        #[near(serializers=[borsh])]
        struct Nep413Message {
            message: String,
            nonce: [u8; 32],
            recipient: String,
            callback_url: Option<String>,
        }

        let receiver_id = account_id.unwrap_or_else(env::predecessor_account_id);
        let message = Nep413Message {
            message: format!("I want to claim this Slimedrop and send it to {receiver_id}"),
            nonce,
            recipient: env::current_account_id().to_string(),
            callback_url,
        };
        const NEP413_413_SIGN_MESSAGE_PREFIX: u32 = (1u32 << 31u32) + 413u32;
        let mut bytes = NEP413_413_SIGN_MESSAGE_PREFIX.to_le_bytes().to_vec();
        require!(
            near_sdk::borsh::to_writer(&mut bytes, &message).is_ok(),
            "nep413 message borsh serialization failed",
        );
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

        require!(
            let Some(drop) = self.drops.get_mut(&public_key),
            "Unexpected public key",
        );
        require!(drop.claims.is_empty(), "Drop already claimed");
        require!(drop.status == DropStatus::Active, "Drop is not active");
        drop.claims.push(Claim {
            account_id: receiver_id.clone(),
            claimed_at_ms: U64(current_timestamp_ms),
        });
        send_drop(drop, receiver_id)
    }

    /// Returns the drop info associated with given key.
    pub fn get_key_info(&self, key: PublicKey) -> Option<SlimedropView> {
        self.drops.get(&key).map(|drop| drop.into())
    }

    /// Returns the drops an account has created.
    pub fn get_account_drops(
        &self,
        account_id: AccountId,
        skip: Option<U64>,
        limit: Option<U64>,
    ) -> Vec<(PublicKey, SlimedropView)> {
        let Some(drops_owned_by_account) = self.drops_owned_by_account.get(&account_id) else {
            return vec![];
        };
        let skip = skip.unwrap_or(U64(0));
        let limit = limit.unwrap_or(U64(100));
        drops_owned_by_account
            .iter()
            .skip(skip.0 as usize)
            .take(limit.0 as usize)
            .map(|key| {
                (
                    key.clone(),
                    self.drops
                        .get(key)
                        .unwrap_or_else(|| env::panic_str("Key is missing"))
                        .into(),
                )
            })
            .collect()
    }

    pub fn cancel_drop(&mut self, public_key: PublicKey) -> Promise {
        require!(let Some(drop) = self.drops.get_mut(&public_key), "Key is missing");
        require!(
            drop.created_by == env::predecessor_account_id(),
            "You can only cancel drops you created"
        );
        require!(drop.status == DropStatus::Active, "Drop already cancelled");
        require!(drop.claims.is_empty(), "Drop already claimed");
        drop.status = DropStatus::Cancelled;
        send_drop(drop, drop.created_by.clone())
    }
}

fn send_drop(drop: &Slimedrop, receiver_id: AccountId) -> Promise {
    Promise::new(receiver_id).transfer(drop.contents.near)
}
