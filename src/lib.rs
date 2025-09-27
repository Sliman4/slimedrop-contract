use std::collections::{HashMap, HashSet};

use near_contract_standards::{
    fungible_token::{core::ext_ft_core, receiver::FungibleTokenReceiver},
    non_fungible_token::{
        self,
        core::{NonFungibleTokenReceiver, ext_nft_core},
    },
    storage_management::ext_storage_management,
};
use near_sdk::{
    AccountId, BorshStorageKey, CurveType, Gas, IntoStorageKey, NearToken, PanicOnDefault, Promise,
    PromiseOrValue, PublicKey,
    env::{self, sha256},
    json_types::{Base64VecU8, U64, U128},
    near,
    store::{IterableMap, LookupMap, Vector},
};

use multi_token::MultiTokenReceiver;

use crate::multi_token::ext_mt_core;

const FT_STORAGE_DEPOSIT: NearToken = NearToken::from_millinear(5); // 0.005 NEAR
const NFT_STORAGE_DEPOSIT: NearToken = NearToken::from_millinear(5); // 0.005 NEAR
const MT_STORAGE_DEPOSIT: NearToken = NearToken::from_millinear(5); // 0.005 NEAR
const FLAT_FEE_PER_DROP: NearToken = NearToken::from_millinear(50); // 0.05 NEAR
const MAX_GAS_FOR_CLAIMS: Gas = Gas::from_tgas(200); // leave 100 tgas for the contract itself and near transfer
const GAS_FOR_FT_TRANSFER: Gas = Gas::from_tgas(10);
const GAS_FOR_NFT_TRANSFER: Gas = Gas::from_tgas(10);
const GAS_FOR_MT_TRANSFER: Gas = Gas::from_tgas(10);
const GAS_FOR_STORAGE_DEPOSIT: Gas = Gas::from_tgas(10);
const GAS_FOR_STORAGE_DEPOSIT_CALLBACK: Gas = Gas::from_tgas(5);

macro_rules! require {
    (let $p: pat = $e:expr, $message:literal $(, $fmt_args:expr)* $(,)?) => {
        let $p = $e else {
            $crate::env::panic_str(&format!($message, $($fmt_args),*))
        };
    };
    ($cond:expr, $message:literal $(, $fmt_args:expr)* $(,)?) => {
        if cfg!(debug_assertions) {
            assert!($cond, $message, $($fmt_args),*)
        } else if !$cond {
            $crate::env::panic_str(&format!($message, $($fmt_args),*))
        }
    };
}

#[near(event_json(standard = "slimedrop"))]
pub enum SlimedropEvent {
    #[event_version("1.0.0")]
    DropCreated {
        public_key: PublicKey,
        contents: DropContents,
        created_by: AccountId,
    },
    #[event_version("1.0.0")]
    DropUpdated {
        public_key: PublicKey,
        contents: DropContents,
    },
    #[event_version("1.0.0")]
    DropClaimed {
        public_key: PublicKey,
        claimed_by: AccountId,
    },
    #[event_version("1.0.0")]
    DropCancelled { public_key: PublicKey },
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct SlimedropContract {
    /// Map of all drops
    pub drops: LookupMap<PublicKey, Slimedrop>,
    /// Map of all drops an account has created
    pub drops_owned_by_account: IterableMap<AccountId, Vector<PublicKey>>,
    /// Map of all drops an account has claimed
    pub drops_claimed_by_account: IterableMap<AccountId, Vector<PublicKey>>,
    /// Fees available to withdraw
    pub fees_earned: NearToken,
    /// Total fees collected
    pub fees_total: NearToken,
}

#[near(serializers=[borsh])]
pub struct Slimedrop {
    pub contents: DropContents,
    pub created_at_ms: U64,
    pub created_by: AccountId,
    pub claims: IterableMap<AccountId, Claim>,
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
    pub claims: HashMap<AccountId, Claim>,
    pub status: DropStatus,
}

impl From<&Slimedrop> for SlimedropView {
    fn from(drop: &Slimedrop) -> Self {
        Self {
            contents: drop.contents.clone(),
            created_at_ms: drop.created_at_ms,
            created_by: drop.created_by.clone(),
            claims: drop
                .claims
                .iter()
                .map(|(account_id, claim)| (account_id.clone(), claim.clone()))
                .collect(),
            status: drop.status,
        }
    }
}

#[near(serializers=[borsh, json])]
#[derive(Clone, PartialEq, PartialOrd, Eq, Ord)]
pub struct Claim {
    pub claimed_at_ms: U64,
}

mod multi_token {
    use near_sdk::ext_contract;

    use super::*;

    pub type TokenId = String;

    #[allow(dead_code)]
    pub trait MultiTokenReceiver {
        fn mt_on_transfer(
            &mut self,
            sender_id: AccountId,
            previous_owner_ids: Vec<AccountId>,
            token_ids: Vec<TokenId>,
            amounts: Vec<U128>,
            msg: String,
        ) -> PromiseOrValue<Vec<U128>>;
    }

    #[allow(dead_code)]
    #[ext_contract(ext_mt_core)]
    pub trait MultiTokenCore {
        fn mt_batch_transfer(
            &mut self,
            receiver_id: AccountId,
            token_ids: Vec<TokenId>,
            amounts: Vec<U128>,
            approvals: Option<Vec<Option<(AccountId, String)>>>,
            memo: Option<String>,
        ) -> PromiseOrValue<Vec<U128>>;
    }
}

#[near(serializers=[borsh, json])]
#[derive(Clone)]
pub struct DropContents {
    /// Native NEAR
    pub near: NearToken,
    /// Fungible tokens
    pub nep141: HashMap<AccountId, U128>,
    /// Non-fungible tokens
    pub nep171: HashMap<AccountId, HashSet<non_fungible_token::TokenId>>,
    /// Multi-fungible tokens
    pub nep245: HashMap<AccountId, HashMap<multi_token::TokenId, U128>>,
}

impl Default for DropContents {
    fn default() -> Self {
        Self {
            near: NearToken::from_near(0),
            nep141: HashMap::new(),
            nep171: HashMap::new(),
            nep245: HashMap::new(),
        }
    }
}

#[near(serializers=[borsh])]
#[derive(BorshStorageKey)]
enum DropStorageKey {
    Drops,
    DropsOwnedByAccount,
    DropsOwnedByAccountEntries,
    DropClaims,
    DropsClaimedByAccount,
    DropsClaimedByAccountEntries,
}

fn check_can_add(drop: &Slimedrop) {
    require!(drop.claims.is_empty(), "Drop already claimed");
    require!(
        drop.status == DropStatus::Active,
        "Cannot add to cancelled drop"
    );
    const GAS_FOR_FT_TRANSFER_FULL: Gas = GAS_FOR_FT_TRANSFER
        .saturating_add(GAS_FOR_STORAGE_DEPOSIT)
        .saturating_add(GAS_FOR_STORAGE_DEPOSIT_CALLBACK);
    const GAS_FOR_NFT_TRANSFER_FULL: Gas = GAS_FOR_NFT_TRANSFER
        .saturating_add(GAS_FOR_STORAGE_DEPOSIT)
        .saturating_add(GAS_FOR_STORAGE_DEPOSIT_CALLBACK);
    const GAS_FOR_MT_TRANSFER_FULL: Gas = GAS_FOR_MT_TRANSFER
        .saturating_add(GAS_FOR_STORAGE_DEPOSIT)
        .saturating_add(GAS_FOR_STORAGE_DEPOSIT_CALLBACK);
    let gas_for_fts = GAS_FOR_FT_TRANSFER_FULL.saturating_mul(drop.contents.nep141.len() as u64);
    let gas_for_nfts = GAS_FOR_NFT_TRANSFER_FULL.saturating_mul(drop.contents.nep171.len() as u64);
    let gas_for_mts = GAS_FOR_MT_TRANSFER_FULL.saturating_mul(drop.contents.nep245.len() as u64);
    require!(
        gas_for_fts
            .saturating_add(gas_for_nfts)
            .saturating_add(gas_for_mts)
            <= MAX_GAS_FOR_CLAIMS,
        "Insufficient gas to add to drop"
    );
}

#[near]
impl SlimedropContract {
    /// Initializes the contract with an empty map for the accounts
    #[init]
    pub fn new() -> Self {
        Self {
            drops: LookupMap::new(DropStorageKey::Drops),
            drops_owned_by_account: IterableMap::new(DropStorageKey::DropsOwnedByAccount),
            drops_claimed_by_account: IterableMap::new(DropStorageKey::DropsClaimedByAccount),
            fees_earned: NearToken::from_near(0),
            fees_total: NearToken::from_near(0),
        }
    }

    /// Allows given public key to claim sent balance. If the drop already
    /// exists, it will add to the existing balance.
    #[payable]
    pub fn add_near(&mut self, public_key: PublicKey) {
        if let Some(drop) = self.drops.get_mut(&public_key) {
            require!(
                !env::attached_deposit().is_zero(),
                "Attached deposit must be greater than 0",
            );
            require!(
                drop.created_by == env::predecessor_account_id(),
                "You can only add NEAR to drops you created"
            );
            check_can_add(drop);

            drop.contents.near = drop.contents.near.saturating_add(env::attached_deposit());
            SlimedropEvent::DropUpdated {
                public_key,
                contents: drop.contents.clone(),
            }
            .emit();
        } else {
            require!(
                env::attached_deposit() > FLAT_FEE_PER_DROP,
                "Attached deposit must be greater than {FLAT_FEE_PER_DROP} to create a new drop",
            );
            self.fees_earned = self.fees_earned.saturating_add(FLAT_FEE_PER_DROP);
            self.fees_total = self.fees_total.saturating_add(FLAT_FEE_PER_DROP);
            let drop = Slimedrop {
                contents: DropContents {
                    near: env::attached_deposit()
                        .checked_sub(FLAT_FEE_PER_DROP)
                        .unwrap_or_else(|| env::panic_str("Attached deposit must be greater than {FLAT_FEE_PER_DROP} to create a new drop")),
                    nep141: HashMap::new(),
                    nep171: HashMap::new(),
                    nep245: HashMap::new(),
                },
                created_at_ms: U64(env::block_timestamp_ms()),
                created_by: env::predecessor_account_id(),
                claims: IterableMap::new(
                    [
                        DropStorageKey::DropClaims.into_storage_key(),
                        public_key.as_bytes().to_vec(),
                    ]
                    .concat(),
                ),
                status: DropStatus::Active,
            };
            self.drops.insert(public_key.clone(), drop);
            self.drops_owned_by_account
                .entry(env::predecessor_account_id())
                .or_insert_with(|| {
                    Vector::new(
                        [
                            DropStorageKey::DropsOwnedByAccountEntries.into_storage_key(),
                            env::predecessor_account_id().as_bytes().to_vec(),
                        ]
                        .concat(),
                    )
                })
                .push(public_key.clone());
            SlimedropEvent::DropCreated {
                public_key,
                contents: DropContents {
                    near: env::attached_deposit(),
                    nep141: HashMap::new(),
                    nep171: HashMap::new(),
                    nep245: HashMap::new(),
                },
                created_by: env::predecessor_account_id(),
            }
            .emit();
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
        require!(
            !drop.claims.contains_key(&receiver_id),
            "Drop already claimed by this account"
        );
        require!(drop.status == DropStatus::Active, "Drop is not active");
        drop.claims.insert(
            receiver_id.clone(),
            Claim {
                claimed_at_ms: U64(current_timestamp_ms),
            },
        );
        self.drops_claimed_by_account
            .entry(receiver_id.clone())
            .or_insert_with(|| {
                Vector::new(
                    [
                        DropStorageKey::DropsClaimedByAccountEntries.into_storage_key(),
                        receiver_id.as_bytes().to_vec(),
                    ]
                    .concat(),
                )
            })
            .push(public_key.clone());
        SlimedropEvent::DropClaimed {
            public_key,
            claimed_by: receiver_id.clone(),
        }
        .emit();
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

    /// Cancels a drop and refunds the contents to the creator.
    pub fn cancel_drop(&mut self, public_key: PublicKey) -> Promise {
        require!(let Some(drop) = self.drops.get_mut(&public_key), "Key is missing");
        require!(
            drop.created_by == env::predecessor_account_id(),
            "You can only cancel drops you created"
        );
        require!(drop.status == DropStatus::Active, "Drop already cancelled");
        require!(drop.claims.is_empty(), "Drop already claimed");
        drop.status = DropStatus::Cancelled;
        SlimedropEvent::DropCancelled { public_key }.emit();
        send_drop(drop, drop.created_by.clone())
    }

    /// Returns the drops an account has claimed.
    pub fn get_account_claimed_drops(
        &self,
        account_id: AccountId,
        skip: Option<U64>,
        limit: Option<U64>,
    ) -> Vec<(PublicKey, SlimedropView)> {
        let Some(drops_claimed_by_account) = self.drops_claimed_by_account.get(&account_id) else {
            return vec![];
        };
        let skip = skip.unwrap_or(U64(0));
        let limit = limit.unwrap_or(U64(100));
        drops_claimed_by_account
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

    /// Withdraws fees to the given account.
    #[private]
    pub fn withdraw_fees(&mut self, withdraw_to: AccountId) -> Promise {
        let near_to_withdraw = self.fees_earned;
        require!(!near_to_withdraw.is_zero(), "No fees to withdraw",);
        self.fees_earned = NearToken::from_near(0);
        Promise::new(withdraw_to).transfer(near_to_withdraw)
    }

    /// Claim callback
    #[private]
    pub fn after_claim(&mut self) {
        // do nothing, just need to return a promise because can't return a joint promise
    }

    /// Callback after storage_deposit on FT. We don't care about whether it succeeded or not,
    /// since not all tokens have / require storage deposit.
    #[private]
    pub fn after_ft_storage_deposit(
        &mut self,
        ft_id: AccountId,
        receiver_id: AccountId,
        amount: U128,
    ) -> Promise {
        ext_ft_core::ext(ft_id)
            .with_static_gas(GAS_FOR_FT_TRANSFER)
            .with_attached_deposit(NearToken::from_yoctonear(1))
            .ft_transfer(receiver_id, amount, Some("slimedrop".to_string()))
    }

    /// Callback after storage_deposit on NFT. We don't care about whether it succeeded or not,
    /// since not all tokens have / require storage deposit.
    #[private]
    pub fn after_nft_storage_deposit(
        &mut self,
        nft_id: AccountId,
        token_id: non_fungible_token::TokenId,
        receiver_id: AccountId,
    ) -> Promise {
        ext_nft_core::ext(nft_id)
            .with_static_gas(GAS_FOR_NFT_TRANSFER)
            .with_attached_deposit(NearToken::from_yoctonear(1))
            .nft_transfer(receiver_id, token_id, None, Some("slimedrop".to_string()))
    }

    /// Callback after storage_deposit on MT. We don't care about whether it succeeded or not,
    /// since not all tokens have / require storage deposit.
    #[private]
    pub fn after_mt_storage_deposit(
        &mut self,
        mt_id: AccountId,
        token_ids: Vec<multi_token::TokenId>,
        amounts: Vec<U128>,
        receiver_id: AccountId,
    ) -> Promise {
        ext_mt_core::ext(mt_id)
            .with_static_gas(GAS_FOR_MT_TRANSFER)
            .with_attached_deposit(NearToken::from_yoctonear(1))
            .mt_batch_transfer(
                receiver_id,
                token_ids,
                amounts,
                None,
                Some("slimedrop".to_string()),
            )
    }
}

#[near(serializers=[json])]
pub struct TransferCallMsg {
    public_key: PublicKey,
}

#[near]
impl FungibleTokenReceiver for SlimedropContract {
    fn ft_on_transfer(
        &mut self,
        sender_id: AccountId,
        amount: U128,
        msg: String,
    ) -> PromiseOrValue<U128> {
        require!(
            let Ok(msg) = near_sdk::serde_json::from_str::<TransferCallMsg>(&msg),
            "Invalid message"
        );
        require!(
            let Some(drop) = self.drops.get_mut(&msg.public_key),
            "Key is missing"
        );
        require!(amount.0 > 0, "Amount must be greater than 0");
        require!(
            drop.created_by == sender_id,
            "You can only add FTs to drops you created"
        );
        check_can_add(drop);

        let token_id = env::predecessor_account_id();
        drop.contents
            .nep141
            .entry(token_id)
            .and_modify(|amount| {
                amount.0 = amount.0.saturating_add(amount.0);
            })
            .or_insert(amount);
        drop.contents.near = drop
            .contents
            .near
            .checked_sub(FT_STORAGE_DEPOSIT)
            .unwrap_or_else(|| env::panic_str(&format!("Insufficient NEAR balance of this gift. Needed {FT_STORAGE_DEPOSIT} for storage deposit, got {}", drop.contents.near)));

        SlimedropEvent::DropUpdated {
            public_key: msg.public_key,
            contents: drop.contents.clone(),
        }
        .emit();

        PromiseOrValue::Value(0.into())
    }
}

#[near]
impl NonFungibleTokenReceiver for SlimedropContract {
    fn nft_on_transfer(
        &mut self,
        sender_id: AccountId,
        #[allow(unused)] previous_owner_id: AccountId,
        token_id: non_fungible_token::TokenId,
        msg: String,
    ) -> PromiseOrValue<bool> {
        require!(
            let Ok(msg) = near_sdk::serde_json::from_str::<TransferCallMsg>(&msg),
            "Invalid message"
        );
        require!(
            let Some(drop) = self.drops.get_mut(&msg.public_key),
            "Key is missing"
        );
        require!(
            drop.created_by == sender_id,
            "You can only add NFTs to drops you created"
        );
        check_can_add(drop);

        let nft_contract_id = env::predecessor_account_id();
        // We don't care about previous owner id if sender is the drop creator
        drop.contents
            .nep171
            .entry(nft_contract_id)
            .and_modify(|token_ids| {
                require!(
                    token_ids.insert(token_id.clone()),
                    "Token id already exists in this drop"
                );
            })
            .or_insert(HashSet::from([token_id]));
        drop.contents.near = drop
            .contents
            .near
            .checked_sub(NFT_STORAGE_DEPOSIT)
            .unwrap_or_else(|| env::panic_str(&format!("Insufficient NEAR balance of this gift. Needed {NFT_STORAGE_DEPOSIT} for storage deposit, got {}", drop.contents.near)));

        SlimedropEvent::DropUpdated {
            public_key: msg.public_key,
            contents: drop.contents.clone(),
        }
        .emit();

        PromiseOrValue::Value(false)
    }
}

#[near]
impl MultiTokenReceiver for SlimedropContract {
    fn mt_on_transfer(
        &mut self,
        sender_id: AccountId,
        previous_owner_ids: Vec<AccountId>,
        token_ids: Vec<multi_token::TokenId>,
        amounts: Vec<U128>,
        msg: String,
    ) -> PromiseOrValue<Vec<U128>> {
        require!(
            token_ids.len() == amounts.len() && previous_owner_ids.len() == token_ids.len(),
            "Token ids, previous owner ids and amounts must have the same length"
        );
        require!(
            let Ok(msg) = near_sdk::serde_json::from_str::<TransferCallMsg>(&msg),
            "Invalid message"
        );
        require!(
            let Some(drop) = self.drops.get_mut(&msg.public_key),
            "Key is missing"
        );
        require!(
            drop.created_by == sender_id,
            "You can only add MTs to drops you created"
        );
        check_can_add(drop);

        let mt_contract_id = env::predecessor_account_id();
        // We don't care about previous owner ids if sender is the drop creator
        for (token_id, amount) in token_ids.into_iter().zip(amounts.into_iter()) {
            drop.contents
                .nep245
                .entry(mt_contract_id.clone())
                .and_modify(|token_ids| {
                    token_ids
                        .entry(token_id.clone())
                        .and_modify(|amount| {
                            amount.0 = amount.0.saturating_add(amount.0);
                        })
                        .or_insert(amount);
                })
                .or_insert(HashMap::from([(token_id.clone(), amount)]));
        }
        drop.contents.near = drop
            .contents
            .near
            .checked_sub(MT_STORAGE_DEPOSIT)
            .unwrap_or_else(|| env::panic_str(&format!("Insufficient NEAR balance of this gift. Needed {MT_STORAGE_DEPOSIT} for storage deposit, got {}", drop.contents.near)));

        PromiseOrValue::Value(vec![0.into(); previous_owner_ids.len()])
    }
}

fn send_drop(drop: &Slimedrop, receiver_id: AccountId) -> Promise {
    let near_promise = Promise::new(receiver_id.clone()).transfer(drop.contents.near);
    let nep141_promises = drop
        .contents
        .nep141
        .iter()
        .map(|(account_id, amount)| {
            ext_storage_management::ext(account_id.clone())
                .with_attached_deposit(FT_STORAGE_DEPOSIT)
                .with_static_gas(GAS_FOR_STORAGE_DEPOSIT)
                .storage_deposit(Some(receiver_id.clone()), Some(false))
                .then(
                    SlimedropContract::ext(env::current_account_id())
                        .with_static_gas(
                            GAS_FOR_STORAGE_DEPOSIT_CALLBACK.saturating_add(GAS_FOR_FT_TRANSFER),
                        )
                        .after_ft_storage_deposit(
                            account_id.clone(),
                            receiver_id.clone(),
                            amount.clone(),
                        ),
                )
        })
        .collect::<Vec<_>>();
    let nep171_promises = drop
        .contents
        .nep171
        .iter()
        .flat_map(|(account_id, token_ids)| {
            token_ids.iter().map(|token_id| {
                ext_storage_management::ext(account_id.clone())
                    .with_attached_deposit(NFT_STORAGE_DEPOSIT)
                    .with_static_gas(GAS_FOR_STORAGE_DEPOSIT)
                    .storage_deposit(Some(receiver_id.clone()), Some(false))
                    .then(
                        SlimedropContract::ext(env::current_account_id())
                            .with_static_gas(
                                GAS_FOR_STORAGE_DEPOSIT_CALLBACK
                                    .saturating_add(GAS_FOR_NFT_TRANSFER),
                            )
                            .after_nft_storage_deposit(
                                account_id.clone(),
                                token_id.clone(),
                                receiver_id.clone(),
                            ),
                    )
            })
        })
        .collect::<Vec<_>>();
    let nep245_promises = drop
        .contents
        .nep245
        .iter()
        .map(|(account_id, token_ids)| {
            ext_storage_management::ext(account_id.clone())
                .with_attached_deposit(MT_STORAGE_DEPOSIT)
                .with_static_gas(GAS_FOR_STORAGE_DEPOSIT)
                .storage_deposit(Some(receiver_id.clone()), Some(false))
                .then(
                    SlimedropContract::ext(env::current_account_id())
                        .with_static_gas(
                            GAS_FOR_STORAGE_DEPOSIT_CALLBACK.saturating_add(GAS_FOR_MT_TRANSFER),
                        )
                        .after_mt_storage_deposit(
                            account_id.clone(),
                            token_ids.keys().cloned().collect::<Vec<_>>(),
                            token_ids.values().cloned().collect::<Vec<_>>(),
                            receiver_id.clone(),
                        ),
                )
        })
        .collect::<Vec<_>>();
    let mut batch_promise = near_promise;
    for promise in nep141_promises {
        batch_promise = batch_promise.and(promise);
    }
    for promise in nep171_promises {
        batch_promise = batch_promise.and(promise);
    }
    for promise in nep245_promises {
        batch_promise = batch_promise.and(promise);
    }
    batch_promise.then(SlimedropContract::ext(env::current_account_id()).after_claim())
}
