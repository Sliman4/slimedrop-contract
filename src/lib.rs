use near_sdk::{
    AccountId, NearToken, PanicOnDefault, Promise, PublicKey, env, near, store::LookupMap,
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
        let drop = self
            .accounts
            .get(&public_key)
            .cloned()
            .unwrap_or(Default::default());
        let new_value = DropContents {
            near: drop.near.saturating_add(env::attached_deposit()),
        };
        self.accounts.insert(public_key, new_value);
    }

    /// Claim tokens for specific account that are attached to the public key this tx is signed with.
    pub fn claim(&mut self, account_id: Option<AccountId>) -> Promise {
        let receiver_id = account_id.unwrap_or_else(env::signer_account_id);
        let drop = self
            .accounts
            .remove(&env::signer_account_pk())
            .expect("Unexpected public key");
        Promise::new(receiver_id).transfer(drop.near)
    }

    /// Returns the balance associated with given key.
    pub fn get_key_balance(&self, key: PublicKey) -> DropContents {
        self.accounts.get(&key).cloned().expect("Key is missing")
    }
}
