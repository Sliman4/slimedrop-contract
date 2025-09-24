use near_sdk::{json_types::U128, near, AccountId};
use near_sdk_contract_tools::{
    ft::{Nep141Controller, Nep141Mint},
    FungibleToken,
};

#[near(contract_state)]
#[derive(FungibleToken, Default)]
pub struct Contract {}

#[near]
impl Contract {
    #[private]
    pub fn mint(&mut self, account_id: AccountId, amount: U128) {
        Nep141Controller::mint(
            self,
            &Nep141Mint {
                amount: amount.0,
                receiver_id: account_id.into(),
                memo: None,
            },
        )
        .expect("Failed to mint");
    }
}
