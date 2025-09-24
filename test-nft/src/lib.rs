use near_sdk::{near, AccountId};
use near_sdk_contract_tools::{
    nft::{Nep171Controller, Nep171Mint, TokenId},
    NonFungibleToken,
};

use near_sdk_contract_tools::nft::Token;

#[near(contract_state)]
#[derive(NonFungibleToken, Default)]
pub struct Contract {}

#[near]
impl Contract {
    #[private]
    pub fn mint(&mut self, account_id: AccountId, token_id: TokenId) {
        Nep171Controller::mint(
            self,
            &Nep171Mint {
                token_ids: vec![token_id.into()],
                receiver_id: account_id.into(),
                memo: None,
            },
        )
        .expect("Failed to mint");
    }
}
