use near_sdk::{json_types::U128, near, AccountId};
use near_sdk_contract_tools::{
    mt::{nep245::TokenAmount, Nep245Controller, Nep245Mint, TokenId},
    Nep145, Nep245,
};

#[near(contract_state)]
#[derive(Nep245, Default, Nep145)]
pub struct Contract {}

#[near]
impl Contract {
    #[private]
    pub fn mint(&mut self, account_id: AccountId, token_id: TokenId, amount: U128) {
        Nep245Controller::create_token(self, token_id.clone()).expect("Failed to create token");
        Nep245Controller::mint(
            self,
            &Nep245Mint {
                payload: vec![TokenAmount {
                    token_id: token_id.into(),
                    amount: amount.0,
                }],
                receiver_id: account_id.into(),
                memo: None,
            },
        )
        .expect("Failed to mint");
    }
}
