use near_sdk::{
    serde::{Deserialize, Serialize},
    serde_json::json,
};
use near_workspaces::types::{KeyType, NearToken, SecretKey};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct DropContents {
    pub near: NearToken,
}

const ONE_NEAR: NearToken = NearToken::from_near(1);

fn create_random_key() -> SecretKey {
    SecretKey::from_random(KeyType::ED25519)
}

#[tokio::test]
async fn test_get_missing_key_panics() -> Result<(), Box<dyn std::error::Error>> {
    let sandbox = near_workspaces::sandbox_with_version("2.8.0").await?;
    let contract_wasm = near_workspaces::compile_project("./").await?;
    let root = sandbox.root_account()?;

    let contract_account = root
        .create_subaccount("contract")
        .initial_balance(ONE_NEAR)
        .transact()
        .await?
        .unwrap();

    let contract = contract_account.deploy(&contract_wasm).await?.unwrap();

    // Initialize the contract
    let result = contract.call("new").transact().await?;
    assert!(result.is_success());

    let secret_key = create_random_key();
    let public_key = secret_key.public_key();

    // This should fail because the key doesn't exist
    let result = contract
        .view("get_key_balance")
        .args_json(json!({"key": public_key}))
        .await;
    assert!(format!("{:#?}", result.unwrap_err()).contains("Key is missing"));

    Ok(())
}

#[tokio::test]
async fn test_create_drop_and_get_balance() -> Result<(), Box<dyn std::error::Error>> {
    let sandbox = near_workspaces::sandbox_with_version("2.8.0").await?;
    let contract_wasm = near_workspaces::compile_project("./").await?;
    let root = sandbox.root_account()?;

    let user_account = root
        .create_subaccount("user")
        .initial_balance(ONE_NEAR.saturating_mul(10))
        .transact()
        .await?
        .unwrap();

    let contract_account = root
        .create_subaccount("contract")
        .initial_balance(ONE_NEAR)
        .transact()
        .await?
        .unwrap();

    let contract = contract_account.deploy(&contract_wasm).await?.unwrap();

    // Initialize the contract
    let result = contract.call("new").transact().await?;
    assert!(result.is_success());

    let secret_key = create_random_key();
    let public_key = secret_key.public_key();

    // Create a drop
    let outcome = user_account
        .call(contract.id(), "create_drop")
        .args_json(json!({"public_key": public_key}))
        .deposit(ONE_NEAR)
        .transact()
        .await?;

    assert!(outcome.is_success());

    // Check the balance
    let balance_outcome = contract
        .view("get_key_balance")
        .args_json(json!({"key": public_key}))
        .await?;

    assert_eq!(
        balance_outcome.json::<DropContents>().unwrap(),
        DropContents { near: ONE_NEAR }
    );

    Ok(())
}

#[tokio::test]
async fn test_drop_claim() -> Result<(), Box<dyn std::error::Error>> {
    let sandbox = near_workspaces::sandbox_with_version("2.8.0").await?;
    let contract_wasm = near_workspaces::compile_project("./").await?;
    let root = sandbox.root_account()?;

    let sender_account = root
        .create_subaccount("sender")
        .initial_balance(ONE_NEAR.saturating_mul(10))
        .transact()
        .await?
        .unwrap();

    let receiver_account = root
        .create_subaccount("receiver")
        .initial_balance(ONE_NEAR)
        .transact()
        .await?
        .unwrap();

    let contract_account = root
        .create_subaccount("contract")
        .initial_balance(ONE_NEAR)
        .transact()
        .await?
        .unwrap();

    let contract = contract_account.deploy(&contract_wasm).await?.unwrap();

    // Initialize the contract
    let result = contract.call("new").transact().await?;
    assert!(result.is_success());

    // Create a key pair for the claimer
    let secret_key = create_random_key();
    let public_key = secret_key.public_key();

    // Create claimer account with the specific key.
    // Claimer doesn't necessarily need to be the same as the receiver
    let claimer_account = root
        .create_subaccount("claimer")
        .initial_balance(ONE_NEAR)
        .keys(secret_key)
        .transact()
        .await?
        .unwrap();

    // Create a drop with the public key
    let outcome = sender_account
        .call(contract.id(), "create_drop")
        .args_json(json!({"public_key": public_key}))
        .deposit(ONE_NEAR)
        .transact()
        .await?;

    assert!(outcome.is_success());

    // Get receiver's initial balance
    let initial_balance = receiver_account.view_account().await?.balance;

    // Claim the drop using the claimer account with the correct key
    let claim_outcome = claimer_account
        .call(contract.id(), "claim")
        .args_json(json!({"account_id": receiver_account.id()}))
        .transact()
        .await?;

    assert!(claim_outcome.is_success());

    // Check that the receiver's balance increased
    let final_balance = receiver_account.view_account().await?.balance;
    let balance_increase = final_balance.saturating_sub(initial_balance);

    assert_eq!(
        balance_increase, ONE_NEAR,
        "Receiver should have received the deposited amount"
    );

    Ok(())
}

#[tokio::test]
async fn test_send_two_times() -> Result<(), Box<dyn std::error::Error>> {
    let sandbox = near_workspaces::sandbox_with_version("2.8.0").await?;
    let contract_wasm = near_workspaces::compile_project("./").await?;
    let root = sandbox.root_account()?;

    let user_account = root
        .create_subaccount("user")
        .initial_balance(ONE_NEAR.saturating_mul(10))
        .transact()
        .await?
        .unwrap();

    let contract_account = root
        .create_subaccount("contract")
        .initial_balance(ONE_NEAR)
        .transact()
        .await?
        .unwrap();

    let contract = contract_account.deploy(&contract_wasm).await?.unwrap();

    // Initialize the contract
    let result = contract.call("new").transact().await?;
    assert!(result.is_success());

    let secret_key = create_random_key();
    let public_key = secret_key.public_key();
    let additional_deposit = NearToken::from_yoctonear(ONE_NEAR.as_yoctonear() + 1);

    // Create first drop
    let outcome1 = user_account
        .call(contract.id(), "create_drop")
        .args_json(json!({"public_key": public_key}))
        .deposit(ONE_NEAR)
        .transact()
        .await?;

    assert!(outcome1.is_success());

    // Check the balance after first deposit
    let balance_after_first_outcome = contract
        .view("get_key_balance")
        .args_json(json!({"key": public_key}))
        .await?;

    assert_eq!(
        balance_after_first_outcome.json::<DropContents>().unwrap(),
        DropContents { near: ONE_NEAR }
    );

    // Create second drop with the same key (should add to existing balance)
    let outcome2 = user_account
        .call(contract.id(), "create_drop")
        .args_json(json!({"public_key": public_key}))
        .deposit(additional_deposit)
        .transact()
        .await?;

    assert!(outcome2.is_success());

    // Check the balance after second deposit
    let balance_after_second_outcome = contract
        .view("get_key_balance")
        .args_json(json!({"key": public_key}))
        .await?;

    let expected_total = ONE_NEAR.saturating_add(additional_deposit);
    assert_eq!(
        balance_after_second_outcome.json::<DropContents>().unwrap(),
        DropContents {
            near: expected_total
        }
    );

    Ok(())
}

#[tokio::test]
async fn test_create_drop_requires_deposit() -> Result<(), Box<dyn std::error::Error>> {
    let sandbox = near_workspaces::sandbox_with_version("2.8.0").await?;
    let contract_wasm = near_workspaces::compile_project("./").await?;
    let root = sandbox.root_account()?;

    let user_account = root
        .create_subaccount("user")
        .initial_balance(ONE_NEAR.saturating_mul(10))
        .transact()
        .await?
        .unwrap();

    let contract_account = root
        .create_subaccount("contract")
        .initial_balance(ONE_NEAR)
        .transact()
        .await?
        .unwrap();

    let contract = contract_account.deploy(&contract_wasm).await?.unwrap();

    // Initialize the contract
    let result = contract.call("new").transact().await?;
    assert!(result.is_success());

    let secret_key = create_random_key();
    let public_key = secret_key.public_key();

    // Try to create a drop without any deposit - should fail
    let result = user_account
        .call(contract.id(), "create_drop")
        .args_json(json!({"public_key": public_key}))
        .deposit(NearToken::from_near(0)) // no deposit
        .transact()
        .await;

    assert!(
        format!(
            "{:#?}",
            result.unwrap().failures()[0]
                .clone()
                .into_result()
                .unwrap_err()
        )
        .contains("Attached deposit must be at least 1 yoctoNEAR"),
    );

    Ok(())
}
