use std::time::{SystemTime, UNIX_EPOCH};

use near_api::{
    SignerTrait,
    signer::{NEP413Payload, secret_key::SecretKeySigner},
};
use near_crypto::{KeyType, SecretKey, Signature};
use near_sdk::{
    AccountId, NearToken,
    json_types::{Base64VecU8, U64},
    serde::{Deserialize, Serialize},
    serde_json::json,
};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct DropContents {
    pub near: NearToken,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct Claim {
    pub account_id: AccountId,
    pub claimed_at_ms: U64,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct SlimedropView {
    pub contents: DropContents,
    pub created_at_ms: U64,
    pub created_by: AccountId,
    pub claims: Vec<Claim>,
}

const ONE_NEAR: NearToken = NearToken::from_near(1);
const CONTRACT_INITIAL_BALANCE: NearToken = NearToken::from_near(10);

#[tokio::test]
async fn test_get_missing_key_panics() -> Result<(), Box<dyn std::error::Error>> {
    let sandbox = near_workspaces::sandbox_with_version("2.8.0").await?;
    let contract_wasm = near_workspaces::compile_project("./").await?;
    let root = sandbox.root_account()?;

    let contract_account = root
        .create_subaccount("contract")
        .initial_balance(CONTRACT_INITIAL_BALANCE)
        .transact()
        .await?
        .unwrap();

    let contract = contract_account.deploy(&contract_wasm).await?.unwrap();

    // Initialize the contract
    let result = contract.call("new").transact().await?;
    assert!(result.is_success());

    let secret_key = SecretKey::from_random(KeyType::ED25519);
    let public_key = secret_key.public_key();

    // This should fail because the key doesn't exist
    let result = contract
        .view("get_key_info")
        .args_json(json!({"key": public_key}))
        .await;
    assert!(format!("{:#?}", result.unwrap_err()).contains("Key is missing"));

    Ok(())
}

#[tokio::test]
async fn test_add_near_and_get_balance() -> Result<(), Box<dyn std::error::Error>> {
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
        .initial_balance(CONTRACT_INITIAL_BALANCE)
        .transact()
        .await?
        .unwrap();

    let contract = contract_account.deploy(&contract_wasm).await?.unwrap();

    // Initialize the contract
    let result = contract.call("new").transact().await?;
    assert!(result.is_success());

    let secret_key = SecretKey::from_random(KeyType::ED25519);
    let public_key = secret_key.public_key();

    // Create a drop
    let outcome = user_account
        .call(contract.id(), "add_near")
        .args_json(json!({"public_key": public_key}))
        .deposit(ONE_NEAR)
        .transact()
        .await?;

    assert!(outcome.is_success());

    // Check the drop info
    let drop_info_outcome = contract
        .view("get_key_info")
        .args_json(json!({"key": public_key}))
        .await?;

    let drop_info = drop_info_outcome.json::<SlimedropView>().unwrap();
    assert_eq!(drop_info.contents, DropContents { near: ONE_NEAR });
    assert_eq!(drop_info.created_by, user_account.id().clone());
    assert!(drop_info.claims.is_empty());

    Ok(())
}

#[tokio::test]
async fn test_drop_claim_for_someone() -> Result<(), Box<dyn std::error::Error>> {
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
        .initial_balance(CONTRACT_INITIAL_BALANCE)
        .transact()
        .await?
        .unwrap();

    let contract = contract_account.deploy(&contract_wasm).await?.unwrap();

    // Initialize the contract
    let result = contract.call("new").transact().await?;
    assert!(result.is_success());

    // Create a key pair for the claimer
    let secret_key = SecretKey::from_random(KeyType::ED25519);
    let public_key = secret_key.public_key();

    // Create claimer account with the specific key.
    // Claimer doesn't necessarily need to be the same as the receiver
    let claimer_account = root
        .create_subaccount("claimer")
        .initial_balance(ONE_NEAR)
        .transact()
        .await?
        .unwrap();

    // Create a drop with the public key
    let outcome = sender_account
        .call(contract.id(), "add_near")
        .args_json(json!({"public_key": public_key}))
        .deposit(ONE_NEAR)
        .transact()
        .await?;

    assert!(outcome.is_success());

    // Get receiver's initial balance
    let initial_balance = receiver_account.view_account().await?.balance;

    // Claim the drop using the claimer account with the correct key
    let now = U64(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64);
    let nonce = now.0.to_be_bytes();
    let nonce = [vec![0; 32 - nonce.len()], nonce.to_vec()]
        .concat()
        .try_into()
        .unwrap();
    let message = NEP413Payload {
        message: format!(
            "I want to claim this Slimedrop and send it to {}",
            receiver_account.id()
        ),
        nonce,
        recipient: contract.id().to_string(),
        callback_url: None,
    };

    // near-api-rs uses an old version of near-crypto, so to_string + parse is needed
    let signer = SecretKeySigner::new(secret_key.to_string().parse().unwrap());
    let signature = signer
        .sign_message_nep413(
            claimer_account.id().clone(),
            public_key.to_string().parse().unwrap(),
            message,
        )
        .await?;
    let signature_base64 = Base64VecU8(match signature.to_string().parse::<Signature>().unwrap() {
        Signature::ED25519(signature) => signature.to_bytes().to_vec(),
        Signature::SECP256K1(signature) => <[u8; 65] as From<_>>::from(signature).to_vec(),
    });

    let claim_outcome = claimer_account
        .call(contract.id(), "claim")
        .args_json(json!({
            "account_id": receiver_account.id(),
            "signature": signature_base64,
            "public_key": public_key,
            "nonce": now,
        }))
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
async fn test_drop_claim_for_myself_ed25519() -> Result<(), Box<dyn std::error::Error>> {
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
        .initial_balance(CONTRACT_INITIAL_BALANCE)
        .transact()
        .await?
        .unwrap();

    let contract = contract_account.deploy(&contract_wasm).await?.unwrap();

    // Initialize the contract
    let result = contract.call("new").transact().await?;
    assert!(result.is_success());

    // Create a key pair for the claimer
    let secret_key = SecretKey::from_random(KeyType::ED25519);
    let public_key = secret_key.public_key();

    // Create a drop with the public key
    let outcome = sender_account
        .call(contract.id(), "add_near")
        .args_json(json!({"public_key": public_key}))
        .deposit(ONE_NEAR)
        .transact()
        .await?;

    assert!(outcome.is_success());

    // Get receiver's initial balance
    let initial_balance = receiver_account.view_account().await?.balance;

    // Claim the drop using the claimer account with the correct key
    let now = U64(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64);
    let nonce = now.0.to_be_bytes();
    let nonce = [vec![0; 32 - nonce.len()], nonce.to_vec()]
        .concat()
        .try_into()
        .unwrap();
    let message = NEP413Payload {
        message: format!(
            "I want to claim this Slimedrop and send it to {}",
            receiver_account.id()
        ),
        nonce,
        recipient: contract.id().to_string(),
        callback_url: None,
    };

    // near-api-rs uses an old version of near-crypto, so to_string + parse is needed
    let signer = SecretKeySigner::new(secret_key.to_string().parse().unwrap());
    let signature = signer
        .sign_message_nep413(
            receiver_account.id().clone(),
            public_key.to_string().parse().unwrap(),
            message,
        )
        .await?;
    let signature_base64 = Base64VecU8(match signature.to_string().parse::<Signature>().unwrap() {
        Signature::ED25519(signature) => signature.to_bytes().to_vec(),
        Signature::SECP256K1(signature) => <[u8; 65] as From<_>>::from(signature).to_vec(),
    });

    let claim_outcome = receiver_account
        .call(contract.id(), "claim")
        .args_json(json!({
            "signature": signature_base64,
            "public_key": public_key,
            "nonce": now,
        }))
        .transact()
        .await?;

    assert!(claim_outcome.is_success());

    // Check that the receiver's balance increased
    let final_balance = receiver_account.view_account().await?.balance;
    let balance_increase = final_balance.saturating_sub(initial_balance);

    // Allow for some error due to gas
    assert!(
        ONE_NEAR.checked_sub(balance_increase).unwrap() < NearToken::from_millinear(5),
        "Receiver should have received the deposited amount"
    );

    Ok(())
}

#[tokio::test]
async fn test_drop_claim_for_myself_secp256k1() -> Result<(), Box<dyn std::error::Error>> {
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
        .initial_balance(CONTRACT_INITIAL_BALANCE)
        .transact()
        .await?
        .unwrap();

    let contract = contract_account.deploy(&contract_wasm).await?.unwrap();

    // Initialize the contract
    let result = contract.call("new").transact().await?;
    assert!(result.is_success());

    // Create a key pair for the claimer
    let secret_key = SecretKey::from_random(KeyType::SECP256K1);
    let public_key = secret_key.public_key();

    // Create a drop with the public key
    let outcome = sender_account
        .call(contract.id(), "add_near")
        .args_json(json!({"public_key": public_key}))
        .deposit(ONE_NEAR)
        .transact()
        .await?;

    assert!(outcome.is_success());

    // Get receiver's initial balance
    let initial_balance = receiver_account.view_account().await?.balance;

    // Claim the drop using the claimer account with the correct key
    let now = U64(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64);
    let nonce = now.0.to_be_bytes();
    let nonce = [vec![0; 32 - nonce.len()], nonce.to_vec()]
        .concat()
        .try_into()
        .unwrap();
    let message = NEP413Payload {
        message: format!(
            "I want to claim this Slimedrop and send it to {}",
            receiver_account.id()
        ),
        nonce,
        recipient: contract.id().to_string(),
        callback_url: None,
    };

    // near-api-rs uses an old version of near-crypto, so to_string + parse is needed
    let signer = SecretKeySigner::new(secret_key.to_string().parse().unwrap());
    let signature = signer
        .sign_message_nep413(
            receiver_account.id().clone(),
            public_key.to_string().parse().unwrap(),
            message,
        )
        .await?;
    let signature_base64 = Base64VecU8(match signature.to_string().parse::<Signature>().unwrap() {
        Signature::ED25519(signature) => signature.to_bytes().to_vec(),
        Signature::SECP256K1(signature) => <[u8; 65] as From<_>>::from(signature).to_vec(),
    });

    let claim_outcome = receiver_account
        .call(contract.id(), "claim")
        .args_json(json!({
            "signature": signature_base64,
            "public_key": public_key,
            "nonce": now,
        }))
        .transact()
        .await?;

    assert!(claim_outcome.is_success());

    // Check that the receiver's balance increased
    let final_balance = receiver_account.view_account().await?.balance;
    let balance_increase = final_balance.saturating_sub(initial_balance);

    // Allow for some error due to gas
    assert!(
        ONE_NEAR.checked_sub(balance_increase).unwrap() < NearToken::from_millinear(5),
        "Receiver should have received the deposited amount"
    );

    Ok(())
}

#[tokio::test]
async fn test_drop_claim_with_invalid_ed25519_signature_panics()
-> Result<(), Box<dyn std::error::Error>> {
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
        .initial_balance(CONTRACT_INITIAL_BALANCE)
        .transact()
        .await?
        .unwrap();

    let contract = contract_account.deploy(&contract_wasm).await?.unwrap();

    // Initialize the contract
    let result = contract.call("new").transact().await?;
    assert!(result.is_success());

    // Create a key pair for the claimer
    let secret_key = SecretKey::from_random(KeyType::ED25519);
    let public_key = secret_key.public_key();

    // Create a drop with the public key
    let outcome = sender_account
        .call(contract.id(), "add_near")
        .args_json(json!({"public_key": public_key}))
        .deposit(ONE_NEAR)
        .transact()
        .await?;

    assert!(outcome.is_success());

    // Claim the drop using the claimer account with the correct key
    let now = U64(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64);
    let nonce = now.0.to_be_bytes();
    let nonce = [vec![0; 32 - nonce.len()], nonce.to_vec()]
        .concat()
        .try_into()
        .unwrap();
    let message = NEP413Payload {
        message: "I want to buy $JAMBO".to_string(),
        nonce,
        recipient: contract.id().to_string(),
        callback_url: None,
    };

    // near-api-rs uses an old version of near-crypto, so to_string + parse is needed
    let signer = SecretKeySigner::new(secret_key.to_string().parse().unwrap());
    let signature = signer
        .sign_message_nep413(
            receiver_account.id().clone(),
            public_key.to_string().parse().unwrap(),
            message,
        )
        .await?;
    let signature_base64 = Base64VecU8(match signature.to_string().parse::<Signature>().unwrap() {
        Signature::ED25519(signature) => signature.to_bytes().to_vec(),
        Signature::SECP256K1(signature) => <[u8; 65] as From<_>>::from(signature).to_vec(),
    });

    let claim_outcome = receiver_account
        .call(contract.id(), "claim")
        .args_json(json!({
            "signature": signature_base64,
            "public_key": public_key,
            "nonce": now,
        }))
        .transact()
        .await?;

    assert!(format!("{:#?}", claim_outcome.failures()[0]).contains("Failed to verify signature"));

    Ok(())
}

#[tokio::test]
async fn test_drop_claim_with_invalid_secp256k1_signature_panics()
-> Result<(), Box<dyn std::error::Error>> {
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
        .initial_balance(CONTRACT_INITIAL_BALANCE)
        .transact()
        .await?
        .unwrap();

    let contract = contract_account.deploy(&contract_wasm).await?.unwrap();

    // Initialize the contract
    let result = contract.call("new").transact().await?;
    assert!(result.is_success());

    // Create a key pair for the claimer
    let secret_key = SecretKey::from_random(KeyType::SECP256K1);
    let public_key = secret_key.public_key();

    // Create a drop with the public key
    let outcome = sender_account
        .call(contract.id(), "add_near")
        .args_json(json!({"public_key": public_key}))
        .deposit(ONE_NEAR)
        .transact()
        .await?;

    assert!(outcome.is_success());

    // Claim the drop using the claimer account with the correct key
    let now = U64(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64);
    let nonce = now.0.to_be_bytes();
    let nonce = [vec![0; 32 - nonce.len()], nonce.to_vec()]
        .concat()
        .try_into()
        .unwrap();
    let message = NEP413Payload {
        message: "I want to buy $JAMBO".to_string(),
        nonce,
        recipient: contract.id().to_string(),
        callback_url: None,
    };

    // near-api-rs uses an old version of near-crypto, so to_string + parse is needed
    let signer = SecretKeySigner::new(secret_key.to_string().parse().unwrap());
    let signature = signer
        .sign_message_nep413(
            receiver_account.id().clone(),
            public_key.to_string().parse().unwrap(),
            message,
        )
        .await?;
    let signature_base64 = Base64VecU8(match signature.to_string().parse::<Signature>().unwrap() {
        Signature::ED25519(signature) => signature.to_bytes().to_vec(),
        Signature::SECP256K1(signature) => <[u8; 65] as From<_>>::from(signature).to_vec(),
    });

    let claim_outcome = receiver_account
        .call(contract.id(), "claim")
        .args_json(json!({
            "signature": signature_base64,
            "public_key": public_key,
            "nonce": now,
        }))
        .transact()
        .await?;

    assert!(format!("{:#?}", claim_outcome.failures()[0]).contains("Failed to verify signature"));

    Ok(())
}

#[tokio::test]
async fn test_drop_claim_with_expired_nonce_panics() -> Result<(), Box<dyn std::error::Error>> {
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
        .initial_balance(CONTRACT_INITIAL_BALANCE)
        .transact()
        .await?
        .unwrap();

    let contract = contract_account.deploy(&contract_wasm).await?.unwrap();

    // Initialize the contract
    let result = contract.call("new").transact().await?;
    assert!(result.is_success());

    // Create a key pair for the claimer
    let secret_key = SecretKey::from_random(KeyType::ED25519);
    let public_key = secret_key.public_key();

    // Create a drop with the public key
    let outcome = sender_account
        .call(contract.id(), "add_near")
        .args_json(json!({"public_key": public_key}))
        .deposit(ONE_NEAR)
        .transact()
        .await?;

    assert!(outcome.is_success());

    // Claim the drop using the claimer account with the correct key
    let now = U64(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
        - 60 * 6 * 1000);
    let nonce = now.0.to_be_bytes();
    let nonce = [vec![0; 32 - nonce.len()], nonce.to_vec()]
        .concat()
        .try_into()
        .unwrap();
    let message = NEP413Payload {
        message: "I want to claim this Slimedrop".to_string(),
        nonce,
        recipient: contract.id().to_string(),
        callback_url: None,
    };

    // near-api-rs uses an old version of near-crypto, so to_string + parse is needed
    let signer = SecretKeySigner::new(secret_key.to_string().parse().unwrap());
    let signature = signer
        .sign_message_nep413(
            receiver_account.id().clone(),
            public_key.to_string().parse().unwrap(),
            message,
        )
        .await?;
    let signature_base64 = Base64VecU8(match signature.to_string().parse::<Signature>().unwrap() {
        Signature::ED25519(signature) => signature.to_bytes().to_vec(),
        Signature::SECP256K1(signature) => <[u8; 65] as From<_>>::from(signature).to_vec(),
    });

    let claim_outcome = receiver_account
        .call(contract.id(), "claim")
        .args_json(json!({
            "signature": signature_base64,
            "public_key": public_key,
            "nonce": now,
        }))
        .transact()
        .await?;

    assert!(format!("{:#?}", claim_outcome.failures()[0]).contains("Nonce has expired"));

    Ok(())
}

#[tokio::test]
async fn test_drop_claim_with_future_nonce_panics() -> Result<(), Box<dyn std::error::Error>> {
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
        .initial_balance(CONTRACT_INITIAL_BALANCE)
        .transact()
        .await?
        .unwrap();

    let contract = contract_account.deploy(&contract_wasm).await?.unwrap();

    // Initialize the contract
    let result = contract.call("new").transact().await?;
    assert!(result.is_success());

    // Create a key pair for the claimer
    let secret_key = SecretKey::from_random(KeyType::ED25519);
    let public_key = secret_key.public_key();

    // Create a drop with the public key
    let outcome = sender_account
        .call(contract.id(), "add_near")
        .args_json(json!({"public_key": public_key}))
        .deposit(ONE_NEAR)
        .transact()
        .await?;

    assert!(outcome.is_success());

    // Claim the drop using the claimer account with the correct key
    let now = U64(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
        + 60 * 1000);
    let nonce = now.0.to_be_bytes();
    let nonce = [vec![0; 32 - nonce.len()], nonce.to_vec()]
        .concat()
        .try_into()
        .unwrap();
    let message = NEP413Payload {
        message: "I want to claim this Slimedrop".to_string(),
        nonce,
        recipient: contract.id().to_string(),
        callback_url: None,
    };

    // near-api-rs uses an old version of near-crypto, so to_string + parse is needed
    let signer = SecretKeySigner::new(secret_key.to_string().parse().unwrap());
    let signature = signer
        .sign_message_nep413(
            receiver_account.id().clone(),
            public_key.to_string().parse().unwrap(),
            message,
        )
        .await?;
    let signature_base64 = Base64VecU8(match signature.to_string().parse::<Signature>().unwrap() {
        Signature::ED25519(signature) => signature.to_bytes().to_vec(),
        Signature::SECP256K1(signature) => <[u8; 65] as From<_>>::from(signature).to_vec(),
    });

    let claim_outcome = receiver_account
        .call(contract.id(), "claim")
        .args_json(json!({
            "signature": signature_base64,
            "public_key": public_key,
            "nonce": now,
        }))
        .transact()
        .await?;

    assert!(format!("{:#?}", claim_outcome.failures()[0]).contains("Nonce is in the future"));

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
        .initial_balance(CONTRACT_INITIAL_BALANCE)
        .transact()
        .await?
        .unwrap();

    let contract = contract_account.deploy(&contract_wasm).await?.unwrap();

    // Initialize the contract
    let result = contract.call("new").transact().await?;
    assert!(result.is_success());

    let secret_key = SecretKey::from_random(KeyType::ED25519);
    let public_key = secret_key.public_key();
    let additional_deposit = NearToken::from_yoctonear(ONE_NEAR.as_yoctonear() + 1);

    // Create first drop
    let outcome1 = user_account
        .call(contract.id(), "add_near")
        .args_json(json!({"public_key": public_key}))
        .deposit(ONE_NEAR)
        .transact()
        .await?;

    assert!(outcome1.is_success());

    // Check the drop info after first deposit
    let drop_info_after_first_outcome = contract
        .view("get_key_info")
        .args_json(json!({"key": public_key}))
        .await?;

    let drop_info = drop_info_after_first_outcome
        .json::<SlimedropView>()
        .unwrap();
    assert_eq!(drop_info.contents, DropContents { near: ONE_NEAR });
    assert_eq!(drop_info.created_by, user_account.id().clone());
    assert!(drop_info.claims.is_empty());

    // Create second drop with the same key (should add to existing balance)
    let outcome2 = user_account
        .call(contract.id(), "add_near")
        .args_json(json!({"public_key": public_key}))
        .deposit(additional_deposit)
        .transact()
        .await?;

    assert!(outcome2.is_success());

    // Check the drop info after second deposit
    let drop_info_after_second_outcome = contract
        .view("get_key_info")
        .args_json(json!({"key": public_key}))
        .await?;

    let expected_total = ONE_NEAR.saturating_add(additional_deposit);
    let drop_info = drop_info_after_second_outcome
        .json::<SlimedropView>()
        .unwrap();
    assert_eq!(
        drop_info.contents,
        DropContents {
            near: expected_total
        }
    );
    assert_eq!(drop_info.created_by, user_account.id().clone());
    assert!(drop_info.claims.is_empty());

    Ok(())
}

#[tokio::test]
async fn test_add_near_requires_deposit() -> Result<(), Box<dyn std::error::Error>> {
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
        .initial_balance(CONTRACT_INITIAL_BALANCE)
        .transact()
        .await?
        .unwrap();

    let contract = contract_account.deploy(&contract_wasm).await?.unwrap();

    // Initialize the contract
    let result = contract.call("new").transact().await?;
    assert!(result.is_success());

    let secret_key = SecretKey::from_random(KeyType::ED25519);
    let public_key = secret_key.public_key();

    // Try to create a drop without any deposit - should fail
    let result = user_account
        .call(contract.id(), "add_near")
        .args_json(json!({"public_key": public_key}))
        .deposit(NearToken::from_near(0)) // no deposit
        .transact()
        .await;

    assert!(
        format!("{:#?}", result.unwrap().failures()[0])
            .contains("Attached deposit must be at least 1 yoctoNEAR"),
    );

    Ok(())
}

#[tokio::test]
async fn test_get_account_drops() -> Result<(), Box<dyn std::error::Error>> {
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
        .initial_balance(CONTRACT_INITIAL_BALANCE)
        .transact()
        .await?
        .unwrap();

    let contract = contract_account.deploy(&contract_wasm).await?.unwrap();

    // Initialize the contract
    let result = contract.call("new").transact().await?;
    assert!(result.is_success());

    // Create multiple drops
    let secret_key1 = SecretKey::from_random(KeyType::ED25519);
    let public_key1 = secret_key1.public_key();
    let secret_key2 = SecretKey::from_random(KeyType::ED25519);
    let public_key2 = secret_key2.public_key();

    // Create first drop
    let outcome1 = user_account
        .call(contract.id(), "add_near")
        .args_json(json!({"public_key": public_key1}))
        .deposit(ONE_NEAR)
        .transact()
        .await?;
    assert!(outcome1.is_success());

    // Create second drop
    let outcome2 = user_account
        .call(contract.id(), "add_near")
        .args_json(json!({"public_key": public_key2}))
        .deposit(ONE_NEAR.saturating_mul(2))
        .transact()
        .await?;
    assert!(outcome2.is_success());

    // Get account drops
    let drops_outcome = contract
        .view("get_account_drops")
        .args_json(json!({"account_id": user_account.id()}))
        .await?;

    let drops = drops_outcome.json::<Vec<SlimedropView>>().unwrap();
    assert_eq!(drops.len(), 2);

    // Check first drop
    assert_eq!(drops[0].contents.near, ONE_NEAR);
    assert_eq!(drops[0].created_by, user_account.id().clone());
    assert!(drops[0].claims.is_empty());

    // Check second drop
    assert_eq!(drops[1].contents.near, ONE_NEAR.saturating_mul(2));
    assert_eq!(drops[1].created_by, user_account.id().clone());
    assert!(drops[1].claims.is_empty());

    // Test pagination
    let bounded_drops_outcome = contract
        .view("get_account_drops")
        .args_json(json!({
            "account_id": user_account.id(),
            "skip": 0.to_string(),
            "limit": 1.to_string()
        }))
        .await?;

    let bounded_drops = bounded_drops_outcome.json::<Vec<SlimedropView>>().unwrap();
    assert_eq!(bounded_drops.len(), 1);

    // Test for account with no drops
    let empty_account = root
        .create_subaccount("empty")
        .initial_balance(ONE_NEAR)
        .transact()
        .await?
        .unwrap();

    let empty_drops_outcome = contract
        .view("get_account_drops")
        .args_json(json!({"account_id": empty_account.id()}))
        .await?;

    let empty_drops = empty_drops_outcome.json::<Vec<SlimedropView>>().unwrap();
    assert!(empty_drops.is_empty());

    Ok(())
}

#[tokio::test]
async fn test_drop_already_claimed_on_add_near() -> Result<(), Box<dyn std::error::Error>> {
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
        .initial_balance(CONTRACT_INITIAL_BALANCE)
        .transact()
        .await?
        .unwrap();

    let contract = contract_account.deploy(&contract_wasm).await?.unwrap();

    // Initialize the contract
    let result = contract.call("new").transact().await?;
    assert!(result.is_success());

    let secret_key = SecretKey::from_random(KeyType::ED25519);
    let public_key = secret_key.public_key();

    // Create a drop
    let outcome = sender_account
        .call(contract.id(), "add_near")
        .args_json(json!({"public_key": public_key}))
        .deposit(ONE_NEAR)
        .transact()
        .await?;
    assert!(outcome.is_success());

    // Claim the drop
    let now = U64(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64);
    let nonce = now.0.to_be_bytes();
    let nonce = [vec![0; 32 - nonce.len()], nonce.to_vec()]
        .concat()
        .try_into()
        .unwrap();
    let message = NEP413Payload {
        message: format!(
            "I want to claim this Slimedrop and send it to {}",
            receiver_account.id()
        ),
        nonce,
        recipient: contract.id().to_string(),
        callback_url: None,
    };

    let signer = SecretKeySigner::new(secret_key.to_string().parse().unwrap());
    let signature = signer
        .sign_message_nep413(
            receiver_account.id().clone(),
            public_key.to_string().parse().unwrap(),
            message,
        )
        .await?;
    let signature_base64 = Base64VecU8(match signature.to_string().parse::<Signature>().unwrap() {
        Signature::ED25519(signature) => signature.to_bytes().to_vec(),
        Signature::SECP256K1(signature) => <[u8; 65] as From<_>>::from(signature).to_vec(),
    });

    let claim_outcome = receiver_account
        .call(contract.id(), "claim")
        .args_json(json!({
            "signature": signature_base64,
            "public_key": public_key,
            "nonce": now,
        }))
        .transact()
        .await?;
    assert!(claim_outcome.is_success());

    // Try to add more NEAR to the same drop - should fail
    let add_near_outcome = sender_account
        .call(contract.id(), "add_near")
        .args_json(json!({"public_key": public_key}))
        .deposit(ONE_NEAR)
        .transact()
        .await?;

    assert!(format!("{:#?}", add_near_outcome.failures()[0]).contains("Drop already claimed"));

    Ok(())
}

#[tokio::test]
async fn test_drop_already_claimed_on_second_claim() -> Result<(), Box<dyn std::error::Error>> {
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
        .initial_balance(CONTRACT_INITIAL_BALANCE)
        .transact()
        .await?
        .unwrap();

    let contract = contract_account.deploy(&contract_wasm).await?.unwrap();

    // Initialize the contract
    let result = contract.call("new").transact().await?;
    assert!(result.is_success());

    let secret_key = SecretKey::from_random(KeyType::ED25519);
    let public_key = secret_key.public_key();

    // Create a drop
    let outcome = sender_account
        .call(contract.id(), "add_near")
        .args_json(json!({"public_key": public_key}))
        .deposit(ONE_NEAR)
        .transact()
        .await?;
    assert!(outcome.is_success());

    // Claim the drop first time
    let now = U64(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64);
    let nonce = now.0.to_be_bytes();
    let nonce = [vec![0; 32 - nonce.len()], nonce.to_vec()]
        .concat()
        .try_into()
        .unwrap();
    let message = NEP413Payload {
        message: format!(
            "I want to claim this Slimedrop and send it to {}",
            receiver_account.id()
        ),
        nonce,
        recipient: contract.id().to_string(),
        callback_url: None,
    };

    let signer = SecretKeySigner::new(secret_key.to_string().parse().unwrap());
    let signature = signer
        .sign_message_nep413(
            receiver_account.id().clone(),
            public_key.to_string().parse().unwrap(),
            message,
        )
        .await?;
    let signature_base64 = Base64VecU8(match signature.to_string().parse::<Signature>().unwrap() {
        Signature::ED25519(signature) => signature.to_bytes().to_vec(),
        Signature::SECP256K1(signature) => <[u8; 65] as From<_>>::from(signature).to_vec(),
    });

    let claim_outcome = receiver_account
        .call(contract.id(), "claim")
        .args_json(json!({
            "signature": signature_base64,
            "public_key": public_key,
            "nonce": now,
        }))
        .transact()
        .await?;
    assert!(claim_outcome.is_success());

    // Try to claim the same drop again - should fail
    let now2 = U64(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64);
    let nonce2 = now2.0.to_be_bytes();
    let nonce2 = [vec![0; 32 - nonce2.len()], nonce2.to_vec()]
        .concat()
        .try_into()
        .unwrap();
    let message2 = NEP413Payload {
        message: format!(
            "I want to claim this Slimedrop and send it to {}",
            receiver_account.id()
        ),
        nonce: nonce2,
        recipient: contract.id().to_string(),
        callback_url: None,
    };

    let signature2 = signer
        .sign_message_nep413(
            receiver_account.id().clone(),
            public_key.to_string().parse().unwrap(),
            message2,
        )
        .await?;
    let signature2_base64 =
        Base64VecU8(match signature2.to_string().parse::<Signature>().unwrap() {
            Signature::ED25519(signature) => signature.to_bytes().to_vec(),
            Signature::SECP256K1(signature) => <[u8; 65] as From<_>>::from(signature).to_vec(),
        });

    let second_claim_outcome = receiver_account
        .call(contract.id(), "claim")
        .args_json(json!({
            "signature": signature2_base64,
            "public_key": public_key,
            "nonce": now2,
        }))
        .transact()
        .await?;

    assert!(format!("{:#?}", second_claim_outcome.failures()[0]).contains("Drop already claimed"));

    Ok(())
}

#[tokio::test]
async fn test_get_key_info_with_claims() -> Result<(), Box<dyn std::error::Error>> {
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
        .initial_balance(CONTRACT_INITIAL_BALANCE)
        .transact()
        .await?
        .unwrap();

    let contract = contract_account.deploy(&contract_wasm).await?.unwrap();

    // Initialize the contract
    let result = contract.call("new").transact().await?;
    assert!(result.is_success());

    let secret_key = SecretKey::from_random(KeyType::ED25519);
    let public_key = secret_key.public_key();

    // Create a drop
    let outcome = sender_account
        .call(contract.id(), "add_near")
        .args_json(json!({"public_key": public_key}))
        .deposit(ONE_NEAR)
        .transact()
        .await?;
    assert!(outcome.is_success());

    // Check drop info before claim
    let drop_info_before = contract
        .view("get_key_info")
        .args_json(json!({"key": public_key}))
        .await?;

    let drop_before = drop_info_before.json::<SlimedropView>().unwrap();
    assert_eq!(drop_before.contents.near, ONE_NEAR);
    assert_eq!(drop_before.created_by, sender_account.id().clone());
    assert!(drop_before.claims.is_empty());

    // Claim the drop
    let now = U64(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64);
    let nonce = now.0.to_be_bytes();
    let nonce = [vec![0; 32 - nonce.len()], nonce.to_vec()]
        .concat()
        .try_into()
        .unwrap();
    let message = NEP413Payload {
        message: format!(
            "I want to claim this Slimedrop and send it to {}",
            receiver_account.id()
        ),
        nonce,
        recipient: contract.id().to_string(),
        callback_url: None,
    };

    let signer = SecretKeySigner::new(secret_key.to_string().parse().unwrap());
    let signature = signer
        .sign_message_nep413(
            receiver_account.id().clone(),
            public_key.to_string().parse().unwrap(),
            message,
        )
        .await?;
    let signature_base64 = Base64VecU8(match signature.to_string().parse::<Signature>().unwrap() {
        Signature::ED25519(signature) => signature.to_bytes().to_vec(),
        Signature::SECP256K1(signature) => <[u8; 65] as From<_>>::from(signature).to_vec(),
    });

    let claim_outcome = receiver_account
        .call(contract.id(), "claim")
        .args_json(json!({
            "signature": signature_base64,
            "public_key": public_key,
            "nonce": now,
        }))
        .transact()
        .await?;
    assert!(claim_outcome.is_success());

    // Check drop info after claim
    let drop_info_after = contract
        .view("get_key_info")
        .args_json(json!({"key": public_key}))
        .await?;

    let drop_after = drop_info_after.json::<SlimedropView>().unwrap();
    assert_eq!(drop_after.contents.near, ONE_NEAR);
    assert_eq!(drop_after.created_by, sender_account.id().clone());
    assert_eq!(drop_after.claims.len(), 1);
    assert_eq!(
        drop_after.claims[0].account_id,
        receiver_account.id().clone()
    );
    assert!(drop_after.claims[0].claimed_at_ms.0 > 0);

    Ok(())
}
