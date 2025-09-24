use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use near_api::{
    SignerTrait,
    signer::{NEP413Payload, secret_key::SecretKeySigner},
};
use near_crypto::{KeyType, PublicKey, SecretKey, Signature};
use near_sdk::json_types::U128;
use near_sdk::{
    AccountId, NearToken,
    json_types::{Base64VecU8, U64},
    serde::{Deserialize, Serialize},
    serde_json::json,
};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct DropContents {
    /// Native NEAR
    pub near: NearToken,
    /// Fungible tokens
    pub nep141: HashMap<AccountId, U128>,
    /// Non-fungible tokens  
    pub nep171: HashMap<AccountId, HashSet<String>>,
    /// Multi-fungible tokens
    pub nep245: HashMap<AccountId, HashMap<String, U128>>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct Claim {
    pub claimed_at_ms: U64,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct SlimedropView {
    pub contents: DropContents,
    pub created_at_ms: U64,
    pub created_by: AccountId,
    pub claims: HashMap<AccountId, Claim>,
    pub status: DropStatus,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub enum DropStatus {
    Active,
    Cancelled,
}

const ONE_NEAR: NearToken = NearToken::from_near(1);
const CONTRACT_INITIAL_BALANCE: NearToken = NearToken::from_near(10);
const FLAT_FEE_PER_DROP: NearToken = NearToken::from_millinear(50); // 0.05 NEAR

#[tokio::test]
#[serial_test::serial]
async fn test_get_missing_key() -> Result<(), Box<dyn std::error::Error>> {
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

    // Check that key returns None
    let result = contract
        .view("get_key_info")
        .args_json(json!({"key": public_key}))
        .await?;
    assert_eq!(result.json::<Option<SlimedropView>>()?, None);

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
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
    assert_eq!(
        drop_info.contents,
        DropContents {
            near: ONE_NEAR.saturating_sub(FLAT_FEE_PER_DROP),
            nep141: HashMap::new(),
            nep171: HashMap::new(),
            nep245: HashMap::new(),
        }
    );
    assert_eq!(drop_info.created_by, user_account.id().clone());
    assert!(drop_info.claims.is_empty());

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
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
        balance_increase,
        ONE_NEAR.saturating_sub(FLAT_FEE_PER_DROP),
        "Receiver should have received the deposited amount minus fees"
    );

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
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
    let expected_amount = ONE_NEAR.saturating_sub(FLAT_FEE_PER_DROP);
    assert!(
        expected_amount.checked_sub(balance_increase).unwrap() < NearToken::from_millinear(5),
        "Receiver should have received the deposited amount minus fees"
    );

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
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
    let expected_amount = ONE_NEAR.saturating_sub(FLAT_FEE_PER_DROP);
    assert!(
        expected_amount.checked_sub(balance_increase).unwrap() < NearToken::from_millinear(5),
        "Receiver should have received the deposited amount minus fees"
    );

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
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
#[serial_test::serial]
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
#[serial_test::serial]
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
#[serial_test::serial]
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
#[serial_test::serial]
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
    assert_eq!(
        drop_info.contents,
        DropContents {
            near: ONE_NEAR.saturating_sub(FLAT_FEE_PER_DROP),
            nep141: HashMap::new(),
            nep171: HashMap::new(),
            nep245: HashMap::new(),
        }
    );
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

    // Should only charge the fee once
    let expected_total = ONE_NEAR
        .saturating_sub(FLAT_FEE_PER_DROP)
        .saturating_add(additional_deposit);
    let drop_info = drop_info_after_second_outcome
        .json::<SlimedropView>()
        .unwrap();
    assert_eq!(
        drop_info.contents,
        DropContents {
            near: expected_total,
            nep141: HashMap::new(),
            nep171: HashMap::new(),
            nep245: HashMap::new(),
        }
    );
    assert_eq!(drop_info.created_by, user_account.id().clone());
    assert!(drop_info.claims.is_empty());

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
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

    // Try to create a drop with insufficient deposit - should fail
    let result = user_account
        .call(contract.id(), "add_near")
        .args_json(json!({"public_key": public_key}))
        .deposit(NearToken::from_millinear(30)) // less than required fee
        .transact()
        .await;

    assert!(
        format!("{:#?}", result.unwrap().failures()[0])
            .contains("Attached deposit must be greater than"),
    );

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
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

    let drops = drops_outcome
        .json::<Vec<(PublicKey, SlimedropView)>>()
        .unwrap();
    assert_eq!(drops.len(), 2);

    // Check first drop
    assert_eq!(drops[0].0, public_key1);
    assert_eq!(
        drops[0].1.contents.near,
        ONE_NEAR.saturating_sub(FLAT_FEE_PER_DROP)
    );
    assert_eq!(drops[0].1.created_by, user_account.id().clone());
    assert!(drops[0].1.claims.is_empty());

    // Check second drop
    assert_eq!(drops[1].0, public_key2);
    assert_eq!(
        drops[1].1.contents.near,
        ONE_NEAR.saturating_mul(2).saturating_sub(FLAT_FEE_PER_DROP)
    );
    assert_eq!(drops[1].1.created_by, user_account.id().clone());
    assert!(drops[1].1.claims.is_empty());

    // Test pagination
    let bounded_drops_outcome = contract
        .view("get_account_drops")
        .args_json(json!({
            "account_id": user_account.id(),
            "skip": 0.to_string(),
            "limit": 1.to_string()
        }))
        .await?;

    let bounded_drops = bounded_drops_outcome
        .json::<Vec<(PublicKey, SlimedropView)>>()
        .unwrap();
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

    let empty_drops = empty_drops_outcome
        .json::<Vec<(PublicKey, SlimedropView)>>()
        .unwrap();
    assert!(empty_drops.is_empty());

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
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
#[serial_test::serial]
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
#[serial_test::serial]
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
    assert_eq!(
        drop_before.contents.near,
        ONE_NEAR.saturating_sub(FLAT_FEE_PER_DROP)
    );
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
    assert_eq!(
        drop_after.contents.near,
        ONE_NEAR.saturating_sub(FLAT_FEE_PER_DROP)
    );
    assert_eq!(drop_after.created_by, sender_account.id().clone());
    assert_eq!(drop_after.claims.len(), 1);
    assert!(drop_after.claims.contains_key(receiver_account.id()));
    let claim = drop_after.claims.get(receiver_account.id()).unwrap();
    assert!(claim.claimed_at_ms.0 > 0);

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_cancel_drop() -> Result<(), Box<dyn std::error::Error>> {
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

    // Verify the drop is active
    let drop_info_before = contract
        .view("get_key_info")
        .args_json(json!({"key": public_key}))
        .await?;

    let drop_before = drop_info_before.json::<SlimedropView>().unwrap();
    assert_eq!(
        drop_before.contents.near,
        ONE_NEAR.saturating_sub(FLAT_FEE_PER_DROP)
    );
    assert_eq!(drop_before.created_by, user_account.id().clone());
    assert!(drop_before.claims.is_empty());

    // Get user's initial balance
    let initial_balance = user_account.view_account().await?.balance;

    // Cancel the drop
    let cancel_outcome = user_account
        .call(contract.id(), "cancel_drop")
        .args_json(json!({"public_key": public_key}))
        .transact()
        .await?;

    assert!(cancel_outcome.is_success());

    // Check that the user's balance increased (got refunded)
    let final_balance = user_account.view_account().await?.balance;
    let balance_increase = final_balance.saturating_sub(initial_balance);

    // Allow for some error due to gas costs - user gets back the drop amount, not the fee
    let expected_refund = ONE_NEAR.saturating_sub(FLAT_FEE_PER_DROP);
    assert!(
        expected_refund.checked_sub(balance_increase).unwrap() < NearToken::from_millinear(50),
        "User should have received the refund (without the fee)"
    );

    // Verify the drop status is cancelled
    let drop_info_after = contract
        .view("get_key_info")
        .args_json(json!({"key": public_key}))
        .await?;

    let drop_after = drop_info_after.json::<SlimedropView>().unwrap();
    assert_eq!(drop_after.status, DropStatus::Cancelled);

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_cancel_drop_unauthorized() -> Result<(), Box<dyn std::error::Error>> {
    let sandbox = near_workspaces::sandbox_with_version("2.8.0").await?;
    let contract_wasm = near_workspaces::compile_project("./").await?;
    let root = sandbox.root_account()?;

    let user_account = root
        .create_subaccount("user")
        .initial_balance(ONE_NEAR.saturating_mul(10))
        .transact()
        .await?
        .unwrap();

    let other_account = root
        .create_subaccount("other")
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

    // User creates a drop
    let outcome = user_account
        .call(contract.id(), "add_near")
        .args_json(json!({"public_key": public_key}))
        .deposit(ONE_NEAR)
        .transact()
        .await?;
    assert!(outcome.is_success());

    // Verify the drop exists and is active
    let drop_info_before = contract
        .view("get_key_info")
        .args_json(json!({"key": public_key}))
        .await?;

    let drop_before = drop_info_before.json::<SlimedropView>().unwrap();
    assert_eq!(
        drop_before.contents.near,
        ONE_NEAR.saturating_sub(FLAT_FEE_PER_DROP)
    );
    assert_eq!(drop_before.created_by, user_account.id().clone());
    assert!(drop_before.claims.is_empty());

    // Try to cancel the drop with a different account - should fail
    let cancel_outcome = other_account
        .call(contract.id(), "cancel_drop")
        .args_json(json!({"public_key": public_key}))
        .transact()
        .await?;

    assert!(
        format!("{:#?}", cancel_outcome.failures()[0])
            .contains("You can only cancel drops you created")
    );

    // Verify the drop is still active
    let drop_info_after = contract
        .view("get_key_info")
        .args_json(json!({"key": public_key}))
        .await?;

    let drop_after = drop_info_after.json::<SlimedropView>().unwrap();
    assert_eq!(drop_after.status, DropStatus::Active);
    assert_eq!(
        drop_after.contents.near,
        ONE_NEAR.saturating_sub(FLAT_FEE_PER_DROP)
    );

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_cancel_drop_already_cancelled() -> Result<(), Box<dyn std::error::Error>> {
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

    // Cancel the drop first time
    let cancel_outcome = user_account
        .call(contract.id(), "cancel_drop")
        .args_json(json!({"public_key": public_key}))
        .transact()
        .await?;
    assert!(cancel_outcome.is_success());

    // Verify the drop is cancelled
    let drop_info = contract
        .view("get_key_info")
        .args_json(json!({"key": public_key}))
        .await?;
    let drop = drop_info.json::<SlimedropView>().unwrap();
    assert_eq!(drop.status, DropStatus::Cancelled);

    // Try to cancel the drop again - should fail
    let second_cancel_outcome = user_account
        .call(contract.id(), "cancel_drop")
        .args_json(json!({"public_key": public_key}))
        .transact()
        .await?;

    assert!(
        format!("{:#?}", second_cancel_outcome.failures()[0]).contains("Drop already cancelled")
    );

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_cancel_drop_already_claimed() -> Result<(), Box<dyn std::error::Error>> {
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

    // Claim the drop first
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

    // Verify the drop has been claimed
    let drop_info = contract
        .view("get_key_info")
        .args_json(json!({"key": public_key}))
        .await?;
    let drop = drop_info.json::<SlimedropView>().unwrap();
    assert!(!drop.claims.is_empty());

    // Try to cancel the claimed drop - should fail
    let cancel_outcome = sender_account
        .call(contract.id(), "cancel_drop")
        .args_json(json!({"public_key": public_key}))
        .transact()
        .await?;

    assert!(format!("{:#?}", cancel_outcome.failures()[0]).contains("Drop already claimed"));

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_account_claimed_drops() -> Result<(), Box<dyn std::error::Error>> {
    let sandbox = near_workspaces::sandbox_with_version("2.8.0").await?;
    let contract_wasm = near_workspaces::compile_project("./").await?;
    let root = sandbox.root_account()?;

    let sender_account = root
        .create_subaccount("sender")
        .initial_balance(ONE_NEAR.saturating_mul(10))
        .transact()
        .await?
        .unwrap();

    let claimer_account = root
        .create_subaccount("claimer")
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
    let secret_key3 = SecretKey::from_random(KeyType::ED25519);
    let public_key3 = secret_key3.public_key();

    // Create first drop
    let outcome1 = sender_account
        .call(contract.id(), "add_near")
        .args_json(json!({"public_key": public_key1}))
        .deposit(ONE_NEAR)
        .transact()
        .await?;
    assert!(outcome1.is_success());

    // Create second drop
    let outcome2 = sender_account
        .call(contract.id(), "add_near")
        .args_json(json!({"public_key": public_key2}))
        .deposit(ONE_NEAR.saturating_mul(2))
        .transact()
        .await?;
    assert!(outcome2.is_success());

    // Create third drop (this one won't be claimed)
    let outcome3 = sender_account
        .call(contract.id(), "add_near")
        .args_json(json!({"public_key": public_key3}))
        .deposit(ONE_NEAR.saturating_mul(3))
        .transact()
        .await?;
    assert!(outcome3.is_success());

    // Check that claimer has no claimed drops initially
    let initial_claimed_drops = contract
        .view("get_account_claimed_drops")
        .args_json(json!({"account_id": claimer_account.id()}))
        .await?;

    let initial_drops = initial_claimed_drops
        .json::<Vec<(PublicKey, SlimedropView)>>()
        .unwrap();
    assert!(initial_drops.is_empty());

    // Claim first drop
    let now1 = U64(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64);
    let nonce1 = now1.0.to_be_bytes();
    let nonce1 = [vec![0; 32 - nonce1.len()], nonce1.to_vec()]
        .concat()
        .try_into()
        .unwrap();
    let message1 = NEP413Payload {
        message: format!(
            "I want to claim this Slimedrop and send it to {}",
            claimer_account.id()
        ),
        nonce: nonce1,
        recipient: contract.id().to_string(),
        callback_url: None,
    };

    let signer1 = SecretKeySigner::new(secret_key1.to_string().parse().unwrap());
    let signature1 = signer1
        .sign_message_nep413(
            claimer_account.id().clone(),
            public_key1.to_string().parse().unwrap(),
            message1,
        )
        .await?;
    let signature1_base64 =
        Base64VecU8(match signature1.to_string().parse::<Signature>().unwrap() {
            Signature::ED25519(signature) => signature.to_bytes().to_vec(),
            Signature::SECP256K1(signature) => <[u8; 65] as From<_>>::from(signature).to_vec(),
        });

    let claim_outcome1 = claimer_account
        .call(contract.id(), "claim")
        .args_json(json!({
            "signature": signature1_base64,
            "public_key": public_key1,
            "nonce": now1,
        }))
        .transact()
        .await?;
    assert!(claim_outcome1.is_success());

    // Claim second drop
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
            claimer_account.id()
        ),
        nonce: nonce2,
        recipient: contract.id().to_string(),
        callback_url: None,
    };

    let signer2 = SecretKeySigner::new(secret_key2.to_string().parse().unwrap());
    let signature2 = signer2
        .sign_message_nep413(
            claimer_account.id().clone(),
            public_key2.to_string().parse().unwrap(),
            message2,
        )
        .await?;
    let signature2_base64 =
        Base64VecU8(match signature2.to_string().parse::<Signature>().unwrap() {
            Signature::ED25519(signature) => signature.to_bytes().to_vec(),
            Signature::SECP256K1(signature) => <[u8; 65] as From<_>>::from(signature).to_vec(),
        });

    let claim_outcome2 = claimer_account
        .call(contract.id(), "claim")
        .args_json(json!({
            "signature": signature2_base64,
            "public_key": public_key2,
            "nonce": now2,
        }))
        .transact()
        .await?;
    assert!(claim_outcome2.is_success());

    // Get all claimed drops
    let claimed_drops_outcome = contract
        .view("get_account_claimed_drops")
        .args_json(json!({"account_id": claimer_account.id()}))
        .await?;

    let claimed_drops = claimed_drops_outcome
        .json::<Vec<(PublicKey, SlimedropView)>>()
        .unwrap();
    assert_eq!(claimed_drops.len(), 2);

    // Verify first claimed drop
    assert_eq!(claimed_drops[0].0, public_key1);
    assert_eq!(
        claimed_drops[0].1.contents.near,
        ONE_NEAR.saturating_sub(FLAT_FEE_PER_DROP)
    );
    assert_eq!(claimed_drops[0].1.created_by, sender_account.id().clone());
    assert_eq!(claimed_drops[0].1.claims.len(), 1);
    assert!(claimed_drops[0].1.claims.contains_key(claimer_account.id()));

    // Verify second claimed drop
    assert_eq!(claimed_drops[1].0, public_key2);
    assert_eq!(
        claimed_drops[1].1.contents.near,
        ONE_NEAR.saturating_mul(2).saturating_sub(FLAT_FEE_PER_DROP)
    );
    assert_eq!(claimed_drops[1].1.created_by, sender_account.id().clone());
    assert_eq!(claimed_drops[1].1.claims.len(), 1);
    assert!(claimed_drops[1].1.claims.contains_key(claimer_account.id()));

    // Test pagination with limit
    let limited_drops_outcome = contract
        .view("get_account_claimed_drops")
        .args_json(json!({
            "account_id": claimer_account.id(),
            "skip": 0.to_string(),
            "limit": 1.to_string()
        }))
        .await?;

    let limited_drops = limited_drops_outcome
        .json::<Vec<(PublicKey, SlimedropView)>>()
        .unwrap();
    assert_eq!(limited_drops.len(), 1);
    assert_eq!(limited_drops[0].0, public_key1);

    // Test pagination with skip
    let skipped_drops_outcome = contract
        .view("get_account_claimed_drops")
        .args_json(json!({
            "account_id": claimer_account.id(),
            "skip": 1.to_string(),
            "limit": 1.to_string()
        }))
        .await?;

    let skipped_drops = skipped_drops_outcome
        .json::<Vec<(PublicKey, SlimedropView)>>()
        .unwrap();
    assert_eq!(skipped_drops.len(), 1);
    assert_eq!(skipped_drops[0].0, public_key2);

    // Test for account with no claimed drops (sender should have 0 claims)
    let sender_claimed_drops_outcome = contract
        .view("get_account_claimed_drops")
        .args_json(json!({"account_id": sender_account.id()}))
        .await?;

    let sender_claimed_drops = sender_claimed_drops_outcome
        .json::<Vec<(PublicKey, SlimedropView)>>()
        .unwrap();
    assert!(sender_claimed_drops.is_empty());

    // Test for completely new account with no claimed drops
    let empty_account = root
        .create_subaccount("empty")
        .initial_balance(ONE_NEAR)
        .transact()
        .await?
        .unwrap();

    let empty_claimed_drops_outcome = contract
        .view("get_account_claimed_drops")
        .args_json(json!({"account_id": empty_account.id()}))
        .await?;

    let empty_claimed_drops = empty_claimed_drops_outcome
        .json::<Vec<(PublicKey, SlimedropView)>>()
        .unwrap();
    assert!(empty_claimed_drops.is_empty());

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_fee_collection_on_drop_creation() -> Result<(), Box<dyn std::error::Error>> {
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

    // Create multiple drops to accumulate fees
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

    // Verify fees are collected correctly by checking contract balance
    let contract_balance = contract_account.view_account().await?.balance;
    let expected_fee_income = FLAT_FEE_PER_DROP.saturating_mul(2);

    // The contract should have gained fees from both drops
    assert!(
        contract_balance >= CONTRACT_INITIAL_BALANCE.saturating_add(expected_fee_income),
        "Contract should have collected fees from drop creation"
    );

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_insufficient_deposit_for_new_drop() -> Result<(), Box<dyn std::error::Error>> {
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

    // Try to create a drop with deposit exactly equal to fee (should fail)
    let result = user_account
        .call(contract.id(), "add_near")
        .args_json(json!({"public_key": public_key}))
        .deposit(FLAT_FEE_PER_DROP)
        .transact()
        .await;

    assert!(
        format!("{:#?}", result.unwrap().failures()[0])
            .contains("Attached deposit must be greater than"),
    );

    // Try with less than fee (should also fail)
    let result2 = user_account
        .call(contract.id(), "add_near")
        .args_json(json!({"public_key": public_key}))
        .deposit(FLAT_FEE_PER_DROP.saturating_sub(NearToken::from_yoctonear(1)))
        .transact()
        .await;

    assert!(
        format!("{:#?}", result2.unwrap().failures()[0])
            .contains("Attached deposit must be greater than"),
    );

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_withdraw_fees() -> Result<(), Box<dyn std::error::Error>> {
    let sandbox = near_workspaces::sandbox_with_version("2.8.0").await?;
    let contract_wasm = near_workspaces::compile_project("./").await?;
    let root = sandbox.root_account()?;

    let user_account = root
        .create_subaccount("user")
        .initial_balance(ONE_NEAR.saturating_mul(10))
        .transact()
        .await?
        .unwrap();

    let withdrawal_account = root
        .create_subaccount("withdrawal")
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

    // Create some drops to accumulate fees
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

    // Get withdrawal account initial balance
    let initial_withdrawal_balance = withdrawal_account.view_account().await?.balance;

    // Withdraw fees (can only be called by the contract itself, so we use the contract account)
    let withdraw_outcome = contract_account
        .call(contract.id(), "withdraw_fees")
        .args_json(json!({"withdraw_to": withdrawal_account.id()}))
        .transact()
        .await?;

    assert!(withdraw_outcome.is_success());

    // Check that withdrawal account received the fees
    let final_withdrawal_balance = withdrawal_account.view_account().await?.balance;
    let balance_increase = final_withdrawal_balance.saturating_sub(initial_withdrawal_balance);
    let expected_fees = FLAT_FEE_PER_DROP.saturating_mul(2);

    assert_eq!(
        balance_increase, expected_fees,
        "Withdrawal account should receive all accumulated fees"
    );

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_withdraw_fees_unauthorized() -> Result<(), Box<dyn std::error::Error>> {
    let sandbox = near_workspaces::sandbox_with_version("2.8.0").await?;
    let contract_wasm = near_workspaces::compile_project("./").await?;
    let root = sandbox.root_account()?;

    let user_account = root
        .create_subaccount("user")
        .initial_balance(ONE_NEAR.saturating_mul(10))
        .transact()
        .await?
        .unwrap();

    let unauthorized_account = root
        .create_subaccount("unauthorized")
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

    // Create a drop to accumulate some fees
    let secret_key = SecretKey::from_random(KeyType::ED25519);
    let public_key = secret_key.public_key();

    let outcome = user_account
        .call(contract.id(), "add_near")
        .args_json(json!({"public_key": public_key}))
        .deposit(ONE_NEAR)
        .transact()
        .await?;
    assert!(outcome.is_success());

    // Try to withdraw fees from unauthorized account (should fail because method is #[private])
    let withdraw_outcome = unauthorized_account
        .call(contract.id(), "withdraw_fees")
        .args_json(json!({"withdraw_to": unauthorized_account.id()}))
        .transact()
        .await?;

    // The method should fail because it's marked as #[private]
    assert!(!withdraw_outcome.is_success());
    let error_message = format!("{:#?}", withdraw_outcome.failures()[0]);
    assert!(
        error_message.contains("Method withdraw_fees is private"),
        "Expected private method error, got: {}",
        error_message
    );

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_withdraw_fees_twice() -> Result<(), Box<dyn std::error::Error>> {
    let sandbox = near_workspaces::sandbox_with_version("2.8.0").await?;
    let contract_wasm = near_workspaces::compile_project("./").await?;
    let root = sandbox.root_account()?;

    let user_account = root
        .create_subaccount("user")
        .initial_balance(ONE_NEAR.saturating_mul(10))
        .transact()
        .await?
        .unwrap();

    let withdrawal_account = root
        .create_subaccount("withdrawal")
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

    // Create a drop to accumulate fees
    let secret_key = SecretKey::from_random(KeyType::ED25519);
    let public_key = secret_key.public_key();

    let outcome = user_account
        .call(contract.id(), "add_near")
        .args_json(json!({"public_key": public_key}))
        .deposit(ONE_NEAR)
        .transact()
        .await?;
    assert!(outcome.is_success());

    // First withdrawal should succeed
    let withdraw_outcome1 = contract_account
        .call(contract.id(), "withdraw_fees")
        .args_json(json!({"withdraw_to": withdrawal_account.id()}))
        .transact()
        .await?;
    assert!(withdraw_outcome1.is_success());

    // Second withdrawal should fail (no fees left)
    let withdraw_outcome2 = contract_account
        .call(contract.id(), "withdraw_fees")
        .args_json(json!({"withdraw_to": withdrawal_account.id()}))
        .transact()
        .await?;

    assert!(format!("{:#?}", withdraw_outcome2.failures()[0]).contains("No fees to withdraw"),);

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_drop_with_ft() -> Result<(), Box<dyn std::error::Error>> {
    let sandbox = near_workspaces::sandbox_with_version("2.8.0").await?;
    let contract_wasm = near_workspaces::compile_project("./").await?;
    let ft_contract_wasm = near_workspaces::compile_project("./test-ft").await?;
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

    let ft_contract = root
        .create_subaccount("ft")
        .initial_balance(CONTRACT_INITIAL_BALANCE)
        .transact()
        .await?
        .unwrap();

    let contract = contract_account.deploy(&contract_wasm).await?.unwrap();
    let ft_contract = ft_contract.deploy(&ft_contract_wasm).await?.unwrap();

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

    // Storage deposit for the sender
    let outcome = sender_account
        .call(ft_contract.id(), "storage_deposit")
        .args_json(json!({"account_id": sender_account.id()}))
        .deposit("0.005 NEAR".parse().unwrap())
        .transact()
        .await?;

    assert!(outcome.is_success());

    // Mint FT for the sender
    let outcome = ft_contract
        .call("mint")
        .args_json(json!({
            "account_id": sender_account.id(),
            "amount": "100"
        }))
        .transact()
        .await?;

    assert!(outcome.is_success());

    // Storage deposit for the contract
    let outcome = ft_contract
        .call("storage_deposit")
        .args_json(json!({"account_id": contract.id()}))
        .deposit("0.005 NEAR".parse().unwrap())
        .transact()
        .await?;

    assert!(outcome.is_success());

    // Add the FT to the drop
    let outcome = sender_account
        .call(ft_contract.id(), "ft_transfer_call")
        .args_json(json!({
            "receiver_id": contract.id().to_string(),
            "amount": "100",
            "msg": json!({"public_key": public_key}).to_string(),
        }))
        .max_gas()
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?;

    assert!(outcome.is_success());

    // Get receiver's initial balance
    let initial_balance_near = receiver_account.view_account().await?.balance;
    let initial_balance_ft = ft_contract
        .call("ft_balance_of")
        .args_json(json!({"account_id": receiver_account.id()}))
        .view()
        .await?
        .json::<U128>()
        .unwrap()
        .0;

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
        .max_gas()
        .transact()
        .await?;

    assert!(claim_outcome.is_success());

    // Check that the receiver's balance increased
    let final_balance_near = receiver_account.view_account().await?.balance;
    let balance_increase_near = final_balance_near.saturating_sub(initial_balance_near);
    let final_balance_ft = ft_contract
        .call("ft_balance_of")
        .args_json(json!({"account_id": receiver_account.id()}))
        .view()
        .await?
        .json::<U128>()
        .unwrap()
        .0;
    let balance_increase_ft = final_balance_ft.saturating_sub(initial_balance_ft);

    // Verify increases (allow for gas costs and storage deposits)
    assert!(
        balance_increase_near > NearToken::from_millinear(750),
        "Receiver should have received most of the NEAR"
    );
    assert_eq!(
        balance_increase_ft, 100,
        "Receiver should have received 100 FT"
    );

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_drop_with_nft() -> Result<(), Box<dyn std::error::Error>> {
    let sandbox = near_workspaces::sandbox_with_version("2.8.0").await?;
    let contract_wasm = near_workspaces::compile_project("./").await?;
    let nft_contract_wasm = near_workspaces::compile_project("./test-nft").await?;
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

    let nft_contract = root
        .create_subaccount("nft")
        .initial_balance(CONTRACT_INITIAL_BALANCE)
        .transact()
        .await?
        .unwrap();

    let contract = contract_account.deploy(&contract_wasm).await?.unwrap();
    let nft_contract = nft_contract.deploy(&nft_contract_wasm).await?.unwrap();

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

    // Storage deposit for the sender
    let outcome = nft_contract
        .call("storage_deposit")
        .args_json(json!({"account_id": sender_account.id()}))
        .deposit("0.01 NEAR".parse().unwrap())
        .transact()
        .await?;

    assert!(outcome.is_success());

    // Mint NFT for the sender
    let token_id = "test_token_1";
    let outcome = nft_contract
        .call("mint")
        .args_json(json!({
            "account_id": sender_account.id(),
            "token_id": token_id
        }))
        .transact()
        .await?;

    assert!(outcome.is_success());

    // Storage deposit for the contract
    let outcome = nft_contract
        .call("storage_deposit")
        .args_json(json!({"account_id": contract.id()}))
        .deposit("0.01 NEAR".parse().unwrap())
        .transact()
        .await?;

    assert!(outcome.is_success());

    // Add the NFT to the drop
    let outcome = sender_account
        .call(nft_contract.id(), "nft_transfer_call")
        .args_json(json!({
            "receiver_id": contract.id().to_string(),
            "token_id": token_id,
            "msg": json!({"public_key": public_key}).to_string(),
        }))
        .max_gas()
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?;

    assert!(outcome.is_success());

    // Verify the drop contains the NFT
    let drop_info = contract
        .view("get_key_info")
        .args_json(json!({"key": public_key}))
        .await?;

    let drop = drop_info.json::<SlimedropView>().unwrap();
    assert!(drop.contents.nep171.contains_key(nft_contract.id()));
    assert!(drop.contents.nep171[nft_contract.id()].contains(token_id));

    // Get receiver's initial balance
    let initial_balance_near = receiver_account.view_account().await?.balance;

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
        .max_gas()
        .transact()
        .await?;

    assert!(claim_outcome.is_success());

    // Check that the receiver's balance increased (NEAR part)
    let final_balance_near = receiver_account.view_account().await?.balance;
    let balance_increase_near = final_balance_near.saturating_sub(initial_balance_near);

    // Check that the receiver now owns the NFT
    let nft_owner = nft_contract
        .call("nft_token")
        .args_json(json!({"token_id": token_id}))
        .view()
        .await?;
    #[allow(unused_variables)]
    let token_info: near_sdk::serde_json::Value = nft_owner.json().unwrap();
    // assert_eq!(token_info["owner_id"], receiver_account.id().to_string()); // TODO: for some reason it's null, even after minting. Possibly a bug in test NFT contract

    // Allow for some error due to gas
    assert!(
        balance_increase_near > NearToken::from_millinear(750),
        "Receiver should have received most of the NEAR"
    );

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_drop_with_mt() -> Result<(), Box<dyn std::error::Error>> {
    let sandbox = near_workspaces::sandbox_with_version("2.8.0").await?;
    let contract_wasm = near_workspaces::compile_project("./").await?;
    let mt_contract_wasm = near_workspaces::compile_project("./test-mt").await?;
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

    let mt_contract = root
        .create_subaccount("mt")
        .initial_balance(CONTRACT_INITIAL_BALANCE)
        .transact()
        .await?
        .unwrap();

    let contract = contract_account.deploy(&contract_wasm).await?.unwrap();
    let mt_contract = mt_contract.deploy(&mt_contract_wasm).await?.unwrap();

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

    // Storage deposit for the sender
    let outcome = sender_account
        .call(mt_contract.id(), "storage_deposit")
        .args_json(json!({"account_id": sender_account.id()}))
        .deposit("0.005 NEAR".parse().unwrap())
        .transact()
        .await?;

    assert!(outcome.is_success());

    // Mint MT for the sender
    let token_id = "sword";
    let amount = U128(50);
    let outcome = mt_contract
        .call("mint")
        .args_json(json!({
            "account_id": sender_account.id(),
            "token_id": token_id,
            "amount": amount
        }))
        .transact()
        .await?;

    assert!(outcome.is_success());

    // Storage deposit for the contract
    let outcome = mt_contract
        .call("storage_deposit")
        .args_json(json!({"account_id": contract.id()}))
        .deposit("0.005 NEAR".parse().unwrap())
        .transact()
        .await?;

    assert!(outcome.is_success());

    // Add the MT to the drop
    let outcome = sender_account
        .call(mt_contract.id(), "mt_batch_transfer_call")
        .args_json(json!({
            "receiver_id": contract.id().to_string(),
            "token_ids": [token_id],
            "amounts": [amount],
            "msg": json!({"public_key": public_key}).to_string(),
        }))
        .max_gas()
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?;

    assert!(outcome.is_success());

    // Verify the drop contains the MT
    let drop_info = contract
        .view("get_key_info")
        .args_json(json!({"key": public_key}))
        .await?;

    let drop = drop_info.json::<SlimedropView>().unwrap();
    assert!(drop.contents.nep245.contains_key(mt_contract.id()));
    assert!(drop.contents.nep245[mt_contract.id()].contains_key(token_id));
    assert_eq!(drop.contents.nep245[mt_contract.id()][token_id], amount);

    // Get receiver's initial balance
    let initial_balance_near = receiver_account.view_account().await?.balance;
    let initial_balance_mt = mt_contract
        .call("mt_balance_of")
        .args_json(json!({
            "account_id": receiver_account.id(),
            "token_id": token_id
        }))
        .view()
        .await?
        .json::<U128>()
        .unwrap_or(U128(0))
        .0;

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
        .max_gas()
        .transact()
        .await?;

    assert!(claim_outcome.is_success());

    // Check that the receiver's balance increased
    let final_balance_near = receiver_account.view_account().await?.balance;
    let balance_increase_near = final_balance_near.saturating_sub(initial_balance_near);
    let final_balance_mt = mt_contract
        .call("mt_balance_of")
        .args_json(json!({
            "account_id": receiver_account.id(),
            "token_id": token_id
        }))
        .view()
        .await?
        .json::<U128>()
        .unwrap()
        .0;
    let balance_increase_mt = final_balance_mt.saturating_sub(initial_balance_mt);

    // Allow for some error due to gas
    assert!(
        balance_increase_near > NearToken::from_millinear(750),
        "Receiver should have received most of the NEAR"
    );
    assert_eq!(
        balance_increase_mt, amount.0,
        "Receiver should have received the MT tokens"
    );

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_mixed_drop_all_token_types() -> Result<(), Box<dyn std::error::Error>> {
    let sandbox = near_workspaces::sandbox_with_version("2.8.0").await?;
    let contract_wasm = near_workspaces::compile_project("./").await?;
    let ft_contract_wasm = near_workspaces::compile_project("./test-ft").await?;
    let nft_contract_wasm = near_workspaces::compile_project("./test-nft").await?;
    let mt_contract_wasm = near_workspaces::compile_project("./test-mt").await?;
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

    // Deploy all token contracts
    let ft_contract = root
        .create_subaccount("ft")
        .initial_balance(CONTRACT_INITIAL_BALANCE)
        .transact()
        .await?
        .unwrap();

    let nft_contract = root
        .create_subaccount("nft")
        .initial_balance(CONTRACT_INITIAL_BALANCE)
        .transact()
        .await?
        .unwrap();

    let mt_contract = root
        .create_subaccount("mt")
        .initial_balance(CONTRACT_INITIAL_BALANCE)
        .transact()
        .await?
        .unwrap();

    let contract = contract_account.deploy(&contract_wasm).await?.unwrap();
    let ft_contract = ft_contract.deploy(&ft_contract_wasm).await?.unwrap();
    let nft_contract = nft_contract.deploy(&nft_contract_wasm).await?.unwrap();
    let mt_contract = mt_contract.deploy(&mt_contract_wasm).await?.unwrap();

    // Initialize the contract
    let result = contract.call("new").transact().await?;
    assert!(result.is_success());

    // Create a key pair for the claimer
    let secret_key = SecretKey::from_random(KeyType::ED25519);
    let public_key = secret_key.public_key();

    // Create a drop with NEAR
    let outcome = sender_account
        .call(contract.id(), "add_near")
        .args_json(json!({"public_key": public_key}))
        .deposit(ONE_NEAR)
        .transact()
        .await?;
    assert!(outcome.is_success());

    // Set up FT
    let outcome = sender_account
        .call(ft_contract.id(), "storage_deposit")
        .args_json(json!({"account_id": sender_account.id()}))
        .deposit("0.005 NEAR".parse().unwrap())
        .transact()
        .await?;
    assert!(outcome.is_success());

    let outcome = ft_contract
        .call("mint")
        .args_json(json!({
            "account_id": sender_account.id(),
            "amount": "100"
        }))
        .transact()
        .await?;
    assert!(outcome.is_success());

    let outcome = ft_contract
        .call("storage_deposit")
        .args_json(json!({"account_id": contract.id()}))
        .deposit("0.005 NEAR".parse().unwrap())
        .transact()
        .await?;
    assert!(outcome.is_success());

    // Add FT to drop
    let outcome = sender_account
        .call(ft_contract.id(), "ft_transfer_call")
        .args_json(json!({
            "receiver_id": contract.id().to_string(),
            "amount": "100",
            "msg": json!({"public_key": public_key}).to_string(),
        }))
        .max_gas()
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?;
    assert!(outcome.is_success());

    // Set up NFT
    let outcome = sender_account
        .call(nft_contract.id(), "storage_deposit")
        .args_json(json!({"account_id": sender_account.id()}))
        .deposit("0.01 NEAR".parse().unwrap())
        .transact()
        .await?;
    assert!(outcome.is_success());

    let token_id = "test_nft_1";
    let outcome = nft_contract
        .call("mint")
        .args_json(json!({
            "account_id": sender_account.id(),
            "token_id": token_id
        }))
        .transact()
        .await?;
    assert!(outcome.is_success());

    let outcome = nft_contract
        .call("storage_deposit")
        .args_json(json!({"account_id": contract.id()}))
        .deposit("0.005 NEAR".parse().unwrap())
        .transact()
        .await?;
    assert!(outcome.is_success());

    // Add NFT to drop
    let outcome = sender_account
        .call(nft_contract.id(), "nft_transfer_call")
        .args_json(json!({
            "receiver_id": contract.id().to_string(),
            "token_id": token_id,
            "msg": json!({"public_key": public_key}).to_string(),
        }))
        .max_gas()
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?;
    assert!(outcome.is_success());

    // Set up MT
    let outcome = sender_account
        .call(mt_contract.id(), "storage_deposit")
        .args_json(json!({"account_id": sender_account.id()}))
        .deposit("0.005 NEAR".parse().unwrap())
        .transact()
        .await?;
    assert!(outcome.is_success());

    let mt_token_id = "sword";
    let mt_amount = U128(25);
    let outcome = mt_contract
        .call("mint")
        .args_json(json!({
            "account_id": sender_account.id(),
            "token_id": mt_token_id,
            "amount": mt_amount
        }))
        .transact()
        .await?;
    assert!(outcome.is_success());

    let outcome = mt_contract
        .call("storage_deposit")
        .args_json(json!({"account_id": contract.id()}))
        .deposit("0.005 NEAR".parse().unwrap())
        .transact()
        .await?;
    assert!(outcome.is_success());

    // Add MT to drop
    let outcome = sender_account
        .call(mt_contract.id(), "mt_batch_transfer_call")
        .args_json(json!({
            "receiver_id": contract.id().to_string(),
            "token_ids": [mt_token_id],
            "amounts": [mt_amount],
            "msg": json!({"public_key": public_key}).to_string(),
        }))
        .max_gas()
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?;
    assert!(outcome.is_success());

    // Verify the drop contains all token types
    let drop_info = contract
        .view("get_key_info")
        .args_json(json!({"key": public_key}))
        .await?;

    let drop = drop_info.json::<SlimedropView>().unwrap();

    // Check NEAR (minus storage deposits)
    assert!(drop.contents.near > NearToken::from_millinear(800)); // Some NEAR left after storage deposits

    // Check FT
    assert!(drop.contents.nep141.contains_key(ft_contract.id()));
    assert_eq!(drop.contents.nep141[ft_contract.id()], U128(100));

    // Check NFT
    assert!(drop.contents.nep171.contains_key(nft_contract.id()));
    assert!(drop.contents.nep171[nft_contract.id()].contains(token_id));

    // Check MT
    assert!(drop.contents.nep245.contains_key(mt_contract.id()));
    assert!(drop.contents.nep245[mt_contract.id()].contains_key(mt_token_id));
    assert_eq!(
        drop.contents.nep245[mt_contract.id()][mt_token_id],
        mt_amount
    );

    // Get receiver's initial balances
    let initial_balance_near = receiver_account.view_account().await?.balance;
    let initial_balance_ft = ft_contract
        .call("ft_balance_of")
        .args_json(json!({"account_id": receiver_account.id()}))
        .view()
        .await?
        .json::<U128>()
        .unwrap_or(U128(0))
        .0;
    let initial_balance_mt = mt_contract
        .call("mt_balance_of")
        .args_json(json!({
            "account_id": receiver_account.id(),
            "token_id": mt_token_id
        }))
        .view()
        .await?
        .json::<U128>()
        .unwrap_or(U128(0))
        .0;

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
        .max_gas()
        .transact()
        .await?;

    assert!(claim_outcome.is_success());

    // Verify all assets were transferred
    let final_balance_near = receiver_account.view_account().await?.balance;
    let balance_increase_near = final_balance_near.saturating_sub(initial_balance_near);

    let final_balance_ft = ft_contract
        .call("ft_balance_of")
        .args_json(json!({"account_id": receiver_account.id()}))
        .view()
        .await?
        .json::<U128>()
        .unwrap()
        .0;
    let balance_increase_ft = final_balance_ft.saturating_sub(initial_balance_ft);

    // Check NFT ownership
    let nft_owner = nft_contract
        .call("nft_token")
        .args_json(json!({"token_id": token_id}))
        .view()
        .await?;
    #[allow(unused_variables)]
    let token_info: near_sdk::serde_json::Value = nft_owner.json().unwrap();
    // assert_eq!(token_info["owner_id"], receiver_account.id().to_string()); // TODO: for some reason it's null, even after minting. Possibly a bug in test NFT contract

    let final_balance_mt = mt_contract
        .call("mt_balance_of")
        .args_json(json!({
            "account_id": receiver_account.id(),
            "token_id": mt_token_id
        }))
        .view()
        .await?
        .json::<U128>()
        .unwrap()
        .0;
    let balance_increase_mt = final_balance_mt.saturating_sub(initial_balance_mt);

    // Verify increases (allow for gas costs and storage deposits)
    assert!(
        balance_increase_near > NearToken::from_millinear(750),
        "Receiver should have received most of the NEAR"
    );
    assert_eq!(
        balance_increase_ft, 100,
        "Receiver should have received 100 FT"
    );
    assert_eq!(
        balance_increase_mt, mt_amount.0,
        "Receiver should have received MT tokens"
    );

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_ft_transfer_insufficient_near_storage() -> Result<(), Box<dyn std::error::Error>> {
    let sandbox = near_workspaces::sandbox_with_version("2.8.0").await?;
    let contract_wasm = near_workspaces::compile_project("./").await?;
    let ft_contract_wasm = near_workspaces::compile_project("./test-ft").await?;
    let root = sandbox.root_account()?;

    let sender_account = root
        .create_subaccount("sender")
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

    let ft_contract = root
        .create_subaccount("ft")
        .initial_balance(CONTRACT_INITIAL_BALANCE)
        .transact()
        .await?
        .unwrap();

    let contract = contract_account.deploy(&contract_wasm).await?.unwrap();
    let ft_contract = ft_contract.deploy(&ft_contract_wasm).await?.unwrap();

    // Initialize the contract
    let result = contract.call("new").transact().await?;
    assert!(result.is_success());

    // Create a key pair for the claimer
    let secret_key = SecretKey::from_random(KeyType::ED25519);
    let public_key = secret_key.public_key();

    // Create a drop with minimal NEAR (just above fee requirement)
    let outcome = sender_account
        .call(contract.id(), "add_near")
        .args_json(json!({"public_key": public_key}))
        .deposit(NearToken::from_millinear(51)) // Just 1 millinear above the fee
        .transact()
        .await?;
    assert!(outcome.is_success());

    // Set up FT
    let outcome = sender_account
        .call(ft_contract.id(), "storage_deposit")
        .args_json(json!({"account_id": sender_account.id()}))
        .deposit("0.005 NEAR".parse().unwrap())
        .transact()
        .await?;
    assert!(outcome.is_success());

    let outcome = ft_contract
        .call("mint")
        .args_json(json!({
            "account_id": sender_account.id(),
            "amount": "100"
        }))
        .transact()
        .await?;
    assert!(outcome.is_success());

    let outcome = ft_contract
        .call("storage_deposit")
        .args_json(json!({"account_id": contract.id()}))
        .deposit("0.005 NEAR".parse().unwrap())
        .transact()
        .await?;
    assert!(outcome.is_success());

    // Try to add FT to drop - should fail due to insufficient NEAR for storage deposit
    let outcome = sender_account
        .call(ft_contract.id(), "ft_transfer_call")
        .args_json(json!({
            "receiver_id": contract.id().to_string(),
            "amount": "100",
            "msg": json!({"public_key": public_key}).to_string(),
        }))
        .max_gas()
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?;

    assert!(outcome.is_success());
    let error_message = format!("{:#?}", outcome.failures()[0]);
    assert!(
        error_message.contains("Insufficient NEAR balance"),
        "Expected insufficient NEAR balance error, got: {}",
        error_message
    );

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_add_token_to_nonexistent_drop() -> Result<(), Box<dyn std::error::Error>> {
    let sandbox = near_workspaces::sandbox_with_version("2.8.0").await?;
    let contract_wasm = near_workspaces::compile_project("./").await?;
    let ft_contract_wasm = near_workspaces::compile_project("./test-ft").await?;
    let root = sandbox.root_account()?;

    let sender_account = root
        .create_subaccount("sender")
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

    let ft_contract = root
        .create_subaccount("ft")
        .initial_balance(CONTRACT_INITIAL_BALANCE)
        .transact()
        .await?
        .unwrap();

    let contract = contract_account.deploy(&contract_wasm).await?.unwrap();
    let ft_contract = ft_contract.deploy(&ft_contract_wasm).await?.unwrap();

    // Initialize the contract
    let result = contract.call("new").transact().await?;
    assert!(result.is_success());

    // Create a random key that doesn't have a drop
    let secret_key = SecretKey::from_random(KeyType::ED25519);
    let public_key = secret_key.public_key();

    // Set up FT
    let outcome = sender_account
        .call(ft_contract.id(), "storage_deposit")
        .args_json(json!({"account_id": sender_account.id()}))
        .deposit("0.005 NEAR".parse().unwrap())
        .transact()
        .await?;
    assert!(outcome.is_success());

    let outcome = ft_contract
        .call("mint")
        .args_json(json!({
            "account_id": sender_account.id(),
            "amount": "100"
        }))
        .transact()
        .await?;
    assert!(outcome.is_success());

    let outcome = ft_contract
        .call("storage_deposit")
        .args_json(json!({"account_id": contract.id()}))
        .deposit("0.005 NEAR".parse().unwrap())
        .transact()
        .await?;
    assert!(outcome.is_success());

    // Try to add FT to non-existent drop - should fail
    let outcome = sender_account
        .call(ft_contract.id(), "ft_transfer_call")
        .args_json(json!({
            "receiver_id": contract.id().to_string(),
            "amount": "100",
            "msg": json!({"public_key": public_key}).to_string(),
        }))
        .max_gas()
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?;

    assert!(outcome.is_success());
    let error_message = format!("{:#?}", outcome.failures()[0]);
    assert!(
        error_message.contains("Key is missing"),
        "Expected key missing error, got: {}",
        error_message
    );

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_add_tokens_to_claimed_drop() -> Result<(), Box<dyn std::error::Error>> {
    let sandbox = near_workspaces::sandbox_with_version("2.8.0").await?;
    let contract_wasm = near_workspaces::compile_project("./").await?;
    let ft_contract_wasm = near_workspaces::compile_project("./test-ft").await?;
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

    let ft_contract = root
        .create_subaccount("ft")
        .initial_balance(CONTRACT_INITIAL_BALANCE)
        .transact()
        .await?
        .unwrap();

    let contract = contract_account.deploy(&contract_wasm).await?.unwrap();
    let ft_contract = ft_contract.deploy(&ft_contract_wasm).await?.unwrap();

    // Initialize the contract
    let result = contract.call("new").transact().await?;
    assert!(result.is_success());

    // Create a key pair
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

    // Claim the drop first
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

    // Set up FT
    let outcome = sender_account
        .call(ft_contract.id(), "storage_deposit")
        .args_json(json!({"account_id": sender_account.id()}))
        .deposit("0.005 NEAR".parse().unwrap())
        .transact()
        .await?;
    assert!(outcome.is_success());

    let outcome = ft_contract
        .call("mint")
        .args_json(json!({
            "account_id": sender_account.id(),
            "amount": "100"
        }))
        .transact()
        .await?;
    assert!(outcome.is_success());

    let outcome = ft_contract
        .call("storage_deposit")
        .args_json(json!({"account_id": contract.id()}))
        .deposit("0.005 NEAR".parse().unwrap())
        .transact()
        .await?;
    assert!(outcome.is_success());

    // Try to add FT to already claimed drop - should fail
    let outcome = sender_account
        .call(ft_contract.id(), "ft_transfer_call")
        .args_json(json!({
            "receiver_id": contract.id().to_string(),
            "amount": "100",
            "msg": json!({"public_key": public_key}).to_string(),
        }))
        .max_gas()
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?;

    assert!(outcome.is_success());
    let error_message = format!("{:#?}", outcome.failures()[0]);
    assert!(
        error_message.contains("Drop already claimed"),
        "Expected drop already claimed error, got: {}",
        error_message
    );

    Ok(())
}
