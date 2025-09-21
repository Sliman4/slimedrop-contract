# Slimedrop contract

> This is a fork of NEAR LinkDrops, which is not compatible with the NEP.

Slimedrop contract allows any user to create a link that their friends can use to claim tokens even if they don't have an account yet.

The way it works:

Sender, that has NEAR:
- Creates a new key pair `(pk1, privkey1)`.
- Calls `slimedrop.add_near(pk1)` with attached balance of NEAR that they want to send.
- Sends a link to any supported wallet app with `privkey1` as part of URL.

Receiver, that doesn't have NEAR:
- Receives link to the wallet with `privkey1`.
- Wallet creates new key pair for this user (or they generate it via HSM) `(pk2, privkey2)`.
- Enters the `new_account_id` receiver want for their new account.
- Wallet relayer creates user's account with `new_account_id` name, `pk2` as full access key, and `pk1` as function call key that can only claim Slimedrops.
- Wallet creates a transaction to `slimedrop.claim()` and wallet relayer sponsors it.
- Contract transfers tokens that Sender sent.
- Optionally, remove `pk1` functio ncall key.

If Receiver already has account (or Sender wants to get back the money):
- Temporarily add `pk1` as their function call key.
- Sign tx with `privkey1` to call `slimedrop.claim()`, which transfers money to signer's account.
- Optionally, remove `pk1` function call key.
