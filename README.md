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
- Wallet relayer creates user's account with `new_account_id` name and `pk2` as full access key.
- Wallet creates a transaction to `slimedrop.claim()` and wallet relayer sponsors it. The transaction argument includes signed `"I want to claim this Slimedrop"` or `"I want to claim this Slimedrop and send it to bob.near"` NEP-413 message with recipient `slimedrop` (contract account ID), and nonce is the current timestamp in big endian, which cannot be older than 5 minutes by the time the transaction is executed.
- Contract transfers tokens that Sender sent.

If Receiver already has account (or Sender wants to get back the money):
- Sign tx with `privkey1` to call `slimedrop.claim()` with same arguments, which transfers money to signer's account.
