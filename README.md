# Formal Analysis of OpenID for Verifiable Presentations over BLE - draft 00

This repository contains the formal model and proofs for a slightly altered version of the [OpenID for Verifiable Presentations over BLE - draft 00](https://openid.net/specs/openid-4-verifiable-presentations-over-ble-1_0.html) specification (from now on simply "the spec").
We only prove a slightly altered version to be secure because we found the spec to be insecure during our analysis.
Thus, we propose two fixes.
In this README, we will stay brief and focus on the assumptions that we make in my formal model and proofs, and introduce the proposed fixes.

## Properties

We argue that the spec should provide the following two properties.

### Secrecy

> Whenever a wallet sends out a verifiable presentation, the adversary cannot obtain it, *unless* the receiving verifier is controlled by the adversary.

### Injective Agreement (Authentication)

> Whenever a verifier receives a presentation, then either:
>
> 1. It was sent by an honest wallet and intended for that verifier.
> Furthermore, (a) the verifier and honest wallet agree on the shared ECDH key, the wallets signing key, and the nonce, and (b) there is no other event in which some verifier accepts some presentation for the same nonce.
> 2. The wallet that signed the presentation was compromised.
> 3. The key that signed the presentation was generated by the adversary.

Two notes:

- (1.b) can intuitively be described as that no replay attacks are possible.
- (3) can be mitigated by authenticating the wallet's key, which, to my understanding, is mandated by other specifications anyways.

## Formal Model

Our formal proofs make the following assumptions:

- Cryptographic primitives are perfectly secure, e.g., one can only obtain the decryption of the message provided one knows the correct key, and all symmetric encryption is performed with an authenticated encryption scheme.
- The wallet can authenticate the signing key of the verifier.
- The verifier can authenticate the signing key of the wallet after the fact.
- The wallet uses a fresh ECDH ephemeral key for every connection.
- The verifier uses *some* fresh ECDH ephemeral key for connections.
They might reuse ephemeral keys among sessions.
- Honestly generated ephemeral keys can never be leaked to the adversary.

Furthermore, our model abstracts the connection setup phase of the protocol, especially when it comes to BLE.
The protocol starts with the verifier announcing an ephemeral ECDH key *somehow* and the wallet receives some ephemeral ECDH key *somehow*.
Note that his does not assume the announcement of the ephemeral key to be secure.
The key might be provided by the adversary.

We also skipped a model of the AuthN & AuthZ step in the protocol.
We argue that this is not critical as the most that can happen here is that the user aborts the protocol, which is a behavior that Tamarin captures.

## Proposed Changes

We propose two changes to the spec:

1. When the verifier sends their signed OpenID4VP request to the wallet, they include a hash of their ephemeral half-key in the request.
2. When the wallet sends a verifiable presentation to a verifier, they include a hash of their ephemeral half-key in the presentation.
For example, this could be achieved by using a hash of the nonce and their half-key as the nonce.

## Attacks Found

These changes are necessary because, otherwise, the request and presentation are not properly bound to the BLE channel.
An interceptor could forward an honest OpenID4VP request to obtain a presentation from a wallet, and forward this presentation to the verifier.
This attack violates both secrecy and authentication.

## Verifying the Proofs

To verify that the spec (with our proposed changes) indeed provides the security properties from above, you can verify our proofs.
For that, you must first [install Tamarin](https://tamarin-prover.github.io/manual/master/book/002_installation.html).

After you have installed Tamarin, you can check the proofs provided in this repository by running:

```sh
tamarin-prover proofs/proofs.spthy
```

Alternatively, you find the proofs yourself by running:

```sh
tamarin-prover --prove oid4vp-over-ble.spthy
```
