# Vixify Blockchain

A modern pure Proof-of-Stake blockchain based on a verifiable delay functions (VDF) and a verifiable random function (VRF). 

[![Build Status](https://travis-ci.org/joemccann/dillinger.svg?branch=master)](https://travis-ci.org/joemccann/dillinger)

## Summary

Vixify is a blockchain adopting a pure Proof-of-Stake consensus protocol based on a verifiable random function (VRF) and a verifiable delay function (VDF) that has the following properties: a) all addresses with a positive stake can participate in consensus; b) is fair regarding the stake and the distribution of rewards; b) is tolerant to several classic attacks such as Sybil attacks, "Nothing-at-stake" attacks and "Winner-takes-all" attacks.

##  VDFs and VRFs (VXFs!)

Verifiable delays functions (VDFs) such as *Ht()* are essentialy cryptographic hash functions computing *t* steps of computation that cannot be paralelized but the computation can be verified much faster, or very fast. They have been proposed as solution to energy inefficient parallelizable Proof-of-Work consensus because of their non-paralelizable properties but they raised some concerns regading winner-takes-all scenarios for nodes with very fast specialized hardware, such as ASIC hardware. Under certain speed assumptions of the players we can handle the winner-takes-all scenarios, so we don't loose the fairness.

In more detail, a VDF that implements a function X → Y is a tuple of three algorithms [1]:
• Setup(λ, T) → pp is a randomized algorithm that takes a security parameter λ and a time
bound T, and outputs public parameters pp,
• Eval(pp, x) → (y, π) takes an input x ∈ X and outputs a y ∈ Y and a proof π.
• Verify(pp, x, y, π) → {accept, reject} outputs accept if y is the correct evaluation of the VDF
on input x.

Verifiable random functions (VRFs) such as *Hsk()* defined using a public-key pair *(sk, pk)* have the property that using a private key *sk* allows to hash a plain-text *s* into a hash *h* that can be verified using a public key *pk*.

VRFs are being popularized these days by the Algorand Blockchain project, although they use voting and do not use VDF as part of their consensus algorithm.

VRF syntax and properties are as follows [1]. A VRF is a triple of algorithms Keygen, Evaluate, and Verify:

 - Keygen(r) → (VK, SK). On a random input, the key generation algorithm produces a verification key VK and a secret key SK pair.
 - Evaluate(SK, X) → (Y, ⍴). The evaluation algorithm takes as input the secret key SK, a message X and produces a pseudorandom output string Y and a proof ⍴.
 - Verify(VK, X, Y, ⍴) → 0/1. The verification algorithm takes as input the verification key VK, the message X, the output Y and the proof ⍴. It outputs 1 if and only if it verifies that Y is the output produced by the evaluation algorithm on inputs SK and X.

### Tech

Vixify Blockchain has the following features:

* Proof-of-Stake - only stakeholders can participate in consensus and recieve rewards.
* Single-thread Mining - Using a VDF allow the blockchain with blocks mined on a single-thread by each stakeholder.
* Secure - Usgin a verifiable random function (VRF) allows next-block miner to be unpredictable, discouragin attacks on stakeholders nodes.
* Ethereum-compatible - Smart Contract build in Solidity have a huge community and support.
* Scaling - using reasonable bigger blocks and on-demand retrieval of accounts/contracts state will help scale any blockchain implementation.

### Installation

Vixify requires [Python ](https://python.org/) v3+ to run.

Install the dependencies and devDependencies and start the server.

```sh
$ cd bla
$ python install -d
$ bla bla
```

For production environments...

```sh

$ pip install 
$ blabl apython
```

### References

[1] Dan Boneh, Benedikt Bunz, Ben Fisch, "A Survey of Two Verifiable Delay Functions", August 22, 2018,  https://crypto.stanford.edu/~dabo/pubs/papers/VDFsurvey.pdf
