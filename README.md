# Vixify Blockchain

A modern pure Proof-of-Stake blockchain based on a verifiable delay functions (VDF) and a verifiable random function (VRF). Implements a synthetic Proof-of-Work using the VDF and VRF based on coin stakes and non-parallelizable mining.

[![Build Status](https://travis-ci.org/joemccann/dillinger.svg?branch=master)](https://travis-ci.org/joemccann/dillinger)

## Summary

Vixify is a blockchain adopting a pure Proof-of-Stake consensus protocol based on a verifiable random function (VRF) and a verifiable delay function (VDF) that has the following properties: a) all addresses with a positive stake can participate in consensus; b) is fair regarding the stake and the distribution of rewards; b) is tolerant to several classic attacks such as Sybil attacks, "Nothing-at-stake" attacks and "Winner-takes-all" attacks.

## Blockchain Features

Vixify Blockchain has the following features:

* Proof-of-Stake - only stakeholders can participate in consensus and recieve rewards.
* Single-thread Mining - Using a VDF allow the blockchain with blocks mined on a single-thread by each stakeholder. Under certain chip technologies the design if secure (for example, no miner has a chip technology that is x3 or x4 faster than the current state of the art in commercial chips).
* Secure - Using a verifiable random function (VRF) allows next-block miner to be unpredictable, discouraging attacks on stakeholders nodes.
* Ethereum-compatible - Smart Contract build in Solidity have a huge community and support.
* Scaling - using reasonable bigger blocks and on-demand retrieval of accounts/contracts state will help scale any blockchain implementation.

## What are VDFs and VRFs (VXFs!)

Verifiable delays functions (VDFs) are essentialy cryptographic hash functions computing several steps of computation that cannot be paralelized but the computation can be verified much faster, or very fast. They have been proposed as solution to energy inefficient parallelizable Proof-of-Work consensus because of their non-paralelizable properties but they raised some concerns regading winner-takes-all scenarios for nodes with very fast specialized hardware, such as ASIC hardware. Under certain speed assumptions of the players we can handle the winner-takes-all scenarios, so we don't loose the fairness.

In more detail, a VDF is implemented by a tuple of three algorithms [1]:

* *VDFSetup(λ, T) → pp* is a randomized algorithm that takes a security parameter *λ* and a time
bound *T*, and outputs public parameter *pp*,
* *VDFEval(pp, x) → (y, π)* takes an input *x ∈ X* and outputs a *y ∈ Y* and a proof *π*.
* *VDFVerify(pp, x, y, π) → {accept, reject}* outputs accept if *y* is the correct evaluation of the VDF
on input *x*.

Verifiable random functions (VRFs) are defined using a public-key pair *(VK,SK)* and have the property that using a private key *SK* allows to hash a plain-text *x* into a hash *y* that can be verified using a public or verification key *VK*.

VRFs are being popularized and use for leader-selection by the Algorand Blockchain project, although they use voting for Byzantine Fault-tolerance and do not use VDF as part of their consensus algorithm.

VRF syntax and properties are as follows [1]. A VRF is a triple of algorithms *VRFKeygen*, *VRFEvaluate*, and *VRFVerify*:

 - *VRFKeygen(r) → (VK, SK)*. On a random input, the key generation algorithm produces a verification key *VK* and a secret key *SK* pair.
 - *VRFEvaluate(SK, x) → (y, ⍴)*. The evaluation algorithm takes as input the secret key *SK*, a message *X* and produces a pseudorandom output string *Y* and a proof *⍴*.
 - *Verify(VK, x, y, ⍴) → {accept, reject}*. The verification algorithm takes as input the verification key *VK*, the message *x*, the output *Y* and the proof *⍴*. It outputs *accept* if and only if it verifies that *Y* is the output produced by the evaluation algorithm on inputs SK and X.

## Vixify Consensus

Vixify Blockchain has a consensus algorithm that has very similar properties to Nakamoto Consensus, because is based on what we call: Synthetic Proof-of-Work. We define the later as:

1. **Money Investment**: To start mining and competing *miners have to invest money*. On our case the need to hold some special coin stake on their coinbase wallet, in Nakamoto Consensus miners invest in special and powerful hardware.
2. **Time Investment**: Depending on know much they invest they will have to also invest time. Their *time investment will be inversally proportial to their money investment*.
3. **Random Timer**: Miners *run a timer with random time and the winner is the one with the smallest time*. In Vixify Consensus a private random timer is generated using the VRF and the VDF functions. On Nakamoto Consensus, looking for the pre-image generated an specially difficult hash has this property of a *random timer*.
4. **Block Proposer is Unpredictable**: Miners (with less than 50% of the stake) don't know if their mined block or whose block will be chosen for consensus. *Next block proposer is not predictable*.
5. **Block Proposer Chances are Predictable**: Miners might have some probabilistic hint that they are going to be the next block proposer but they are never certain, unless they have more than 50% of the stake and then they can start to do some attacks on the blockchain and eventually getting 100% of the stake and total control of the blockchain.

To see the differences between Nakamoto Consensus and Vixify Consensus check the following diagrams:

![Nakamoto Consensus diagram](https://i.ibb.co/tmBQTTB/Nakamoto-Consensus.png "Nakamoto Consensus diagram")


## Installation

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
[2] Dan Boneh, Joseph Bonneau, Benedikt Bunz, and Ben Fisch, "Verifiable Delay Functions" https://eprint.iacr.org/2018/601.pdf
