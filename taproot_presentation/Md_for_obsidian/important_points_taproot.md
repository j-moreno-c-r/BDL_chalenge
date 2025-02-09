
*  **[Schnorr Signatures](https://learnmeabitcoin.com/technical/cryptography/elliptic-curve/schnorr/)** — The new P2TR locking script uses the more efficient Schnorr signature scheme instead of [ECDSA](https://learnmeabitcoin.com/technical/cryptography/elliptic-curve/ecdsa/).
* **[Tapscript](https://learnmeabitcoin.com/technical/upgrades/taproot/#tapscript)** — The custom locking scripts inside P2TR use a slightly modified version of [Script](https://learnmeabitcoin.com/technical/script/) called _Tapscript_. 

### 2. Privacy [#](https://learnmeabitcoin.com/technical/upgrades/taproot/#privacy)

Thanks to the [merkle tree](https://learnmeabitcoin.com/technical/block/merkle-root/#merkle-tree) structure used for the custom scripts, only a _single script_ is actually revealed when you unlock a P2TR using the _script path spend_.

So you could construct a script tree with hundreds of different custom locking scripts, but **only the custom script you use will be revealed when you unlock it** (the rest will only appear as [hashes](https://learnmeabitcoin.com/technical/cryptography/hash-function/) of the original scripts).

This means all the other possible spending conditions of a P2TR are kept private.

"stoled from learn me a bitcoin sorry greg"
