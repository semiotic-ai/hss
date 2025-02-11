# Signature Scheme NCS1

## `setup`.

1. Given a pairing friendly elliptic curve with groups $\displaystyle \mathbb{G}_{1} ,\ \mathbb{G}_{2} ,$ and $\displaystyle \mathbb{G}_{T}$, choose generators $\displaystyle p\in \mathbb{G}_{1}$ and $\displaystyle q\in \mathbb{G}_{2}$.
2. Choose a random value, $\displaystyle sk\xleftarrow{\$}\mathbb{F}_{r}$, where $\displaystyle \mathbb{F}_{r}$ is the scalar field of the elliptic curve, and set $\displaystyle r:=\ sk\ \times q$. Note that the operation $\displaystyle \times $ corresponds to elliptic curve scalar multiplication.
3. Output the public key $\displaystyle pk\ :=\ ( p,\ q,\ r)$ and the secret key $\displaystyle sk$.

## `sign(sk, pk, id, index, m)`.

Given a secret key, $\displaystyle sk$, the point $\displaystyle p$ from the public key $\displaystyle pk$, an identifier, $\displaystyle id$, an $\displaystyle index$ corresponding to the row being signed and message, $\displaystyle m$, output the signature as

$$
signature:=sk\times (\mathtt{hash\_to\_curve}( id,\ index) +m\times p)
$$

Note that $\displaystyle +$ corresponds to elliptic curve point addition.

## `verify(pk, id, index, m, signature)`.

Given a public key, $\displaystyle pk=( p,\ q,\ r)$, an identifier, $\displaystyle id$, an $\displaystyle index$ corresponding to the row being verified, a message, $\displaystyle m$, and a $\displaystyle signature$, calculate

$$
left\ =\ e( signature,\ q)\\
right\ =\ e(\mathtt{hash\_to\_curve}( id,\ index) +m\times p,\ r)
$$

where the function $\displaystyle e( .,.)$ is the bilinear pairing.
If $\displaystyle left=right$ output $\displaystyle true$, else output $\displaystyle false$.

## `combine(weights, signatures)`.

Given a vector of $\displaystyle weights$ and vector of $\displaystyle signatures$, each of length $\displaystyle n$, calculate the aggregate signatures as

$$
aggregate\_signature\ =\ \sum _{i=0}^{n-1} weight_{i} \times signature_{i}
$$

## `verify_aggregate(pk, id, weights, m, aggregate_signature)`.

Given a public key $\displaystyle pk=( p,\ q,\ r)$, an identifier $\displaystyle id$, a vector of $\displaystyle weights$ of length $\displaystyle n$, a message $\displaystyle m$, and an $\displaystyle aggregate\_signature$, verify that the message $\displaystyle m$ corresponds to the weighted average of signed original messages by calculating

$$
left\ =\ e( signature,\ q)\\
right\ =\ e\left(\sum _{i=0}^{n-1} weight_{i} \times \mathtt{hash\_to\_curve}( id,\ i) +m\times p,\ r\right)
$$

If $\displaystyle left=right$ output $\displaystyle true$, else output $\displaystyle false$.

See *HSS Exercise.pdf* if the Latex is not rendering.
