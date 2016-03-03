# Cryptopals Solutions
This repository contains my solutions to the [Matasano Crypto Challenge](http://cryptopals.com/).

__Warning__: The whole funny part of the challenge is trying to solve the sets by yourself. 
Look at the online solutions only afterwards, to evaluate yours.

## Try it out

### Requirements
This project explicitly requires a Python version ≥ 3.4.
I've experimented with [type hints](https://www.python.org/dev/peps/pep-0484/).
Any other requirement is listed in the `requirements.txt` file.

### Launch it
```bash
$ git clone https://github.com/aldur/MatasanoCrypto.git
$ cd MatasanoCrypto
$ python3 setup.py develop
$ python3 bin/matasano <challenge number>
```

## Read it
The `bin/matasano` file contains the code used to solve each problem.
Navigate the code from there or head to the section below.

## Progress

- [x] Set 1.
- [x] Set 2.
- [x] Set 3.
- [x] Set 4.
- [x] Set 5.
- [x] Set 6.
- [x] Set 7.

Specifically, you can find below references to the commit that solves each challenge.

1. [Convert hex to base64](https://github.com/aldur/MatasanoCrypto/commit/96af8f918f10eef0c428a55934f531832f7f761b)
2. [Fixed XOR](https://github.com/aldur/MatasanoCrypto/commit/96af8f918f10eef0c428a55934f531832f7f761b)
3. [Single-byte XOR cipher](https://github.com/aldur/MatasanoCrypto/commit/96af8f918f10eef0c428a55934f531832f7f761b)
4. [Detect single-character XOR](https://github.com/aldur/MatasanoCrypto/commit/96af8f918f10eef0c428a55934f531832f7f761b)
5. [Implement repeating-key XOR](https://github.com/aldur/MatasanoCrypto/commit/96af8f918f10eef0c428a55934f531832f7f761b)
6. [Break repeating-key XOR](https://github.com/aldur/MatasanoCrypto/commit/96af8f918f10eef0c428a55934f531832f7f761b)
7. [AES in ECB mode](https://github.com/aldur/MatasanoCrypto/commit/96af8f918f10eef0c428a55934f531832f7f761b)
8. [Detect AES in ECB mode](https://github.com/aldur/MatasanoCrypto/commit/96af8f918f10eef0c428a55934f531832f7f761b)
9. [Implement PKCS#7 padding](https://github.com/aldur/MatasanoCrypto/commit/e4651a89c316bccb052aeaaa506eac4722cc5bf1)
10. [Implement CBC mode](https://github.com/aldur/MatasanoCrypto/commit/e4651a89c316bccb052aeaaa506eac4722cc5bf1)
11. [An ECB/CBC detection oracle](https://github.com/aldur/MatasanoCrypto/commit/e4651a89c316bccb052aeaaa506eac4722cc5bf1)
12. [Byte-at-a-time ECB decryption (Simple)](https://github.com/aldur/MatasanoCrypto/commit/66772e9131ed5f59bd182c2346a373a3c1897a0d)
13. [ECB cut-and-paste](https://github.com/aldur/MatasanoCrypto/commit/953531c664b2eb8c72dfe0385bc80a96f560e1c1)
14. [Byte-at-a-time ECB decryption (Harder)](https://github.com/aldur/MatasanoCrypto/commit/03a5204577cde654cf61902a16904fe4209a6ddb)
15. [PKCS#7 padding validation](https://github.com/aldur/MatasanoCrypto/commit/618b7b07bb0b6eafdb13afdabd55e7509994a4fe)
16. [CBC bitflipping attacks](https://github.com/aldur/MatasanoCrypto/commit/09ab7d90d4bc3908d8925ec13dad4a428cc99c23)
17. [The CBC padding oracle](https://github.com/aldur/MatasanoCrypto/commit/9bfa0c7a62c554a4afa30eb7c8450655942f7d3a)
18. [Implement CTR, the stream cipher mode](https://github.com/aldur/MatasanoCrypto/commit/4bf4da94f782f4a49bea1e28094fc5d56a337932)
19. [Break fixed-nonce CTR mode using substitions](https://github.com/aldur/MatasanoCrypto/commit/fd4d2189e9df5e6111bfcdb3bd9d2e502d64e54c)
20. [Break fixed-nonce CTR statistically](https://github.com/aldur/MatasanoCrypto/commit/4becdc5a39bb476c6f9b738622e038a7cc713035)
21. [Implement the MT19937 Mersenne Twister RNG](https://github.com/aldur/MatasanoCrypto/commit/9d562fe1d05f99a7daa135d41206413e1c4a6a2e)
22. [Crack an MT19937 seed](https://github.com/aldur/MatasanoCrypto/commit/5043f6653fb75db765b438ec3bfd71f1c400ccfd)
23. [Clone an MT19937 RNG from its output](https://github.com/aldur/MatasanoCrypto/commit/94bd200e7f127e4c4db5d620240d3e155aa34c75)
24. [Create the MT19937 stream cipher and break it](https://github.com/aldur/MatasanoCrypto/commit/d32c2a5e18127d74b776ba160a377fa4741af126)
25. [Break "random access read/write" AES CTR](https://github.com/aldur/MatasanoCrypto/commit/eb12dd197a9bdf3bbe85a70e68079de1947e68d0)
26. [CTR bitflipping](https://github.com/aldur/MatasanoCrypto/commit/6f469473ee27cfa2723802c727028678ea13e57d)
27. [Recover the key from CBC with IV=Key](https://github.com/aldur/MatasanoCrypto/commit/9dd6b163fcfeb1e72f244cde6249f269009b5493)
28. [Implement a SHA-1 keyed MAC](https://github.com/aldur/MatasanoCrypto/commit/f4b42e8e30d6808e918b97ce5bff14d077478346)
29. [Break a SHA-1 keyed MAC using length extension](https://github.com/aldur/MatasanoCrypto/commit/bde6bf2d485bd118b741292977fc713d6b94647e)
30. [Break an MD4 keyed MAC using length extension](https://github.com/aldur/MatasanoCrypto/commit/2eaf616c265f2a82c029fdce5a48a28b67cca569)
31. [Implement and break HMAC-SHA1 with an artificial timing leak](https://github.com/aldur/MatasanoCrypto/commit/3a2740da8280fe866209ae509da06c016f2f5b3a)
32. [Break HMAC-SHA1 with a slightly less artificial timing leak](https://github.com/aldur/MatasanoCrypto/commit/4774cb9f2e9c132451f0df31a4df9aef0e6690a3)
33. [Implement Diffie-Hellman](https://github.com/aldur/MatasanoCrypto/commit/372a92e34fe09df469836249c527ca8984150990)
34. [Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection](https://github.com/aldur/MatasanoCrypto/commit/f7b2a85aa1bcfba27034ff594d7bae8a4545b9a2)
35. [Implement DH with negotiated groups, and break with malicious "g" parameters](https://github.com/aldur/MatasanoCrypto/commit/b8c3c59c3294b84fc510a3d850262f3ef526ec0e)
36. [Implement Secure Remote Password (SRP)](https://github.com/aldur/MatasanoCrypto/commit/4ef54cc150cb4948bc975c613cf7ff2be61642df)
37. [Break SRP with a zero key](https://github.com/aldur/MatasanoCrypto/commit/edd6955928959fccde6ecbe50c3e80f949a118c1)
38. [Offline dictionary attack on simplified SRP](https://github.com/aldur/MatasanoCrypto/commit/5d27616a9096f3a3abafac83607ce46798cf35ec)
39. [Implement RSA](https://github.com/aldur/MatasanoCrypto/commit/dfbd287fae97f290f21d56d8147ea175fe5b491b)
40. [Implement an E=3 RSA Broadcast attack](https://github.com/aldur/MatasanoCrypto/commit/f15437c079744a05c26a7b003634137d5b339e06)
41. [Implement unpadded message recovery oracle](https://github.com/aldur/MatasanoCrypto/commit/96a94d438bae5ff472c6c38c77bc9d8777bb9715)
42. [Bleichenbacher's e=3 RSA Attack](https://github.com/aldur/MatasanoCrypto/commit/6c76b33cb6a068d8119e9cadb819861b036e7f77)
43. [DSA key recovery from nonce](https://github.com/aldur/MatasanoCrypto/commit/02774c6a8dcf2353d122d1391c974919b683d508)
44. [DSA nonce recovery from repeated nonce](https://github.com/aldur/MatasanoCrypto/commit/12b6f237e2d48f0cc0d40a8792e74130f4d0760f)
45. [DSA parameter tampering](https://github.com/aldur/MatasanoCrypto/commit/0e2b2e4473b156694e026245838941cad99f8adf)
46. [RSA parity oracle](https://github.com/aldur/MatasanoCrypto/commit/f499a2c6d9f0ac4c9af5b3563182cf6c0a389c1b)
47. [Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case)](https://github.com/aldur/MatasanoCrypto/commit/9fa49e29835f9a79e16643ca49f872423048cc38)
48. [Bleichenbacher's PKCS 1.5 Padding Oracle (Complete Case)](https://github.com/aldur/MatasanoCrypto/commit/45162ff5414088f7752f3eb5abeb4a55e34256e6)
49. [CBC-MAC Message Forgery](https://github.com/aldur/MatasanoCrypto/commit/50f6a75f8b348b02bbbec600d7e097894c95a191)
50. [Hashing with CBC-MAC](https://github.com/aldur/MatasanoCrypto/commit/d565cd1d5f9eaeb82241150717ec5b73a787208a)
51. [Compression Ratio Side-Channel Attacks](https://github.com/aldur/MatasanoCrypto/commit/a6d075cb7c81d0e74148f2dbd1bb68824266774c)
52. [Iterated Hash Function Multicollisions](https://github.com/aldur/MatasanoCrypto/commit/4dc159c4e74a65fe4a686b00e2e8b5112e4792bc)
53. [Kelsey and Schneier's Expandable Messages](https://github.com/aldur/MatasanoCrypto/commit/c7d3e189b2b0623c732cd7565ced0b808b4af47e)
54. [Kelsey and Kohno's Nostradamus Attack](https://github.com/aldur/MatasanoCrypto/commit/39eb9fd6e9cfeb63451abf8c0791da3fed114406)
55. [MD4 Collisions](https://github.com/aldur/MatasanoCrypto/commit/b2298655b43831b932117dfcca0bc039a06bb044)
56. [RC4 Single-Byte Biases](https://github.com/aldur/MatasanoCrypto/commit/da6457e2ef298d2c4c8e26107016dd4e37d45b53)

## License
MIT License.
