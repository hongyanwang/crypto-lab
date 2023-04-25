## Multiple signature schemes

1. `Group Signature`: One member can anonymously sign a message on behalf of the group. The administrator of the group have the ability to reveal the credential of the signer.

>anonymity, supervisable

2. `Ring Signature`: One member can anonymously sign a message using multiple members' public keys. The credential of the signer cannot be revealed.

>anonymity

3. `Threshold Signature`: Signatures of multiple participants that meet the threshold value can be integrated into one group signature, which can be verified by the group public key.

>high availability, distributed

4. `Multi-Signature`: Multiple participants sign the same message with their own private keys, and the verification can be passed if a certain signature number or weight is satisfied.

>multiple verifications, mostly used for authority management

5. `Blind Signature`: The signer does not know the message content to sign. The legal signature of the original message can be obtained after signing.

>privacy
