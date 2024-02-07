# zklogin-verifier

A rust server that verifies a zkLogin signature given bytes for transaction data or personal message. 

# Run

```bash
cargo run
```

# Call

```bash
curl -X POST 0.0.0.0:3000/verify -H 'Content-Type: application/json' -d '{"signature": "BQNNMTczMTgwODkxMjU5NTI0MjE3MzYzNDIyNjM3MTc5MzI3MTk0Mzc3MTc4NDQyODI0MTAxODc5NTc5ODQ3NTE5Mzk5NDI4OTgyNTEyNTBNMTEzNzM5NjY2NDU0NjkxMjI1ODIwNzQwODIyOTU5ODUzODgyNTg4NDA2ODE2MTgyNjg1OTM5NzY2OTczMjU4OTIyODA5MTU2ODEyMDcBMQMCTDU5Mzk4NzExNDczNDg4MzQ5OTczNjE3MjAxMjIyMzg5ODAxNzcxNTIzMDMyNzQzMTEwNDcyNDk5MDU5NDIzODQ5MTU3Njg2OTA4OTVMNDUzMzU2ODI3MTEzNDc4NTI3ODczMTIzNDU3MDM2MTQ4MjY1MTk5Njc0MDc5MTg4ODI4NTg2NDk2Njg4NDAzMjcxNzA0OTgxMTcwOAJNMTA1NjQzODcyODUwNzE1NTU0Njk3NTM5OTA2NjE0MTA4NDAxMTg2MzU5MjU0NjY1OTcwMzcwMTgwNTg3NzAwNDEzNDc1MTg0NjEzNjhNMTI1OTczMjM1NDcyNzc1NzkxNDQ2OTg0OTYzNzIyNDI2MTUzNjgwODU4MDEzMTMzNDMxNTU3MzU1MTEzMzAwMDM4ODQ3Njc5NTc4NTQCATEBMANNMTU3OTE1ODk0NzI1NTY4MjYyNjMyMzE2NDQ3Mjg4NzMzMzc2MjkwMTUyNjk5ODQ2OTk0MDQwNzM2MjM2MDMzNTI1Mzc2Nzg4MTMxNzFMNDU0Nzg2NjQ5OTI0ODg4MTQ0OTY3NjE2MTE1ODAyNDc0ODA2MDQ4NTM3MzI1MDAyOTQyMzkwNDExMzAxNzQyMjUzOTAzNzE2MjUyNwExMXdpYVhOeklqb2lhSFIwY0hNNkx5OXBaQzUwZDJsMFkyZ3VkSFl2YjJGMWRHZ3lJaXcCMmV5SmhiR2NpT2lKU1V6STFOaUlzSW5SNWNDSTZJa3BYVkNJc0ltdHBaQ0k2SWpFaWZRTTIwNzk0Nzg4NTU5NjIwNjY5NTk2MjA2NDU3MDIyOTY2MTc2OTg2Njg4NzI3ODc2MTI4MjIzNjI4MTEzOTE2MzgwOTI3NTAyNzM3OTExCgAAAAAAAABhAG6Bf8BLuaIEgvF8Lx2jVoRWKKRIlaLlEJxgvqwq5nDX+rvzJxYAUFd7KeQBd9upNx+CHpmINkfgj26jcHbbqAy5xu4WMO8+cRFEpkjbBruyKE9ydM++5T/87lA8waSSAA==", "bytes": "AAABACACAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgEBAQABAAAcpgUkGBwS5nPO79YXkjMyvaRjGS57hqxzfyd2yGtejwGbB4FfBEl+LgXSLKw6oGFBCyCGjMYZFUxCocYb6ZAnFwEAAAAAAAAAIJZw7UpW1XHubORIOaY8d2+WyBNwoJ+FEAxlsa7h7JHrHKYFJBgcEuZzzu/WF5IzMr2kYxkue4asc38ndshrXo8BAAAAAAAAABAnAAAAAAAAAA==", "intent_scope": 0, "curr_epoch": 9, "network": "Devnet"}'

{"is_verified":true}
```

# Notes

1. This verifier currently can verify providers defined [here](https://github.com/MystenLabs/fastcrypto/blob/802c1ac98061687d6ce024849c747a250dbeea52/fastcrypto-zkp/src/bn254/zk_login.rs#L80). For supported providers per network, see [doc](https://docs.sui.io/build/zk_login#openid-providers).
2. Accepted `intent_scope`: 0 (TransactionData), 3 (PersonalMessage). Defined in [Sui](https://github.com/MystenLabs/sui/blob/7181ea91b6752fb75aa1e163047428f1201685e4/crates/shared-crypto/src/intent.rs#L59). 
3. Accepted `network`: Localnet, Devnet, Testnet, Mainnet.
4. `curr_epoch` is optional: If not provided, it is retrieved from Sui based on `network`.
5. `author`: The ZKLogin SuiAddress of the signer. It is optional for `intent_scope`: 0, but required for `intent_scope`: 3.

