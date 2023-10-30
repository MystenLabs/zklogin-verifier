# zklogin-verifier

A rust server that verifies a zkLogin signature given a message. 

# Run

```bash
cargo run
```

# Call

```bash
curl -X POST 0.0.0.0:3000/verify -H 'Content-Type: application/json' -d '{"signature": "", "bytes": ""}'

{"is_verified":"true"}
```