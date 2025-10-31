[![Crates.io](https://img.shields.io/crates/v/grpc-jwt-tonic.svg)](https://crates.io/crates/grpc-jwt-tonic)
[![Documentation](https://docs.rs/grpc-jwt-tonic/badge.svg)](https://docs.rs/grpc-jwt-tonic)
[![License](https://img.shields.io/crates/l/grpc-jwt-tonic.svg)](https://github.com/LdDl/grpc-jwt-tonic/blob/main/LICENSE)
[![Build Status](https://github.com/LdDl/grpc-jwt-tonic/workflows/CI/badge.svg)](https://github.com/LdDl/grpc-jwt-tonic/actions)

# grpc-jwt-tonic - JWT recipe for Tonic gRPC-based server in Rust

This crate provides JWT (JSON Web Token) authentication and authorization middleware for Tonic-based gRPC servers in Rust. It's the port of my original Go library [grpc-jwt](https://github.com/LdDl/grpc-jwt), maintaining the same API patterns and functionality while leveraging Rust's type safety and performance benefits.

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Proto File Generation](#proto-file-generation)
- [Usage](#usage)
    - [Run the server](#run-the-server)
    - [Run the client](#run-the-client)
    - [Key Generation](#key-generation)
- [Configuration](#configuration)
- [Comparison with Go Version](#comparison-with-go-version)
- [Support](#support)
- [Dependencies](#dependencies)
- [License](#license)

## **Features**

✅ **JWT Authentication** - Login with username/password, receive JWT tokens  
✅ **Token Refresh** - Refresh expired tokens   
✅ **Method Interception** - Selectively protect gRPC methods  
✅ **Multiple Algorithms** - Support for HMAC (HS256, HS384, HS512) and RSA (RS256, RS384, RS512)  
✅ **Custom Claims** - Add custom payload data to JWT tokens    
✅ **Authorization Logic** - Flexible user authorization callbacks  
✅ **Streaming Support** - Works with both unary and streaming gRPC calls  

## **Installation**

Add this to your `Cargo.toml`:

```toml
[dependencies]
grpc-jwt-tonic = "0.1.0"
tonic = "0.14.2"
tokio = { version = "1.0", features = ["macros", "rt-multi-thread"] }
serde_json = "1.0"

[build-dependencies]
tonic-prost-build = "0.14.2"
```

## **Proto File Generation**

To regenerate protobuf files, use:

```bash
# Use the build.rs approach (recommended)
cargo build
```

## **Usage**

### **Run the server**

Here's a complete server implementation with JWT authentication - [server-side directory](./examples/server/)

```shell
# Start Rust gRPC server with JWT authentication
cd examples/server
cargo run --bin server
```

### **Run the client**

Here's how to use the JWT authentication from a Rust client - [client-side directory](./examples/client/)

```shell
# Test with Rust client
cd examples/client
cargo run --bin client
```

### **Key Generation**

For production use with RSA keys, generate private/public key pairs:

```shell
# Generate RSA private key
ssh-keygen -t rsa -b 4096 -m PEM -f jwtRS512.key
# Extract public key
openssl rsa -in jwtRS512.key -pubout -outform PEM -out jwtRS512.key.pub
```

Then use in your code:
```rust
let private_key = std::fs::read("jwtRS512.key")?;
let public_key = std::fs::read("jwtRS512.key.pub")?;

let opts = JwtEngineOptions {
    alg: AlgorithmKind::RS512 { private_key, public_key },
    // ... other options
};
```

## **Configuration**

### **JwtEngineOptions**

Configure the JWT engine behavior:

```rust
pub struct JwtEngineOptions {
    pub realm: String,              // JWT realm identifier (default: "grpc jwt")
    pub alg: AlgorithmKind,         // Signing algorithm (default: HS256 with "secret")
    pub timeout: Duration,          // Token expiration time (default: 1 hour)
    pub max_refresh: Duration,      // Maximum refresh duration (default: 7 days)
    pub identity_key: String,       // Key for identity in claims (default: "identity")
    pub token_lookup: String,       // Where to find token (default: "header:Authorization")
    pub token_head_name: String,    // Token prefix (default: "Bearer")
    pub send_authorization: bool,   // Send auth in response (default: false)
    pub disabled_abort: bool,       // Disable abort on auth failure (default: false)
    pub priv_key_file: String,      // Private key file path for RSA (default: empty)
    pub pub_key_file: String,       // Public key file path for RSA (default: empty)
}
```

### **AlgorithmKind**

Supported JWT signing algorithms:

```rust
pub enum AlgorithmKind {
    HS256(Vec<u8>),                                          // HMAC with SHA-256
    HS384(Vec<u8>),                                          // HMAC with SHA-384  
    HS512(Vec<u8>),                                          // HMAC with SHA-512
    RS256 { private_pem: Vec<u8>, public_pem: Vec<u8> },    // RSA with SHA-256
    RS384 { private_pem: Vec<u8>, public_pem: Vec<u8> },    // RSA with SHA-384
    RS512 { private_pem: Vec<u8>, public_pem: Vec<u8> },    // RSA with SHA-512
}
```

## **Comparison with Go Version**

This Rust implementation maintains full compatibility with the [original Go version](https://github.com/LdDl/grpc-jwt):

| Feature | Go Version | Rust Version | Compatible |
|---------|------------|--------------|------------|
| JWT Authentication | ✅ | ✅ | ✅ |
| Token Refresh | ✅ | ✅ | ✅ |
| HMAC Algorithms | ✅ | ✅ | ✅ |
| RSA Algorithms | ✅ | ✅ | ✅ |
| Custom Claims | ✅ | ✅ | ✅ |
| Method Interception | ✅ | ✅ | ✅ |
| Streaming Support | ✅ | ✅ | ✅ |
| Cross-Language Clients | ✅ | ✅ | ✅ |

## **Support**

If you have troubles or questions please [open an issue](https://github.com/LdDl/grpc-jwt-tonic/issues/new).

Use this crate carefully: there are no tests. I have no that much time to test every case (for my job purposes it works as intended).

PRs are welcome!

### **Related Projects**

- **Original Go implementation**: [LdDl/grpc-jwt](https://github.com/LdDl/grpc-jwt)
- **Tonic gRPC framework**: [hyperium/tonic](https://github.com/hyperium/tonic)
- **JWT for Rust**: [Keats/jsonwebtoken](https://github.com/Keats/jsonwebtoken)

## **Dependencies**

* [tonic](https://github.com/hyperium/tonic?tab=MIT-1-ov-file#readme) - Rust gRPC framework - License: MIT
* [jsonwebtoken](https://github.com/Keats/jsonwebtoken?tab=MIT-1-ov-file#readme) - JWT implementation - License: MIT  
* [tokio](https://github.com/tokio-rs/tokio?tab=MIT-1-ov-file#readme) - Async runtime - License: MIT + Apache
* [serde_json MIT](https://github.com/serde-rs/json/blob/master/LICENSE-MIT) and [serde_json Apache 2.0](https://github.com/serde-rs/json/blob/master/LICENSE-APACHE) - JSON serialization - License: MIT/Apache-2.0
* [prost](https://github.com/tokio-rs/prost?tab=Apache-2.0-1-ov-file#readme) - Protocol Buffers - License: Apache-2.0

## **License**

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or https://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/licenses/MIT)

at your option.

### **Contribution**

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

---

*This is the official Rust port by [LdDl](https://github.com/LdDl), the original author of [grpc-jwt](https://github.com/LdDl/grpc-jwt).* 🦀

## Author's Note

> Why Rust?
>
> After building and maintaining the Go version, I wanted to explore how this JWT gRPC pattern would work in Rust, taking advantage of:
> - Zero-cost abstractions and compile-time optimizations
> - Memory safety without garbage collection overhead  
> - Async performance with Tokio
>
> — *Dmitrii (LdDl)*