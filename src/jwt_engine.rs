use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::fmt;
use std::fs;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub enum JwtError {
    MissingSecretKey,
    InvalidSigningAlgorithm,
    ExpiredToken,
    MissingExpField,
    WrongExpFormat,
    Token(String),
    Forbidden,
    MissingAuthenticatorFunc,
    MissingLoginValues,
    FailedAuthentication,
    FailedTokenCreation,
    EmptyAuthHeader,
    InvalidAuthHeader,
    EmptyQueryToken,
    EmptyCookieToken,
    EmptyParamToken,
    NoPrivKeyFile,
    NoPubKeyFile,
    InvalidPrivKey,
    InvalidPubKey,
}

impl fmt::Display for JwtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JwtError::MissingSecretKey => write!(f, "secret key is required"),
            JwtError::InvalidSigningAlgorithm => write!(f, "invalid signing algorithm"),
            JwtError::ExpiredToken => write!(f, "token is expired"),
            JwtError::MissingExpField => write!(f, "missing exp field"),
            JwtError::WrongExpFormat => write!(f, "exp must be number"),
            JwtError::Token(msg) => write!(f, "token error: {msg}"),
            JwtError::Forbidden => write!(f, "you don't have permission to access this resource"),
            JwtError::MissingAuthenticatorFunc => write!(f, "authenticator func is undefined"),
            JwtError::MissingLoginValues => write!(f, "missing Username or Password"),
            JwtError::FailedAuthentication => write!(f, "incorrect Username or Password"),
            JwtError::FailedTokenCreation => write!(f, "failed to create JWT Token"),
            JwtError::EmptyAuthHeader => write!(f, "auth header is empty"),
            JwtError::InvalidAuthHeader => write!(f, "auth header is invalid"),
            JwtError::EmptyQueryToken => write!(f, "query token is empty"),
            JwtError::EmptyCookieToken => write!(f, "cookie token is empty"),
            JwtError::EmptyParamToken => write!(f, "parameter token is empty"),
            JwtError::NoPrivKeyFile => write!(f, "private key file unreadable"),
            JwtError::NoPubKeyFile => write!(f, "public key file unreadable"),
            JwtError::InvalidPrivKey => write!(f, "private key invalid"),
            JwtError::InvalidPubKey => write!(f, "public key invalid"),
        }
    }
}

impl std::error::Error for JwtError {}

#[derive(Clone)]
pub enum AlgorithmKind {
    HS256(Vec<u8>),
    HS384(Vec<u8>),
    HS512(Vec<u8>),
    RS256 { private_pem: Vec<u8>, public_pem: Vec<u8> },
    RS384 { private_pem: Vec<u8>, public_pem: Vec<u8> },
    RS512 { private_pem: Vec<u8>, public_pem: Vec<u8> },
}

impl AlgorithmKind {
    pub fn algorithm(&self) -> Algorithm {
        match self {
            AlgorithmKind::HS256(_) => Algorithm::HS256,
            AlgorithmKind::HS384(_) => Algorithm::HS384,
            AlgorithmKind::HS512(_) => Algorithm::HS512,
            AlgorithmKind::RS256 { .. } => Algorithm::RS256,
            AlgorithmKind::RS384 { .. } => Algorithm::RS384,
            AlgorithmKind::RS512 { .. } => Algorithm::RS512,
        }
    }
    fn encoding_key(&self) -> Result<EncodingKey, JwtError> {
        match self {
            AlgorithmKind::HS256(k) | AlgorithmKind::HS384(k) | AlgorithmKind::HS512(k) => {
                Ok(EncodingKey::from_secret(k))
            }
            AlgorithmKind::RS256 { private_pem, .. }
            | AlgorithmKind::RS384 { private_pem, .. }
            | AlgorithmKind::RS512 { private_pem, .. } => {
                EncodingKey::from_rsa_pem(private_pem).map_err(|e| JwtError::Token(e.to_string()))
            }
        }
    }
    fn decoding_key(&self) -> Result<DecodingKey, JwtError> {
        match self {
            AlgorithmKind::HS256(k) | AlgorithmKind::HS384(k) | AlgorithmKind::HS512(k) => {
                Ok(DecodingKey::from_secret(k))
            }
            AlgorithmKind::RS256 { public_pem, .. }
            | AlgorithmKind::RS384 { public_pem, .. }
            | AlgorithmKind::RS512 { public_pem, .. } => {
                DecodingKey::from_rsa_pem(public_pem).map_err(|e| JwtError::Token(e.to_string()))
            }
        }
    }
    pub fn from_rsa_files(alg: Algorithm, priv_key_file: &str, pub_key_file: &str) -> Result<Self, JwtError> {
        let private_pem = fs::read(priv_key_file)
            .map_err(|_| JwtError::NoPrivKeyFile)?;
        let public_pem = fs::read(pub_key_file)
            .map_err(|_| JwtError::NoPubKeyFile)?;

        // Validate keys
        EncodingKey::from_rsa_pem(&private_pem)
            .map_err(|_| JwtError::InvalidPrivKey)?;
        DecodingKey::from_rsa_pem(&public_pem)
            .map_err(|_| JwtError::InvalidPubKey)?;

        match alg {
            Algorithm::RS256 => Ok(AlgorithmKind::RS256 { private_pem, public_pem }),
            Algorithm::RS384 => Ok(AlgorithmKind::RS384 { private_pem, public_pem }),
            Algorithm::RS512 => Ok(AlgorithmKind::RS512 { private_pem, public_pem }),
            _ => Err(JwtError::InvalidSigningAlgorithm),
        }
    }
}

#[derive(Clone)]
pub struct JwtEngineOptions {
    pub realm: String,
    pub alg: AlgorithmKind,
    pub timeout: Duration,
    pub max_refresh: Duration,
    pub identity_key: String,
    pub token_lookup: String,
    pub token_head_name: String,
    pub send_authorization: bool,
    pub disabled_abort: bool,
    pub priv_key_file: String,
    pub pub_key_file: String,
}

impl Default for JwtEngineOptions {
    fn default() -> Self {
        Self {
            realm: "grpc jwt".to_string(),
            alg: AlgorithmKind::HS256(b"secret".to_vec()),
            timeout: Duration::from_secs(3600),
            max_refresh: Duration::from_secs(3600 * 24 * 7),
            identity_key: "identity".to_string(),
            token_lookup: "header:Authorization".to_string(),
            token_head_name: "Bearer".to_string(),
            send_authorization: false,
            disabled_abort: false,
            priv_key_file: String::new(),
            pub_key_file: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub exp: u64,
    pub orig_iat: u64,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone)]
pub struct JwtEngine {
    pub opts: Arc<JwtEngineOptions>,
}

impl JwtEngine {
    pub fn new(mut opts: JwtEngineOptions) -> Result<Self, JwtError> {
        // Apply defaults
        if opts.token_lookup.is_empty() {
            opts.token_lookup = "header:Authorization".to_string();
        }
        
        if opts.timeout.as_secs() == 0 {
            opts.timeout = Duration::from_secs(3600);
        }
        
        opts.token_head_name = opts.token_head_name.trim().to_string();
        if opts.token_head_name.is_empty() {
            opts.token_head_name = "Bearer".to_string();
        }
        
        if opts.identity_key.is_empty() {
            opts.identity_key = "identity".to_string();
        }
        
        if opts.realm.is_empty() {
            opts.realm = "grpc jwt".to_string();
        }

        // Read keys if using public key algorithms
        if Self::using_public_key_algo_static(&opts.alg) {
            if opts.priv_key_file.is_empty() || opts.pub_key_file.is_empty() {
                return Err(JwtError::MissingSecretKey);
            }
            // Update the algorithm with loaded keys
            opts.alg = Self::read_keys_static(&opts.priv_key_file, &opts.pub_key_file, &opts.alg)?;
        } else {
            // For HMAC algorithms, ensure we have a key
            match &opts.alg {
                AlgorithmKind::HS256(k) | AlgorithmKind::HS384(k) | AlgorithmKind::HS512(k) => {
                    if k.is_empty() {
                        return Err(JwtError::MissingSecretKey);
                    }
                }
                _ => {}
            }
        }

        Ok(Self { opts: Arc::new(opts) })
    }

    // Static helper method
    fn using_public_key_algo_static(alg: &AlgorithmKind) -> bool {
        matches!(
            alg,
            AlgorithmKind::RS256 { .. } | AlgorithmKind::RS384 { .. } | AlgorithmKind::RS512 { .. }
        )
    }
    
    fn read_keys_static(priv_key_file: &str, pub_key_file: &str, current_alg: &AlgorithmKind) -> Result<AlgorithmKind, JwtError> {
        let private_pem = Self::read_private_key_static(priv_key_file)?;
        let public_pem = Self::read_public_key_static(pub_key_file)?;
        
        match current_alg {
            AlgorithmKind::RS256 { .. } => Ok(AlgorithmKind::RS256 { private_pem, public_pem }),
            AlgorithmKind::RS384 { .. } => Ok(AlgorithmKind::RS384 { private_pem, public_pem }),
            AlgorithmKind::RS512 { .. } => Ok(AlgorithmKind::RS512 { private_pem, public_pem }),
            _ => Err(JwtError::InvalidSigningAlgorithm),
        }
    }

    fn read_private_key_static(file_path: &str) -> Result<Vec<u8>, JwtError> {
        let key_data = fs::read(file_path)
            .map_err(|_| JwtError::NoPrivKeyFile)?;
        
        // Validate the private key
        EncodingKey::from_rsa_pem(&key_data)
            .map_err(|_| JwtError::InvalidPrivKey)?;
            
        Ok(key_data)
    }

    fn read_public_key_static(file_path: &str) -> Result<Vec<u8>, JwtError> {
        let key_data = fs::read(file_path)
            .map_err(|_| JwtError::NoPubKeyFile)?;
        
        // Validate the public key
        DecodingKey::from_rsa_pem(&key_data)
            .map_err(|_| JwtError::InvalidPubKey)?;
            
        Ok(key_data)
    }

    pub fn using_public_key_algo(&self) -> bool {
        Self::using_public_key_algo_static(&self.opts.alg)
    }

    pub fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    pub fn sign_with_extra(&self, mut extra: Map<String, Value>) -> Result<(String, u64), JwtError> {
        let now = Self::now();
        let exp = now + self.opts.timeout.as_secs();
        extra.insert("orig_iat".into(), Value::from(now));
        extra.insert("exp".into(), Value::from(exp));

        let claims = Claims { exp, orig_iat: now, extra };
        let mut header = Header::new(self.opts.alg.algorithm());
        header.typ = Some("JWT".into());
        let token = jsonwebtoken::encode(&header, &claims, &self.opts.alg.encoding_key()?)
            .map_err(|e| JwtError::Token(e.to_string()))?;
        Ok((token, exp))
    }

    pub fn decode(&self, token: &str) -> Result<Claims, JwtError> {
        let mut validation = Validation::new(self.opts.alg.algorithm());
        validation.validate_exp = false;
        let data = jsonwebtoken::decode::<Claims>(
            token,
            &self.opts.alg.decoding_key()?,
            &validation,
        ).map_err(|e| JwtError::Token(e.to_string()))?;
        Ok(data.claims)
    }

    pub fn get_claims(&self, token: &str) -> Result<Map<String, Value>, JwtError> {
        let claims = self.decode(token)?;
        let mut m = claims.extra.clone();
        m.insert("exp".to_string(), Value::from(claims.exp));
        m.insert("orig_iat".to_string(), Value::from(claims.orig_iat));
        Ok(m)
    }

    pub fn ensure_not_expired(&self, claims: &Map<String, Value>) -> Result<(), JwtError> {
        let exp = claims
            .get("exp")
            .ok_or(JwtError::MissingExpField)?
            .as_u64()
            .ok_or(JwtError::WrongExpFormat)?;
        if (exp as i64) < (Self::now() as i64) {
            return Err(JwtError::ExpiredToken);
        }
        Ok(())
    }

    pub fn check_if_token_expire(&self, token: &str) -> Result<Map<String, Value>, JwtError> {
        let claims = self.decode(token)?;
        let orig_iat = claims.orig_iat;
        let now = Self::now();
        if (now as i64) - (orig_iat as i64) > self.opts.max_refresh.as_secs() as i64 {
            return Err(JwtError::ExpiredToken);
        }
        let mut m = claims.extra.clone();
        m.insert("orig_iat".into(), Value::from(orig_iat));
        m.insert("exp".into(), Value::from(claims.exp));
        Ok(m)
    }
}