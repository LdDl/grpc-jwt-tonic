use crate::{
    jwt_engine::{JwtEngine, JwtError},
    grpcjwt::*,
};
use serde_json::{Map, Value};
use std::{collections::HashSet, sync::Arc};
use tonic::{
    async_trait, metadata::MetadataMap, Request, Response, Status, 
};

/// JWT interceptor that provides authentication and authorization for gRPC methods.
/// 
/// The interceptor can selectively protect gRPC methods by checking JWT tokens,
/// validating user identity, and enforcing authorization rules. It also implements
/// the JWT service for login and token refresh operations.
pub struct JwtInterceptor {
    /// The JWT engine used for token operations
    jwt_object: Arc<JwtEngine>,
    /// Set of method paths that require JWT authentication
    intercepted_methods: HashSet<String>,
    /// Function to extract identity from JWT claims
    pub identity_handler: Arc<dyn Fn(&Map<String, Value>) -> Option<Value> + Send + Sync>,
    /// Function to authorize a user based on their identity
    pub authorizator: Arc<dyn Fn(&Value) -> bool + Send + Sync>,
    /// Function to authenticate username/password credentials
    pub authenticator: Arc<dyn Fn(&str, &str) -> Result<Value, JwtError> + Send + Sync>,
    /// Optional function to add custom payload to JWT tokens
    pub payload_func: Option<Arc<dyn Fn(&Value) -> Map<String, Value> + Send + Sync>>,
}

impl JwtInterceptor {
    /// Creates a new JWT interceptor with the specified configuration.
    /// 
    /// # Arguments
    /// * `jwt_engine` - The JWT engine for token operations
    /// * `identity_handler` - Function to extract identity from claims
    /// * `authorizator` - Function to authorize users
    /// * `authenticator` - Function to authenticate credentials
    /// * `methods` - Array of method paths that require authentication
    /// 
    /// # Returns
    /// * `Ok(JwtInterceptor)` - Successfully created interceptor
    /// * `Err(JwtError)` - If configuration is invalid
    pub fn new(
        jwt_engine: Arc<JwtEngine>,
        identity_handler: Arc<dyn Fn(&Map<String, Value>) -> Option<Value> + Send + Sync>,
        authorizator: Arc<dyn Fn(&Value) -> bool + Send + Sync>,
        authenticator: Arc<dyn Fn(&str, &str) -> Result<Value, JwtError> + Send + Sync>,
        methods: &[&str],
    ) -> Result<Self, JwtError> {
        let mut interceptor = Self {
            jwt_object: jwt_engine,
            intercepted_methods: HashSet::new(),
            identity_handler,
            authorizator,
            authenticator,
            payload_func: None,
        };
        
        interceptor.intercept_methods(methods);
        Ok(interceptor)
    }

    /// Adds a payload function to include custom claims in JWT tokens.
    /// 
    /// # Arguments
    /// * `payload_func` - Function that takes user identity and returns custom claims
    /// 
    /// # Returns
    /// * `JwtInterceptor` - Self with payload function configured
    pub fn with_payload_func(
        mut self, 
        payload_func: Arc<dyn Fn(&Value) -> Map<String, Value> + Send + Sync>
    ) -> Self {
        self.payload_func = Some(payload_func);
        self
    }

    /// Adds methods to the list of methods that require JWT authentication.
    /// 
    /// # Arguments
    /// * `methods` - Array of gRPC method paths (e.g., "/service.Service/Method")
    pub fn intercept_methods(&mut self, methods: &[&str]) {
        for method in methods {
            self.intercepted_methods.insert(method.to_string());
        }
    }

    /// Removes methods from the list of intercepted methods.
    /// 
    /// # Arguments
    /// * `methods` - Array of gRPC method paths to stop intercepting
    pub fn ignore_methods(&mut self, methods: &[&str]) {
        for method in methods {
            self.intercepted_methods.remove(*method);
        }
    }

    /// Checks if a method requires JWT authentication.
    /// 
    /// # Arguments
    /// * `method` - The gRPC method path to check
    /// 
    /// # Returns
    /// * `true` - If method requires authentication
    /// * `false` - If method is public
    fn check_method(&self, method: &str) -> bool {
        self.intercepted_methods.contains(method)
    }

    /// Extracts JWT token from request metadata.
    /// 
    /// Currently looks for token in the "token" metadata key.
    /// 
    /// # Arguments
    /// * `metadata` - The request metadata map
    /// 
    /// # Returns
    /// * `Some(String)` - The extracted token
    /// * `None` - If no token found or token is invalid
    fn extract_token_from_metadata(&self, metadata: &MetadataMap) -> Option<String> {
        metadata.get("token")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    }

    /// Validates a JWT token and extracts user identity.
    /// 
    /// This is the core authentication logic that:
    /// 1. Decodes and validates the JWT token
    /// 2. Checks token expiration
    /// 3. Extracts user identity from claims
    /// 4. Performs authorization check
    /// 
    /// # Arguments
    /// * `token_string` - The JWT token to validate
    /// 
    /// # Returns
    /// * `Ok((claims, identity))` - Token is valid with claims and identity
    /// * `Err(Status)` - Token is invalid, expired, or user is unauthorized
    fn validate_token_and_get_identity(
        &self, 
        token_string: &str
    ) -> Result<(Map<String, Value>, Value), Status> {
        // Get claims from JWT
        let claims = self.jwt_object.get_claims(token_string)
            .map_err(|e| Status::unauthenticated(e.to_string()))?;

        // Check expiration
        self.jwt_object.ensure_not_expired(&claims)
            .map_err(|e| Status::unauthenticated(e.to_string()))?;

        // Extract identity
        let identity = (self.identity_handler)(&claims)
            .ok_or_else(|| Status::unauthenticated("invalid identity"))?;

        // Check authorization
        if !(self.authorizator)(&identity) {
            return Err(Status::permission_denied("forbidden"));
        }

        Ok((claims, identity))
    }

    /// Interceptor for unary gRPC calls.
    /// 
    /// Validates JWT tokens for protected methods. Public methods are allowed through
    /// without authentication.
    /// 
    /// # Arguments
    /// * `req` - The incoming gRPC request
    /// * `method` - The gRPC method path being called
    /// 
    /// # Returns
    /// * `Ok(Request)` - Request is authenticated or method is public
    /// * `Err(Status)` - Authentication failed or token is invalid
    pub fn auth_interceptor(
        &self,
        req: Request<()>,
        method: &str,
    ) -> Result<Request<()>, Status> {
        if !self.check_method(method) {
            return Ok(req);
        }

        let metadata = req.metadata();
        let token_string = self.extract_token_from_metadata(metadata)
            .ok_or_else(|| Status::unauthenticated("missing token in metadata"))?;

        let (_claims, _identity) = self.validate_token_and_get_identity(&token_string)?;

        Ok(req)
    }

    /// Interceptor for streaming gRPC calls.
    /// 
    /// Similar to unary interceptor but designed for streaming endpoints.
    /// Validates JWT tokens for protected streaming methods.
    /// 
    /// # Arguments
    /// * `req` - The incoming gRPC request
    /// * `method` - The gRPC method path being called
    /// 
    /// # Returns
    /// * `Ok(Request)` - Request is authenticated or method is public
    /// * `Err(Status)` - Authentication failed or token is invalid
    pub fn auth_stream_interceptor(
        &self,
        req: Request<()>,
        method: &str,
    ) -> Result<Request<()>, Status> {
        if !self.check_method(method) {
            return Ok(req);
        }

        let metadata = req.metadata();
        let token_string = self.extract_token_from_metadata(metadata)
            .ok_or_else(|| Status::unauthenticated("missing token in metadata"))?;

        let (_claims, _identity) = self.validate_token_and_get_identity(&token_string)?;

        Ok(req)
    }

    /// Extracts and validates claims from a JWT token.
    /// 
    /// Utility method to get claims without performing full authentication.
    /// Useful for extracting user data from valid tokens.
    /// 
    /// # Arguments
    /// * `token` - The JWT token string
    /// 
    /// # Returns
    /// * `Ok(Map<String, Value>)` - The token claims
    /// * `Err(JwtError)` - If token is invalid or malformed
    pub fn get_claims_from_jwt(&self, token: &str) -> Result<Map<String, Value>, JwtError> {
        self.jwt_object.get_claims(token)
    }
}

#[async_trait]
impl jwt_service_server::JwtService for JwtInterceptor {
    /// LoginHandler implementation
    async fn login_handler(
        &self,
        request: Request<LoginRequest>,
    ) -> Result<Response<LoginResponse>, Status> {
        let req = request.into_inner();
        
        // Authenticate user
        let data = (self.authenticator)(&req.username, &req.password)
            .map_err(|e| Status::unauthenticated(e.to_string()))?;

        // Create claims with payload function if available
        let mut extra = if let Some(payload_func) = &self.payload_func {
            (payload_func)(&data)
        } else {
            Map::new()
        };

        // Add identity to claims
        extra.insert(self.jwt_object.opts.identity_key.clone(), data);

        // Sign token
        match self.jwt_object.sign_with_extra(extra) {
            Ok((token, expire)) => Ok(Response::new(LoginResponse {
                code: 200,
                token,
                expire,
            })),
            Err(_) => Ok(Response::new(LoginResponse {
                code: 500,
                token: String::new(),
                expire: 0,
            })),
        }
    }

    /// RefreshToken implementation
    async fn refresh_token(
        &self,
        request: Request<NoArguments>,
    ) -> Result<Response<RefreshTokenResponse>, Status> {
        let metadata = request.metadata();
        let token_string = self.extract_token_from_metadata(metadata)
            .ok_or_else(|| Status::unauthenticated("missing token in metadata"))?;

        let claims = match self.jwt_object.check_if_token_expire(&token_string) {
            Ok(claims) => claims,
            Err(_) => {
                return Ok(Response::new(RefreshTokenResponse {
                    code: 500,
                    token: String::new(),
                    expire: 0,
                }));
            }
        };

        // Create new token with refreshed claims
        match self.jwt_object.sign_with_extra(claims) {
            Ok((token, expire)) => Ok(Response::new(RefreshTokenResponse {
                code: 200,
                token,
                expire,
            })),
            Err(_) => Ok(Response::new(RefreshTokenResponse {
                code: 500,
                token: String::new(),
                expire: 0,
            })),
        }
    }
}

// Helper functions for use in other parts of your application
pub fn get_claims_from_request<T>(req: &Request<T>) -> Option<&Map<String, Value>> {
    req.extensions().get::<Map<String, Value>>()
}

pub fn get_identity_from_request<T>(req: &Request<T>) -> Option<&Value> {
    req.extensions().get::<Value>()
}

// Tonic interceptor wrapper for unary calls
pub fn create_unary_interceptor(
    jwt_interceptor: Arc<JwtInterceptor>,
) -> impl Fn(Request<()>) -> Result<Request<()>, Status> + Clone {
    move |req: Request<()>| {
        // Extract method info - you'll need to get this from tonic's internals
        // For now, we'll use a placeholder
        let method = "/example.Service/Method"; // You'd extract this properly
        jwt_interceptor.auth_interceptor(req, method)
    }
}

// Tonic interceptor wrapper for stream calls  
pub fn create_stream_interceptor(
    jwt_interceptor: Arc<JwtInterceptor>,
) -> impl Fn(Request<()>) -> Result<Request<()>, Status> + Clone {
    move |req: Request<()>| {
        // Extract method info - you'll need to get this from tonic's internals
        let method = "/example.Service/Method"; // You'd extract this properly
        jwt_interceptor.auth_stream_interceptor(req, method)
    }
}