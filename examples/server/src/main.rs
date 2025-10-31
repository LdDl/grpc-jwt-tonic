use grpc_jwt_tonic::{
    jwt_engine::{JwtEngine, JwtEngineOptions, AlgorithmKind},
    interceptor::JwtInterceptor,
    grpcjwt::jwt_service_server::JwtServiceServer,
};
use serde_json::{Map, Value};
use std::{pin::Pin, sync::Arc, time::Duration};
use tokio::time::sleep;
use tokio_stream::{wrappers::ReceiverStream, Stream};
use tonic::{transport::Server, Request, Response, Status};

// Import the generated module directly (since build.rs outputs to ./src)
mod server_example;

use server_example::{
    server_example_server::{ServerExample, ServerExampleServer},
    HiddenData, NoArguments, PublicData,
};

#[derive(Default)]
pub struct MyCustomServer {
    jwt_interceptor: Option<Arc<JwtInterceptor>>,
}

impl MyCustomServer {
    pub fn new(jwt_interceptor: Arc<JwtInterceptor>) -> Self {
        Self {
            jwt_interceptor: Some(jwt_interceptor),
        }
    }
}

// ADD THIS MISSING TRAIT IMPLEMENTATION
#[tonic::async_trait]
impl ServerExample for MyCustomServer {
    async fn get_hidden_data(
        &self,
        _request: Request<NoArguments>,
    ) -> Result<Response<HiddenData>, Status> {
        println!("GetHiddenData called - JWT authentication required");
        
        let response = HiddenData {
            message: "this is very hidden data (jwt token is required)".to_string(),
        };
        
        Ok(Response::new(response))
    }

    type GetHiddenStreamDataStream = Pin<Box<dyn Stream<Item = Result<HiddenData, Status>> + Send>>;
    
    async fn get_hidden_stream_data(
        &self,
        _request: Request<NoArguments>,
    ) -> Result<Response<Self::GetHiddenStreamDataStream>, Status> {
        println!("GetHiddenStreamData called - JWT authentication required");
        
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        
        tokio::spawn(async move {
            for i in 0..3 {
                let message = HiddenData {
                    message: format!("Ping #{}", i),
                };
                
                if tx.send(Ok(message)).await.is_err() {
                    break;
                }
                
                sleep(Duration::from_secs(1)).await;
            }
        });

        let output_stream = ReceiverStream::new(rx);
        Ok(Response::new(Box::pin(output_stream) as Self::GetHiddenStreamDataStream))
    }

    async fn get_public_data(
        &self,
        _request: Request<NoArguments>,
    ) -> Result<Response<PublicData>, Status> {
        println!("GetPublicData called - no JWT authentication required");
        
        let response = PublicData {
            message: "this is public data (jwt token is not required)".to_string(),
        };
        
        Ok(Response::new(response))
    }
}

// ADD THE MISSING DATABASE TYPES AND IMPLEMENTATIONS
#[derive(Debug, Clone)]
struct UserData {
    name: String,
    password: String,
    description: String,
    access: String,
}

type Database = Vec<UserData>;

trait DatabaseOps {
    fn check_user(&self, login: &str) -> Option<UserData>;
}

impl DatabaseOps for Database {
    fn check_user(&self, login: &str) -> Option<UserData> {
        self.iter().find(|user| user.name == login).cloned()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "127.0.0.1:65012".parse()?;

    // Database setup
    let database: Database = vec![
        UserData {
            name: "user".to_string(),
            password: "pass".to_string(),
            description: "simple user".to_string(),
            access: "Authentication".to_string(),
        },
        UserData {
            name: "user2".to_string(),
            password: "pass".to_string(),
            description: "simple user2".to_string(),
            access: "Banned".to_string(),
        },
    ];

    let database_arc = Arc::new(database);

    // JWT Engine setup
    let opts = JwtEngineOptions {
        realm: "my custom realm".to_string(),
        alg: AlgorithmKind::HS256(b"my very secret key".to_vec()),
        timeout: Duration::from_secs(3600 * 24 * 7),
        max_refresh: Duration::from_secs(3600 * 24 * 7),
        identity_key: "my identity key".to_string(),
        ..Default::default()
    };

    let jwt_engine = Arc::new(JwtEngine::new(opts)?);

    // Handler setup
    let payload_func = {
        let db = database_arc.clone();
        Arc::new(move |login: &Value| -> Map<String, Value> {
            if let Some(login_str) = login.as_str() {
                if let Some(user) = db.check_user(login_str) {
                    let mut payload = Map::new();
                    payload.insert("login".to_string(), Value::String(login_str.to_string()));
                    payload.insert("desc".to_string(), Value::String(user.description));
                    return payload;
                }
            }
            Map::new()
        })
    };

    let identity_handler = Arc::new(|claims: &Map<String, Value>| -> Option<Value> {
        let login = claims.get("login")?.as_str()?;
        let desc = claims.get("desc")?.as_str()?;
        
        let mut user_data = Map::new();
        user_data.insert("name".to_string(), Value::String(login.to_string()));
        user_data.insert("description".to_string(), Value::String(desc.to_string()));
        
        Some(Value::Object(user_data))
    });

    let authenticator = {
        let db = database_arc.clone();
        Arc::new(move |username: &str, password: &str| -> Result<Value, grpc_jwt_tonic::jwt_engine::JwtError> {
            let user = db.check_user(username)
                .ok_or(grpc_jwt_tonic::jwt_engine::JwtError::FailedAuthentication)?;
            
            println!("Authenticating user: '{}' with password: '{}'", username, password);
            if password == user.password && user.access == "Authentication" {
                Ok(Value::String(username.to_string()))
            } else if user.access != "Authentication" {
                Err(grpc_jwt_tonic::jwt_engine::JwtError::Forbidden)
            } else {
                Err(grpc_jwt_tonic::jwt_engine::JwtError::FailedAuthentication)
            }
        })
    };

    let authorizator = {
        let db = database_arc.clone();
        Arc::new(move |user_info: &Value| -> bool {
            if let Some(user_obj) = user_info.as_object() {
                if let Some(name) = user_obj.get("name").and_then(|v| v.as_str()) {
                    if let Some(user) = db.check_user(name) {
                        return user.access == "Authentication";
                    }
                }
            }
            false
        })
    };

    let methods_to_intercept = [
        "/server_example.ServerExample/GetHiddenData",
        "/server_example.ServerExample/GetHiddenStreamData",
        "/grpcjwt.JWTService/RefreshToken",
    ];

    // Create two separate JwtInterceptor instances since we need to move them
    let jwt_interceptor_for_server = JwtInterceptor::new(
        jwt_engine.clone(),
        identity_handler.clone(),
        authorizator.clone(),
        authenticator.clone(),
        &methods_to_intercept,
    )?.with_payload_func(payload_func.clone());

    let jwt_interceptor_for_jwt_service = JwtInterceptor::new(
        jwt_engine,
        identity_handler,
        authorizator,
        authenticator,
        &methods_to_intercept,
    )?.with_payload_func(payload_func);

    let my_custom_server = MyCustomServer::new(Arc::new(jwt_interceptor_for_server));

    println!("🚀 Starting gRPC server on {}...", addr);
    println!("📝 Available services:");
    println!("   - ServerExample (GetPublicData, GetHiddenData*, GetHiddenStreamData*)");
    println!("   - JWTService (LoginHandler, RefreshToken*) [from library]");
    println!("   * = requires JWT authentication");
    println!("👥 Test users: user/pass, user2/pass");

    Server::builder()
        .add_service(ServerExampleServer::new(my_custom_server))
        .add_service(JwtServiceServer::new(jwt_interceptor_for_jwt_service))
        .serve(addr)
        .await?;

    Ok(())
}