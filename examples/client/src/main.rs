use grpc_jwt_tonic::grpcjwt::{
    jwt_service_client::JwtServiceClient,
    LoginRequest, RefreshTokenResponse,
    NoArguments as JwtNoArguments, // Import NoArguments from JWT service
};
use serde_json::{Map, Value};
use std::time::Duration;
use tokio_stream::StreamExt;
use tonic::{
    metadata::MetadataValue,
    transport::Channel,
    Request, Status,
};

// Import ServerExample client from our generated code
mod server_example;

use server_example::{
    server_example_client::ServerExampleClient,
    NoArguments as ServerNoArguments, // Rename to avoid conflict
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server_addr = "http://127.0.0.1:65012";

    println!("🚀 Connecting to Rust gRPC JWT server at {}", server_addr);

    // Connect to server
    let channel = Channel::from_static(server_addr).connect().await?;

    // Create JWT client for authentication
    let mut jwt_client = JwtServiceClient::new(channel.clone());

    // Create ServerExample client for business logic
    let mut server_client = ServerExampleClient::new(channel.clone());

    println!("\n1️⃣ Testing GetPublicData (no authentication required)...");
    
    // Test public data (no authentication required)
    let public_response = server_client
        .get_public_data(Request::new(ServerNoArguments {})) // Use ServerNoArguments
        .await?;
    
    println!("✅ Public data: {}", public_response.into_inner().message);

    println!("\n2️⃣ Logging in...");

    // Login to get JWT token
    let login_request = LoginRequest {
        username: "user".to_string(),
        password: "pass".to_string(),
    };

    let login_response = jwt_client
        .login_handler(Request::new(login_request))
        .await?;

    let token = login_response.into_inner().token;
    println!("✅ Received JWT token: {}...", &token[0..20.min(token.len())]);

    println!("\n3️⃣ Testing GetHiddenData (JWT authentication required)...");

    // Test hidden data (JWT required)
    let mut hidden_request = Request::new(ServerNoArguments {}); // Use ServerNoArguments
    
    // Add JWT token to metadata
    let token_metadata = MetadataValue::try_from(&token)?;
    hidden_request.metadata_mut().insert("token", token_metadata.clone());

    let hidden_response = server_client
        .get_hidden_data(hidden_request)
        .await?;

    println!("✅ Hidden data: {}", hidden_response.into_inner().message);

    println!("\n4️⃣ Testing RefreshToken...");

    // Test token refresh - FIX: Use JwtNoArguments instead of ()
    let mut refresh_request = Request::new(JwtNoArguments {}); // Changed from () to JwtNoArguments {}
    refresh_request.metadata_mut().insert("token", token_metadata.clone());

    let refresh_response = jwt_client
        .refresh_token(refresh_request)
        .await?;

    let new_token = refresh_response.into_inner().token;
    println!("✅ Received new JWT token: {}...", &new_token[0..20.min(new_token.len())]);

    println!("\n5️⃣ Testing GetHiddenStreamData (streaming with JWT authentication)...");

    // Test streaming hidden data (JWT required)
    let mut stream_request = Request::new(ServerNoArguments {}); // Use ServerNoArguments
    let stream_token_metadata = MetadataValue::try_from(&new_token)?;
    stream_request.metadata_mut().insert("token", stream_token_metadata);

    let mut stream_response = server_client
        .get_hidden_stream_data(stream_request)
        .await?
        .into_inner();

    // Read streaming data
    println!("📡 Receiving stream data:");
    while let Some(stream_item) = stream_response.next().await {
        match stream_item {
            Ok(data) => println!("   📦 Stream message: {}", data.message),
            Err(e) => println!("   ❌ Stream error: {}", e),
        }
    }

    println!("\n🎉 All tests completed successfully!");
    println!("🔗 Rust client ↔️ Rust server communication working perfectly!");

    Ok(())
}