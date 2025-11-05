use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// JWT claims for user sessions
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,      // User ID
    pub email: String,    // Email
    pub role: UserRole,   // device_owner or proxy_user
    pub exp: i64,         // Expiration time
    pub iat: i64,         // Issued at
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    DeviceOwner,
    ProxyUser,
}

impl Claims {
    pub fn new(user_id: String, email: String, role: UserRole) -> Self {
        let now = Utc::now();
        let exp = now + Duration::hours(24); // 24 hour expiration

        Self {
            sub: user_id,
            email,
            role,
            exp: exp.timestamp(),
            iat: now.timestamp(),
        }
    }
}

/// JWT token manager
pub struct JwtManager {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl JwtManager {
    pub fn new(secret: &str) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(secret.as_bytes()),
        }
    }

    pub fn create_token(&self, claims: Claims) -> Result<String, AuthError> {
        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| AuthError::TokenCreationError(e.to_string()))
    }

    pub fn verify_token(&self, token: &str) -> Result<Claims, AuthError> {
        let token_data = decode::<Claims>(token, &self.decoding_key, &Validation::default())
            .map_err(|e| AuthError::InvalidToken(e.to_string()))?;

        Ok(token_data.claims)
    }
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Token creation error: {0}")]
    TokenCreationError(String),

    #[error("Invalid token: {0}")]
    InvalidToken(String),

    #[error("Unauthorized")]
    Unauthorized,
}
