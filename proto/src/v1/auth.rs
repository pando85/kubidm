use serde::{Deserialize, Serialize};
use std::{cmp::Ordering, fmt};
use utoipa::ToSchema;
use uuid::Uuid;

use webauthn_rs_proto::{PublicKeyCredential, RequestChallengeResponse};

/// Authentication to Kubidm is a stepped process.
///
/// The session is first initialised with the requested username.
///
/// In response the list of supported authentication mechanisms is provided.
///
/// The user chooses the authentication mechanism to proceed with.
///
/// The server responds with a challenge that the user provides a credential
/// to satisfy. This challenge and response process continues until a credential
/// fails to validate, an error occurs, or successful authentication is complete.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum AuthStep {
    /// Initialise a new authentication session
    Init(String),
    /// Initialise a new authentication session with extra flags
    /// for requesting different types of session tokens or
    /// immediate access to privileges.
    Init2 {
        username: String,
        issue: AuthIssueSession,
        #[serde(default)]
        /// If true, the session will have r/w access.
        privileged: bool,
    },
    /// Request the named authentication mechanism to proceed
    Begin(AuthMech),
    /// Provide a credential in response to a challenge
    Cred(AuthCredential),
}

/// The response to an AuthStep request.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum AuthState {
    /// You need to select how you want to proceed.
    Choose(Vec<AuthMech>),
    /// Continue to auth, allowed mechanisms/challenges listed.
    Continue(Vec<AuthAllowed>),
    /// Something was bad, your session is terminated and no cookie.
    Denied(String),
    /// Everything is good, your bearer token has been issued and is within.
    Success(String),
}

/// The credential challenge provided by a user.
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum AuthCredential {
    Anonymous,
    Password(String),
    Totp(u32),

    #[schema(value_type = HashMap<String, Value>)]
    SecurityKey(Box<PublicKeyCredential>),
    BackupCode(String),
    // Should this just be discoverable?
    #[schema(value_type = String)]
    Passkey(Box<PublicKeyCredential>),
}

impl fmt::Debug for AuthCredential {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AuthCredential::Anonymous => write!(fmt, "Anonymous"),
            AuthCredential::Password(_) => write!(fmt, "Password(_)"),
            AuthCredential::Totp(_) => write!(fmt, "TOTP(_)"),
            AuthCredential::SecurityKey(_) => write!(fmt, "SecurityKey(_)"),
            AuthCredential::BackupCode(_) => write!(fmt, "BackupCode(_)"),
            AuthCredential::Passkey(_) => write!(fmt, "Passkey(_)"),
        }
    }
}

/// The mechanisms that may proceed in this authentication
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialOrd, Ord, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum AuthMech {
    Anonymous,
    Password,
    PasswordBackupCode,
    // Now represents TOTP.
    #[serde(rename = "passwordmfa")]
    PasswordTotp,
    PasswordSecurityKey,
    Passkey,
    OAuth2Trust,
}

impl AuthMech {
    pub fn to_value(&self) -> &'static str {
        match self {
            AuthMech::Anonymous => "anonymous",
            AuthMech::Password => "password",
            AuthMech::PasswordTotp => "passwordmfa",
            AuthMech::PasswordBackupCode => "passwordbackupcode",
            AuthMech::PasswordSecurityKey => "passwordsecuritykey",
            AuthMech::Passkey => "passkey",
            AuthMech::OAuth2Trust => "oauth2trust",
        }
    }
}

impl PartialEq for AuthMech {
    fn eq(&self, other: &Self) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}

impl fmt::Display for AuthMech {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthMech::Anonymous => write!(f, "Anonymous (no credentials)"),
            AuthMech::Password => write!(f, "Password"),
            AuthMech::PasswordTotp => write!(f, "TOTP and Password"),
            AuthMech::PasswordBackupCode => write!(f, "Backup Code and Password"),
            AuthMech::PasswordSecurityKey => write!(f, "Security Key and Password"),
            AuthMech::Passkey => write!(f, "Passkey"),
            AuthMech::OAuth2Trust => write!(f, "OAuth2 Trust"),
        }
    }
}

/// The type of session that should be issued to the client.
#[derive(Debug, Serialize, Deserialize, Copy, Clone, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum AuthIssueSession {
    /// Issue a bearer token for this client. This is the default.
    Token,
    /// Issue a cookie for this client.
    Cookie,
}

impl std::fmt::Display for AuthIssueSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthIssueSession::Token => write!(f, "Token"),
            AuthIssueSession::Cookie => write!(f, "Cookie"),
        }
    }
}

/// A request for the next step of an authentication.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AuthRequest {
    pub step: AuthStep,
}

/// A challenge containing the list of allowed authentication types
/// that can satisfy the next step. These may have inner types with
/// required context.
#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum AuthAllowed {
    Anonymous,
    BackupCode,
    Password,
    Totp,

    #[schema(value_type = HashMap<String, Value>)]
    SecurityKey(RequestChallengeResponse),
    #[schema(value_type = HashMap<String, Value>)]
    Passkey(RequestChallengeResponse),
}

impl PartialEq for AuthAllowed {
    fn eq(&self, other: &Self) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}

impl From<&AuthAllowed> for u8 {
    fn from(a: &AuthAllowed) -> u8 {
        match a {
            AuthAllowed::Anonymous => 0,
            AuthAllowed::Password => 1,
            AuthAllowed::BackupCode => 2,
            AuthAllowed::Totp => 3,
            AuthAllowed::Passkey(_) => 4,
            AuthAllowed::SecurityKey(_) => 5,
        }
    }
}

impl Eq for AuthAllowed {}

impl Ord for AuthAllowed {
    fn cmp(&self, other: &Self) -> Ordering {
        let self_ord: u8 = self.into();
        let other_ord: u8 = other.into();
        self_ord.cmp(&other_ord)
    }
}

impl PartialOrd for AuthAllowed {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for AuthAllowed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthAllowed::Anonymous => write!(f, "Anonymous (no credentials)"),
            AuthAllowed::Password => write!(f, "Password"),
            AuthAllowed::BackupCode => write!(f, "Backup Code"),
            AuthAllowed::Totp => write!(f, "TOTP"),
            AuthAllowed::SecurityKey(_) => write!(f, "Security Token"),
            AuthAllowed::Passkey(_) => write!(f, "Passkey"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AuthResponse {
    pub sessionid: Uuid,
    pub state: AuthState,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_mech_to_value() {
        assert_eq!(AuthMech::Anonymous.to_value(), "anonymous");
        assert_eq!(AuthMech::Password.to_value(), "password");
        assert_eq!(AuthMech::PasswordTotp.to_value(), "passwordmfa");
        assert_eq!(
            AuthMech::PasswordBackupCode.to_value(),
            "passwordbackupcode"
        );
        assert_eq!(
            AuthMech::PasswordSecurityKey.to_value(),
            "passwordsecuritykey"
        );
        assert_eq!(AuthMech::Passkey.to_value(), "passkey");
        assert_eq!(AuthMech::OAuth2Trust.to_value(), "oauth2trust");
    }

    #[test]
    fn test_auth_mech_display() {
        assert_eq!(
            AuthMech::Anonymous.to_string(),
            "Anonymous (no credentials)"
        );
        assert_eq!(AuthMech::Password.to_string(), "Password");
        assert_eq!(AuthMech::PasswordTotp.to_string(), "TOTP and Password");
        assert_eq!(
            AuthMech::PasswordBackupCode.to_string(),
            "Backup Code and Password"
        );
        assert_eq!(
            AuthMech::PasswordSecurityKey.to_string(),
            "Security Key and Password"
        );
        assert_eq!(AuthMech::Passkey.to_string(), "Passkey");
        assert_eq!(AuthMech::OAuth2Trust.to_string(), "OAuth2 Trust");
    }

    #[test]
    fn test_auth_mech_eq() {
        assert_eq!(AuthMech::Password, AuthMech::Password);
        assert_ne!(AuthMech::Password, AuthMech::PasswordTotp);
        assert_ne!(AuthMech::Anonymous, AuthMech::Password);
    }

    #[test]
    fn test_auth_mech_serde() {
        let mech = AuthMech::Password;
        let json = serde_json::to_string(&mech).expect("Failed to serialize");
        assert_eq!(json, "\"password\"");

        let deserialized: AuthMech = serde_json::from_str(&json).expect("Failed to deserialize");
        assert_eq!(deserialized, AuthMech::Password);
    }

    #[test]
    fn test_auth_mech_serde_passwordmfa() {
        // PasswordTotp uses custom serde rename
        let mech = AuthMech::PasswordTotp;
        let json = serde_json::to_string(&mech).expect("Failed to serialize");
        assert_eq!(json, "\"passwordmfa\"");

        let deserialized: AuthMech = serde_json::from_str(&json).expect("Failed to deserialize");
        assert_eq!(deserialized, AuthMech::PasswordTotp);
    }

    #[test]
    fn test_auth_credential_debug_does_not_leak() {
        let cred = AuthCredential::Password("super-secret".to_string());
        let debug = format!("{:?}", cred);
        assert_eq!(debug, "Password(_)");
        assert!(!debug.contains("super-secret"));

        let cred = AuthCredential::BackupCode("secret-code".to_string());
        let debug = format!("{:?}", cred);
        assert_eq!(debug, "BackupCode(_)");
        assert!(!debug.contains("secret-code"));

        let cred = AuthCredential::Totp(123456);
        let debug = format!("{:?}", cred);
        assert_eq!(debug, "TOTP(_)");
    }

    #[test]
    fn test_auth_issue_session_serde() {
        let token = AuthIssueSession::Token;
        let json = serde_json::to_string(&token).expect("Failed to serialize");
        assert_eq!(json, "\"token\"");
        let deserialized: AuthIssueSession =
            serde_json::from_str(&json).expect("Failed to deserialize");
        assert!(matches!(deserialized, AuthIssueSession::Token));

        let cookie = AuthIssueSession::Cookie;
        let json = serde_json::to_string(&cookie).expect("Failed to serialize");
        assert_eq!(json, "\"cookie\"");
        let deserialized: AuthIssueSession =
            serde_json::from_str(&json).expect("Failed to deserialize");
        assert!(matches!(deserialized, AuthIssueSession::Cookie));
    }

    #[test]
    fn test_auth_step_init() {
        let step = AuthStep::Init("testuser".to_string());
        let json = serde_json::to_string(&step).expect("Failed to serialize");
        assert!(json.contains("testuser"));
    }

    #[test]
    fn test_auth_step_init2() {
        let step = AuthStep::Init2 {
            username: "testuser".to_string(),
            issue: AuthIssueSession::Token,
            privileged: true,
        };
        let json = serde_json::to_string(&step).expect("Failed to serialize");
        assert!(json.contains("testuser"));
        assert!(json.contains("privileged"));
    }

    #[test]
    fn test_auth_state_denied() {
        let state = AuthState::Denied("Invalid credentials".to_string());
        let json = serde_json::to_string(&state).expect("Failed to serialize");
        assert!(json.contains("denied"));
        assert!(json.contains("Invalid credentials"));
    }

    #[test]
    fn test_auth_state_success() {
        let state = AuthState::Success("bearer-token-123".to_string());
        let json = serde_json::to_string(&state).expect("Failed to serialize");
        assert!(json.contains("success"));
        assert!(json.contains("bearer-token-123"));
    }

    #[test]
    fn test_auth_allowed_ordering() {
        // Test that AuthAllowed variants are ordered correctly
        let mut allowed = [
            AuthAllowed::Totp,
            AuthAllowed::Anonymous,
            AuthAllowed::Password,
            AuthAllowed::BackupCode,
        ];
        allowed.sort();

        assert_eq!(allowed[0], AuthAllowed::Anonymous);
        assert_eq!(allowed[1], AuthAllowed::Password);
        assert_eq!(allowed[2], AuthAllowed::BackupCode);
        assert_eq!(allowed[3], AuthAllowed::Totp);
    }

    #[test]
    fn test_auth_allowed_display() {
        assert_eq!(
            AuthAllowed::Anonymous.to_string(),
            "Anonymous (no credentials)"
        );
        assert_eq!(AuthAllowed::Password.to_string(), "Password");
        assert_eq!(AuthAllowed::BackupCode.to_string(), "Backup Code");
        assert_eq!(AuthAllowed::Totp.to_string(), "TOTP");
    }

    #[test]
    fn test_auth_allowed_eq() {
        assert_eq!(AuthAllowed::Password, AuthAllowed::Password);
        assert_ne!(AuthAllowed::Password, AuthAllowed::Totp);
    }

    #[test]
    fn test_auth_allowed_from_u8() {
        assert_eq!(u8::from(&AuthAllowed::Anonymous), 0);
        assert_eq!(u8::from(&AuthAllowed::Password), 1);
        assert_eq!(u8::from(&AuthAllowed::BackupCode), 2);
        assert_eq!(u8::from(&AuthAllowed::Totp), 3);
    }

    #[test]
    fn test_auth_request_serde() {
        let req = AuthRequest {
            step: AuthStep::Begin(AuthMech::Password),
        };
        let json = serde_json::to_string(&req).expect("Failed to serialize");
        assert!(json.contains("begin"));
        assert!(json.contains("password"));
    }

    #[test]
    fn test_auth_response_serde() {
        let resp = AuthResponse {
            sessionid: Uuid::nil(),
            state: AuthState::Success("token".to_string()),
        };
        let json = serde_json::to_string(&resp).expect("Failed to serialize");
        assert!(json.contains("sessionid"));
        assert!(json.contains("state"));

        let deserialized: AuthResponse =
            serde_json::from_str(&json).expect("Failed to deserialize");
        assert_eq!(deserialized.sessionid, Uuid::nil());
        assert!(matches!(deserialized.state, AuthState::Success(_)));
    }
}
