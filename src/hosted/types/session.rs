// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Session types for hosted verification flows.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Lifecycle states for a hosted verification session.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SessionState {
    /// Session created, waiting for proof submission
    Pending,

    /// Proof received and validated by provii-verifier
    /// Note: Serializes to "proof_ok_waiting_for_redeem" to match provii-agegate expectations
    #[serde(rename = "proof_ok_waiting_for_redeem")]
    ProofOk,

    /// Full verification complete, credential redeemed
    Verified,

    /// Session expired before completion
    Expired,

    /// Session manually revoked
    Revoked,
}

impl SessionState {
    /// Check if this state allows status checks.
    pub fn can_check_status(&self) -> bool {
        matches!(
            self,
            SessionState::Pending | SessionState::ProofOk | SessionState::Verified
        )
    }

    /// Check if this state allows redemption.
    pub fn can_redeem(&self) -> bool {
        matches!(self, SessionState::ProofOk)
    }

    /// Check if the session is in a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            SessionState::Verified | SessionState::Expired | SessionState::Revoked
        )
    }

    /// Validate whether a state transition from `self` to `to` is permitted.
    ///
    /// The allowed transitions form a strict DAG:
    ///
    ///   Pending  -> ProofOk, Expired, Revoked
    ///   ProofOk  -> Verified, Expired, Revoked
    ///
    /// Terminal states (Verified, Expired, Revoked) cannot transition anywhere.
    /// Self-transitions are rejected (no-op updates should not reach this check).
    pub fn is_valid_transition(&self, to: SessionState) -> bool {
        if *self == to {
            return false;
        }
        matches!(
            (self, to),
            (SessionState::Pending, SessionState::ProofOk)
                | (SessionState::Pending, SessionState::Expired)
                | (SessionState::Pending, SessionState::Revoked)
                | (SessionState::ProofOk, SessionState::Verified)
                | (SessionState::ProofOk, SessionState::Expired)
                | (SessionState::ProofOk, SessionState::Revoked)
        )
    }
}

/// Session binding mode for IP/User-Agent validation
#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SessionBindingMode {
    /// Strict: Reject any IP or User-Agent mismatch
    Strict,

    /// Relaxed: Log warning but allow (for mobile IP changes)
    #[default]
    Relaxed,

    /// Reserved for future use. No code path currently sets this variant.
    /// All sessions default to Relaxed. Maintained for serde compatibility
    /// and exhaustive match coverage.
    None,
}

/// Complete session state for a hosted verification flow.
///
/// This struct contains all information needed to track a verification session
/// from creation through redemption. Sensitive fields like `code_verifier` are
/// encrypted before storage.
///
/// # SECURITY: Memory Zeroisation (ASVS 11.7.1 L3)
///
/// Implements a manual `Drop` that zeroises `code_verifier`, `nonce`, and
/// `credential_data` when the struct is dropped. Debug output redacts these
/// same fields to prevent accidental logging of secret material.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostedSession {
    /// Unique session identifier (UUID v4)
    pub session_id: String,

    /// Public key of the relying party that owns this session
    pub public_key: String,

    /// Origin (scheme + host + port) that initiated the session
    pub origin: String,

    /// Current session lifecycle state
    pub state: SessionState,

    /// PKCE code challenge (SHA-256 hash of code_verifier, base64url)
    pub code_challenge: String,

    /// PKCE code verifier (encrypted with MEK before storage)
    pub code_verifier: String,

    /// provii-verifier challenge ID for this verification
    pub verifier_challenge_id: String,

    /// Proof direction: "over_age" or "under_age"
    #[serde(default = "default_proof_direction")]
    pub proof_direction: String,

    /// Cryptographic nonce for replay protection
    pub nonce: String,

    /// When the session expires (Unix timestamp seconds)
    pub expires_at: u64,

    /// When the session was created (Unix timestamp seconds)
    pub created_at: u64,

    /// Last activity timestamp for idle timeout (Unix timestamp seconds)
    #[serde(default = "default_last_activity")]
    pub last_activity_at: u64,

    /// When the proof was submitted (Unix timestamp seconds, optional)
    pub proof_submitted_at: Option<u64>,

    /// When the session was verified (Unix timestamp seconds, optional)
    pub verified_at: Option<u64>,

    /// User agent string from the client
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,

    /// IP address of the client (hashed for privacy)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ip_hash: Option<String>,

    /// Session binding mode
    #[serde(default)]
    pub binding_mode: SessionBindingMode,

    /// Verification environment (production or sandbox)
    /// Used to route to the correct provii-verifier deployment
    #[serde(default = "default_environment")]
    pub environment: String,

    /// Credential data from provii-verifier (only set after ProofOk)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_data: Option<String>,

    /// Error message if verification failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// Number of status check requests for this session
    #[serde(default)]
    pub status_check_count: u32,

    /// Number of redemption attempts for this session
    #[serde(default)]
    pub redeem_attempt_count: u32,

    /// Verifying key ID from provii-verifier challenge response (issuer kid)
    #[serde(default)]
    pub verifying_key_id: Option<u32>,
}

impl std::fmt::Debug for HostedSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostedSession")
            .field("session_id", &self.session_id)
            .field("public_key", &self.public_key)
            .field("origin", &self.origin)
            .field("state", &self.state)
            .field("code_challenge", &self.code_challenge)
            .field("code_verifier", &"[REDACTED]")
            .field("verifier_challenge_id", &self.verifier_challenge_id)
            .field("proof_direction", &self.proof_direction)
            .field("nonce", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .field("created_at", &self.created_at)
            .field("last_activity_at", &self.last_activity_at)
            .field("proof_submitted_at", &self.proof_submitted_at)
            .field("verified_at", &self.verified_at)
            .field("binding_mode", &self.binding_mode)
            .field("environment", &self.environment)
            .field(
                "credential_data",
                &self.credential_data.as_ref().map(|_| "[REDACTED]"),
            )
            .field("status_check_count", &self.status_check_count)
            .field("redeem_attempt_count", &self.redeem_attempt_count)
            .finish()
    }
}

impl Drop for HostedSession {
    fn drop(&mut self) {
        self.code_verifier.zeroize();
        self.nonce.zeroize();
        if let Some(ref mut cred) = self.credential_data {
            cred.zeroize();
        }
    }
}

/// Default for last_activity_at during deserialisation
fn default_last_activity() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0)
}

/// Default environment is production
fn default_environment() -> String {
    "production".to_string()
}

/// Default proof direction is over_age
fn default_proof_direction() -> String {
    "over_age".to_string()
}

impl HostedSession {
    /// Create a new pending session.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: String,
        public_key: String,
        origin: String,
        code_challenge: String,
        code_verifier: String,
        verifier_challenge_id: String,
        nonce: String,
        expires_at: u64,
        environment: String,
    ) -> Self {
        let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0);
        Self {
            session_id,
            public_key,
            origin,
            state: SessionState::Pending,
            code_challenge,
            code_verifier,
            verifier_challenge_id,
            proof_direction: default_proof_direction(),
            nonce,
            expires_at,
            created_at: now,
            last_activity_at: now,
            proof_submitted_at: None,
            verified_at: None,
            user_agent: None,
            client_ip_hash: None,
            binding_mode: SessionBindingMode::default(),
            environment,
            credential_data: None,
            error: None,
            status_check_count: 0,
            redeem_attempt_count: 0,
            verifying_key_id: None,
        }
    }

    /// Check if the session has expired.
    ///
    /// Checks both absolute expiration and idle timeout:
    /// - Absolute: Current time >= expires_at
    /// - Idle: (now - last_activity_at) >= SESSION_IDLE_TIMEOUT_SEC
    ///
    /// Environment variable SESSION_IDLE_TIMEOUT_SEC defaults to 900 seconds (15 minutes).
    pub fn is_expired(&self) -> bool {
        self.is_expired_with_idle_timeout(900) // Default 15 minutes
    }

    /// Check if the session has expired with a custom idle timeout.
    ///
    /// # Arguments
    ///
    /// * `idle_timeout_seconds` - Maximum seconds of inactivity before expiration
    pub fn is_expired_with_idle_timeout(&self, idle_timeout_seconds: u64) -> bool {
        let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0);

        // Check absolute expiration
        if now >= self.expires_at {
            return true;
        }

        // Reject sessions with future activity timestamps (prevents integer underflow)
        // This defends against storage corruption or malicious timestamp manipulation
        if self.last_activity_at > now {
            return true;
        }

        // Check idle timeout (safe from underflow due to check above)
        if now.saturating_sub(self.last_activity_at) >= idle_timeout_seconds {
            return true;
        }

        false
    }

    /// Update session activity timestamp.
    ///
    /// Should be called on EVERY authenticated request to prevent idle timeout.
    pub fn update_activity(&mut self) {
        self.last_activity_at = u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0);
    }

    /// Mark the session as having received a valid proof.
    ///
    /// Only valid from the `Pending` state. Returns `false` and leaves the
    /// session unchanged if the current state is not `Pending`.
    pub fn mark_proof_ok(&mut self, credential_data: String) -> bool {
        if self.state != SessionState::Pending {
            return false;
        }
        self.state = SessionState::ProofOk;
        self.proof_submitted_at = Some(u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0));
        self.credential_data = Some(credential_data);
        true
    }

    /// Mark the session as fully verified.
    ///
    /// Only valid from the `ProofOk` state. Returns `false` and leaves the
    /// session unchanged if the transition is invalid.
    pub fn mark_verified(&mut self) -> bool {
        if !self.state.is_valid_transition(SessionState::Verified) {
            return false;
        }
        self.state = SessionState::Verified;
        self.verified_at = Some(u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0));
        true
    }

    /// Mark the session as expired.
    ///
    /// Only valid from `Pending` or `ProofOk` states. Returns `false` and
    /// leaves the session unchanged if the session is already terminal.
    pub fn mark_expired(&mut self) -> bool {
        if !self.state.is_valid_transition(SessionState::Expired) {
            return false;
        }
        self.state = SessionState::Expired;
        true
    }

    /// Mark the session as revoked.
    ///
    /// Only valid from `Pending` or `ProofOk` states. Returns `false` and
    /// leaves the session unchanged if the session is already terminal.
    pub fn mark_revoked(&mut self, reason: String) -> bool {
        if !self.state.is_valid_transition(SessionState::Revoked) {
            return false;
        }
        self.state = SessionState::Revoked;
        self.error = Some(reason);
        true
    }

    /// Increment the status check counter.
    pub fn increment_status_checks(&mut self) {
        self.status_check_count = self.status_check_count.saturating_add(1);
    }

    /// Increment the redemption attempt counter.
    pub fn increment_redeem_attempts(&mut self) {
        self.redeem_attempt_count = self.redeem_attempt_count.saturating_add(1);
    }

    /// Set session binding fields (IP hash and User-Agent hash).
    ///
    /// This should be called immediately after session creation to bind
    /// the session to the client's IP and User-Agent for security.
    pub fn set_binding(&mut self, client_ip_hash: Option<String>, user_agent_hash: Option<String>) {
        self.client_ip_hash = client_ip_hash;
        self.user_agent = user_agent_hash;
    }

    /// SECURITY: Regenerate session ID for session fixation prevention.
    ///
    /// Creates a new session with a fresh cryptographically random session ID,
    /// copying all existing session data and resetting `last_activity_at`.
    ///
    /// # Arguments
    ///
    /// * `extend_expiry` - If true, extends `expires_at` by the original TTL
    ///
    /// # Returns
    ///
    /// Tuple of `(new_session_id, new_session)`.
    ///
    /// Uses UUID v4 for the new session ID. The caller must invalidate the old
    /// session ID immediately, update storage, update the cookie, and audit
    /// log the regeneration.
    pub fn regenerate_id(&self, extend_expiry: bool) -> (String, Self) {
        use uuid::Uuid;

        // Generate new cryptographically random session ID
        let new_session_id = Uuid::new_v4().to_string();

        let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0);

        // Calculate new expiry if extending
        let new_expires_at = if extend_expiry {
            // Calculate original TTL and extend
            let original_ttl = self.expires_at.saturating_sub(self.created_at);
            now.saturating_add(original_ttl)
        } else {
            self.expires_at
        };

        // Create new session with regenerated ID
        let new_session = Self {
            session_id: new_session_id.clone(),
            public_key: self.public_key.clone(),
            origin: self.origin.clone(),
            state: self.state,
            code_challenge: self.code_challenge.clone(),
            code_verifier: self.code_verifier.clone(),
            verifier_challenge_id: self.verifier_challenge_id.clone(),
            proof_direction: self.proof_direction.clone(),
            nonce: self.nonce.clone(),
            expires_at: new_expires_at,
            created_at: self.created_at,
            last_activity_at: now, // Reset activity timestamp
            proof_submitted_at: self.proof_submitted_at,
            verified_at: self.verified_at,
            user_agent: self.user_agent.clone(),
            client_ip_hash: self.client_ip_hash.clone(),
            binding_mode: self.binding_mode,
            environment: self.environment.clone(),
            credential_data: self.credential_data.clone(),
            error: self.error.clone(),
            status_check_count: self.status_check_count,
            redeem_attempt_count: self.redeem_attempt_count,
            verifying_key_id: self.verifying_key_id,
        };

        (new_session_id, new_session)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_session() -> HostedSession {
        HostedSession::new(
            "sess-123".to_string(),
            "pk-test".to_string(),
            "https://example.com".to_string(),
            "challenge-hash".to_string(),
            "verifier-secret".to_string(),
            "vcid-123".to_string(),
            "nonce-abc".to_string(),
            u64::try_from(chrono::Utc::now().timestamp())
                .unwrap_or(0)
                .saturating_add(3600),
            "production".to_string(),
        )
    }

    #[test]
    fn test_session_creation() {
        let session = create_test_session();
        assert_eq!(session.session_id, "sess-123");
        assert_eq!(session.state, SessionState::Pending);
        assert_eq!(session.status_check_count, 0);
        assert_eq!(session.redeem_attempt_count, 0);
    }

    #[test]
    fn test_session_state_transitions() -> Result<(), Box<dyn std::error::Error>> {
        let mut session = create_test_session();
        assert_eq!(session.state, SessionState::Pending);

        assert!(session.mark_proof_ok("cred-data".to_string()));
        assert_eq!(session.state, SessionState::ProofOk);
        assert!(session.proof_submitted_at.is_some());
        assert_eq!(
            session
                .credential_data
                .as_ref()
                .ok_or("missing credential_data")?,
            "cred-data"
        );

        // Calling mark_proof_ok again must fail (not Pending any more)
        assert!(!session.mark_proof_ok("second-attempt".to_string()));
        assert_eq!(session.state, SessionState::ProofOk);

        assert!(session.mark_verified());
        assert_eq!(session.state, SessionState::Verified);
        assert!(session.verified_at.is_some());
        Ok(())
    }

    #[test]
    fn test_session_expiration() {
        let mut session = create_test_session();
        assert!(!session.is_expired());

        session.expires_at = u64::try_from(chrono::Utc::now().timestamp())
            .unwrap_or(0)
            .saturating_sub(100);
        assert!(session.is_expired());
    }

    #[test]
    fn test_session_state_can_check_status() {
        assert!(SessionState::Pending.can_check_status());
        assert!(SessionState::ProofOk.can_check_status());
        assert!(SessionState::Verified.can_check_status());
        assert!(!SessionState::Expired.can_check_status());
        assert!(!SessionState::Revoked.can_check_status());
    }

    #[test]
    fn test_session_state_can_redeem() {
        assert!(!SessionState::Pending.can_redeem());
        assert!(SessionState::ProofOk.can_redeem());
        assert!(!SessionState::Verified.can_redeem());
        assert!(!SessionState::Expired.can_redeem());
        assert!(!SessionState::Revoked.can_redeem());
    }

    #[test]
    fn test_session_state_is_terminal() {
        assert!(!SessionState::Pending.is_terminal());
        assert!(!SessionState::ProofOk.is_terminal());
        assert!(SessionState::Verified.is_terminal());
        assert!(SessionState::Expired.is_terminal());
        assert!(SessionState::Revoked.is_terminal());
    }

    #[test]
    fn test_valid_transitions_from_pending() {
        assert!(SessionState::Pending.is_valid_transition(SessionState::ProofOk));
        assert!(SessionState::Pending.is_valid_transition(SessionState::Expired));
        assert!(SessionState::Pending.is_valid_transition(SessionState::Revoked));
        assert!(!SessionState::Pending.is_valid_transition(SessionState::Verified));
        assert!(!SessionState::Pending.is_valid_transition(SessionState::Pending));
    }

    #[test]
    fn test_valid_transitions_from_proof_ok() {
        assert!(SessionState::ProofOk.is_valid_transition(SessionState::Verified));
        assert!(SessionState::ProofOk.is_valid_transition(SessionState::Expired));
        assert!(SessionState::ProofOk.is_valid_transition(SessionState::Revoked));
        assert!(!SessionState::ProofOk.is_valid_transition(SessionState::Pending));
        assert!(!SessionState::ProofOk.is_valid_transition(SessionState::ProofOk));
    }

    #[test]
    fn test_terminal_states_reject_all_transitions() {
        for terminal in [
            SessionState::Verified,
            SessionState::Expired,
            SessionState::Revoked,
        ] {
            for target in [
                SessionState::Pending,
                SessionState::ProofOk,
                SessionState::Verified,
                SessionState::Expired,
                SessionState::Revoked,
            ] {
                assert!(
                    !terminal.is_valid_transition(target),
                    "{:?} -> {:?} should be invalid",
                    terminal,
                    target,
                );
            }
        }
    }

    #[test]
    fn test_mark_revoked() -> Result<(), Box<dyn std::error::Error>> {
        let mut session = create_test_session();
        assert!(session.mark_revoked("Test revocation".to_string()));
        assert_eq!(session.state, SessionState::Revoked);
        assert_eq!(
            session.error.as_ref().ok_or("missing error")?,
            "Test revocation"
        );
        Ok(())
    }

    #[test]
    fn test_mark_verified_rejects_invalid_state() {
        let mut session = create_test_session();
        // Cannot go Pending -> Verified (must go through ProofOk)
        assert!(!session.mark_verified());
        assert_eq!(session.state, SessionState::Pending);
    }

    #[test]
    fn test_mark_expired_rejects_terminal_state() {
        let mut session = create_test_session();
        assert!(session.mark_proof_ok("cred".to_string()));
        assert!(session.mark_verified());
        // Cannot expire an already-Verified session
        assert!(!session.mark_expired());
        assert_eq!(session.state, SessionState::Verified);
    }

    #[test]
    fn test_mark_revoked_rejects_terminal_state() {
        let mut session = create_test_session();
        assert!(session.mark_expired());
        // Cannot revoke an already-Expired session
        assert!(!session.mark_revoked("test".to_string()));
        assert_eq!(session.state, SessionState::Expired);
    }

    #[test]
    fn test_increment_counters() {
        let mut session = create_test_session();
        assert_eq!(session.status_check_count, 0);
        assert_eq!(session.redeem_attempt_count, 0);

        session.increment_status_checks();
        assert_eq!(session.status_check_count, 1);

        session.increment_redeem_attempts();
        assert_eq!(session.redeem_attempt_count, 1);
    }

    #[test]
    fn test_session_state_serialization() -> Result<(), Box<dyn std::error::Error>> {
        let state = SessionState::Pending;
        let json = serde_json::to_string(&state)?;
        assert_eq!(json, r#""pending""#);

        let state = SessionState::ProofOk;
        let json = serde_json::to_string(&state)?;
        assert_eq!(json, r#""proof_ok_waiting_for_redeem""#);
        Ok(())
    }

    #[test]
    fn test_session_serialization() -> Result<(), Box<dyn std::error::Error>> {
        let session = create_test_session();
        let json = serde_json::to_string(&session)?;
        assert!(json.contains("sess-123"));
        assert!(json.contains("pk-test"));

        let deserialized: HostedSession = serde_json::from_str(&json)?;
        assert_eq!(deserialized.session_id, session.session_id);
        assert_eq!(deserialized.state, session.state);
        Ok(())
    }

    #[test]
    fn test_update_activity() {
        let mut session = create_test_session();
        // Set activity to a past timestamp so update_activity will produce a larger value
        session.last_activity_at = session.last_activity_at.saturating_sub(10);
        let original_activity = session.last_activity_at;

        session.update_activity();

        assert!(session.last_activity_at > original_activity);
    }

    #[test]
    fn test_is_expired_with_idle_timeout_active_session() {
        let session = create_test_session();

        // Session should not be expired with 30 minute idle timeout (just created)
        assert!(!session.is_expired_with_idle_timeout(1800));

        // Session should not be expired with 1 second idle timeout (just created)
        assert!(!session.is_expired_with_idle_timeout(1));
    }

    #[test]
    fn test_is_expired_with_idle_timeout_idle_session() {
        let mut session = create_test_session();

        // Set last_activity_at to 31 minutes ago
        let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0);
        session.last_activity_at = now.saturating_sub(1860); // 31 minutes ago

        // Session should be expired with 30 minute (1800 second) idle timeout
        assert!(session.is_expired_with_idle_timeout(1800));

        // Session should not be expired with 32 minute idle timeout
        assert!(!session.is_expired_with_idle_timeout(1920));
    }

    #[test]
    fn test_is_expired_with_idle_timeout_absolute_expiration() {
        let mut session = create_test_session();

        // Set expires_at to past
        session.expires_at = u64::try_from(chrono::Utc::now().timestamp())
            .unwrap_or(0)
            .saturating_sub(100);

        // Session should be expired even with large idle timeout
        assert!(session.is_expired_with_idle_timeout(10000));
    }

    #[test]
    fn test_activity_extends_session_lifetime() {
        let mut session = create_test_session();
        let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0);

        // Set last_activity to 20 minutes ago
        session.last_activity_at = now.saturating_sub(1200);

        // Session should not be expired (within 30 min idle timeout)
        assert!(!session.is_expired_with_idle_timeout(1800));

        // Update activity (simulates user action)
        session.update_activity();

        // Session should still not be expired after activity update
        assert!(!session.is_expired_with_idle_timeout(1800));

        // Verify last_activity was updated to recent time
        let current_now = u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0);
        assert!(session.last_activity_at >= current_now.saturating_sub(1)); // Within 1 second
    }

    #[test]
    fn test_regenerate_id_resets_activity() {
        let mut session = create_test_session();
        let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0);

        // Set last_activity to 20 minutes ago
        session.last_activity_at = now.saturating_sub(1200);

        // Regenerate session ID
        let (_new_id, new_session) = session.regenerate_id(false);

        // Verify new session has updated last_activity_at
        let current_now = u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0);
        assert!(new_session.last_activity_at >= current_now.saturating_sub(1)); // Within 1 second
        assert!(new_session.last_activity_at > session.last_activity_at);
    }

    #[test]
    fn test_default_is_expired_uses_15_minute_timeout() {
        let mut session = create_test_session();
        let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0);

        // Set last_activity to 14 minutes ago
        session.last_activity_at = now.saturating_sub(840);

        // Should not be expired (default is 15 minutes = 900 seconds)
        assert!(!session.is_expired());

        // Set last_activity to 16 minutes ago
        session.last_activity_at = now.saturating_sub(960);

        // Should be expired (exceeded 15 minute default)
        assert!(session.is_expired());
    }

    // --- New coverage tests below ---

    #[test]
    fn test_session_state_serde_round_trip_all_variants() -> Result<(), Box<dyn std::error::Error>>
    {
        let variants = [
            (SessionState::Pending, r#""pending""#),
            (SessionState::ProofOk, r#""proof_ok_waiting_for_redeem""#),
            (SessionState::Verified, r#""verified""#),
            (SessionState::Expired, r#""expired""#),
            (SessionState::Revoked, r#""revoked""#),
        ];
        for (state, expected_json) in &variants {
            let serialized = serde_json::to_string(state)?;
            assert_eq!(
                &serialized, expected_json,
                "Serialization mismatch for {:?}",
                state
            );
            let deserialized: SessionState = serde_json::from_str(&serialized)?;
            assert_eq!(*state, deserialized, "Round-trip mismatch for {:?}", state);
        }
        Ok(())
    }

    #[test]
    fn test_session_state_deserialize_proof_ok_alias() -> Result<(), Box<dyn std::error::Error>> {
        // The serde rename means "proof_ok_waiting_for_redeem" deserializes to ProofOk
        let state: SessionState = serde_json::from_str(r#""proof_ok_waiting_for_redeem""#)?;
        assert_eq!(state, SessionState::ProofOk);
        Ok(())
    }

    #[test]
    fn test_session_state_deserialize_rejects_unknown() {
        let result = serde_json::from_str::<SessionState>(r#""unknown_state""#);
        assert!(result.is_err());
    }

    #[test]
    fn test_session_binding_mode_default() {
        let mode = SessionBindingMode::default();
        assert_eq!(mode, SessionBindingMode::Relaxed);
    }

    #[test]
    fn test_session_binding_mode_serde_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let variants = [
            (SessionBindingMode::Strict, r#""strict""#),
            (SessionBindingMode::Relaxed, r#""relaxed""#),
            (SessionBindingMode::None, r#""none""#),
        ];
        for (mode, expected_json) in &variants {
            let serialized = serde_json::to_string(mode)?;
            assert_eq!(&serialized, expected_json, "Mismatch for {:?}", mode);
            let deserialized: SessionBindingMode = serde_json::from_str(&serialized)?;
            assert_eq!(*mode, deserialized, "Round-trip mismatch for {:?}", mode);
        }
        Ok(())
    }

    #[test]
    fn test_session_debug_redacts_secrets() {
        let session = create_test_session();
        let debug_output = format!("{:?}", session);

        // code_verifier, nonce, credential_data must be redacted
        assert!(
            debug_output.contains("[REDACTED]"),
            "Debug output must contain [REDACTED]"
        );
        assert!(
            !debug_output.contains("verifier-secret"),
            "code_verifier must be redacted in Debug"
        );
        assert!(
            !debug_output.contains("nonce-abc"),
            "nonce must be redacted in Debug"
        );

        // Non-secret fields should be visible
        assert!(debug_output.contains("sess-123"));
        assert!(debug_output.contains("pk-test"));
        assert!(debug_output.contains("https://example.com"));
    }

    #[test]
    fn test_session_debug_redacts_credential_data() {
        let mut session = create_test_session();
        session.mark_proof_ok("super-secret-credential".to_string());
        let debug_output = format!("{:?}", session);

        assert!(
            !debug_output.contains("super-secret-credential"),
            "credential_data must be redacted in Debug"
        );
    }

    #[test]
    fn test_session_deny_unknown_fields() {
        let json = r#"{
            "session_id": "s1",
            "public_key": "pk",
            "origin": "https://example.com",
            "state": "pending",
            "code_challenge": "cc",
            "code_verifier": "cv",
            "verifier_challenge_id": "vcid",
            "nonce": "n",
            "expires_at": 9999999999,
            "created_at": 1000000000,
            "unknown_extra_field": "should_fail"
        }"#;
        let result = serde_json::from_str::<HostedSession>(json);
        assert!(
            result.is_err(),
            "deny_unknown_fields should reject unknown keys"
        );
    }

    #[test]
    fn test_session_defaults_on_missing_optional_fields() -> Result<(), Box<dyn std::error::Error>>
    {
        // Minimal JSON with only required fields
        let json = r#"{
            "session_id": "s1",
            "public_key": "pk",
            "origin": "https://example.com",
            "state": "pending",
            "code_challenge": "cc",
            "code_verifier": "cv",
            "verifier_challenge_id": "vcid",
            "nonce": "n",
            "expires_at": 9999999999,
            "created_at": 1000000000
        }"#;
        let session: HostedSession = serde_json::from_str(json)?;
        assert_eq!(session.proof_direction, "over_age");
        assert_eq!(session.environment, "production");
        assert_eq!(session.binding_mode, SessionBindingMode::Relaxed);
        assert_eq!(session.status_check_count, 0);
        assert_eq!(session.redeem_attempt_count, 0);
        assert!(session.user_agent.is_none());
        assert!(session.client_ip_hash.is_none());
        assert!(session.credential_data.is_none());
        assert!(session.error.is_none());
        assert!(session.proof_submitted_at.is_none());
        assert!(session.verified_at.is_none());
        assert!(session.verifying_key_id.is_none());
        Ok(())
    }

    #[test]
    fn test_set_binding() {
        let mut session = create_test_session();
        assert!(session.client_ip_hash.is_none());
        assert!(session.user_agent.is_none());

        session.set_binding(Some("hashed-ip".to_string()), Some("hashed-ua".to_string()));
        assert_eq!(session.client_ip_hash.as_deref(), Some("hashed-ip"));
        assert_eq!(session.user_agent.as_deref(), Some("hashed-ua"));
    }

    #[test]
    fn test_set_binding_with_none() {
        let mut session = create_test_session();
        session.set_binding(Some("ip1".to_string()), Some("ua1".to_string()));

        // Overwrite with None
        session.set_binding(None, None);
        assert!(session.client_ip_hash.is_none());
        assert!(session.user_agent.is_none());
    }

    #[test]
    fn test_regenerate_id_produces_different_id() {
        let session = create_test_session();
        let (new_id, new_session) = session.regenerate_id(false);

        assert_ne!(new_id, session.session_id);
        assert_eq!(new_session.session_id, new_id);
    }

    #[test]
    fn test_regenerate_id_preserves_state() {
        let mut session = create_test_session();
        session.mark_proof_ok("cred".to_string());
        session.set_binding(Some("ip".to_string()), Some("ua".to_string()));
        session.increment_status_checks();
        session.increment_redeem_attempts();

        let (_new_id, new_session) = session.regenerate_id(false);

        assert_eq!(new_session.state, SessionState::ProofOk);
        assert_eq!(new_session.public_key, session.public_key);
        assert_eq!(new_session.origin, session.origin);
        assert_eq!(new_session.code_challenge, session.code_challenge);
        assert_eq!(new_session.code_verifier, session.code_verifier);
        assert_eq!(new_session.nonce, session.nonce);
        assert_eq!(new_session.environment, session.environment);
        assert_eq!(new_session.binding_mode, session.binding_mode);
        assert_eq!(new_session.client_ip_hash, session.client_ip_hash);
        assert_eq!(new_session.user_agent, session.user_agent);
        assert_eq!(new_session.status_check_count, session.status_check_count);
        assert_eq!(
            new_session.redeem_attempt_count,
            session.redeem_attempt_count
        );
        assert_eq!(new_session.credential_data, session.credential_data);
        assert_eq!(new_session.proof_submitted_at, session.proof_submitted_at);
        assert_eq!(new_session.created_at, session.created_at);
        assert_eq!(new_session.verifying_key_id, session.verifying_key_id);
    }

    #[test]
    fn test_regenerate_id_extend_expiry_true() {
        let mut session = create_test_session();
        // Force a known created_at / expires_at pair so original TTL = 3600
        session.created_at = 1_000_000;
        session.expires_at = 1_003_600;

        let (_new_id, new_session) = session.regenerate_id(true);

        // The new expiry should be approximately now + 3600.
        // Since we cannot know the exact wall-clock, just verify it changed
        // and is larger than the old expires_at (which was in 2001).
        let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0);
        assert!(
            new_session.expires_at > 1_003_600,
            "Extended expiry should be well past the old fixed value"
        );
        // Within a generous 5-second window of now + 3600
        let expected_min = now.saturating_add(3600).saturating_sub(5);
        let expected_max = now.saturating_add(3600).saturating_add(5);
        assert!(
            new_session.expires_at >= expected_min && new_session.expires_at <= expected_max,
            "Expected ~{}, got {}",
            now + 3600,
            new_session.expires_at
        );
    }

    #[test]
    fn test_regenerate_id_no_extend_keeps_original_expiry() {
        let mut session = create_test_session();
        let original_expiry = session.expires_at;

        // Force created_at to something old so TTL calculation is non-trivial
        session.created_at = 1_000_000;
        session.expires_at = original_expiry;

        let (_new_id, new_session) = session.regenerate_id(false);
        assert_eq!(new_session.expires_at, original_expiry);
    }

    #[test]
    fn test_counter_saturating_add() {
        let mut session = create_test_session();
        session.status_check_count = u32::MAX;
        session.increment_status_checks();
        assert_eq!(session.status_check_count, u32::MAX);

        session.redeem_attempt_count = u32::MAX;
        session.increment_redeem_attempts();
        assert_eq!(session.redeem_attempt_count, u32::MAX);
    }

    #[test]
    fn test_mark_expired_from_pending() {
        let mut session = create_test_session();
        assert_eq!(session.state, SessionState::Pending);
        assert!(session.mark_expired());
        assert_eq!(session.state, SessionState::Expired);
    }

    #[test]
    fn test_mark_expired_from_proof_ok() {
        let mut session = create_test_session();
        session.mark_proof_ok("cred".to_string());
        assert!(session.mark_expired());
        assert_eq!(session.state, SessionState::Expired);
    }

    #[test]
    fn test_mark_revoked_from_proof_ok() -> Result<(), Box<dyn std::error::Error>> {
        let mut session = create_test_session();
        session.mark_proof_ok("cred".to_string());
        assert!(session.mark_revoked("fraud detected".to_string()));
        assert_eq!(session.state, SessionState::Revoked);
        assert_eq!(
            session.error.as_ref().ok_or("missing error")?,
            "fraud detected"
        );
        Ok(())
    }

    #[test]
    fn test_mark_verified_from_pending_fails() {
        let mut session = create_test_session();
        assert!(!session.mark_verified());
        assert_eq!(session.state, SessionState::Pending);
        assert!(session.verified_at.is_none());
    }

    #[test]
    fn test_mark_verified_from_verified_fails() {
        let mut session = create_test_session();
        session.mark_proof_ok("cred".to_string());
        session.mark_verified();
        assert_eq!(session.state, SessionState::Verified);

        // Second mark_verified should fail (terminal)
        assert!(!session.mark_verified());
    }

    #[test]
    fn test_full_lifecycle_pending_to_verified() {
        let mut session = create_test_session();
        assert_eq!(session.state, SessionState::Pending);
        assert!(!session.state.is_terminal());
        assert!(session.state.can_check_status());
        assert!(!session.state.can_redeem());

        assert!(session.mark_proof_ok("cred-data".to_string()));
        assert_eq!(session.state, SessionState::ProofOk);
        assert!(!session.state.is_terminal());
        assert!(session.state.can_check_status());
        assert!(session.state.can_redeem());

        assert!(session.mark_verified());
        assert_eq!(session.state, SessionState::Verified);
        assert!(session.state.is_terminal());
        assert!(session.state.can_check_status());
        assert!(!session.state.can_redeem());

        // Cannot transition out of Verified
        assert!(!session.mark_expired());
        assert!(!session.mark_revoked("late".to_string()));
    }

    #[test]
    fn test_is_expired_with_future_activity_timestamp() {
        let mut session = create_test_session();
        let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0);

        // Set last_activity_at far into the future (storage corruption scenario)
        session.last_activity_at = now.saturating_add(10000);

        // Should be considered expired (defensive check against clock manipulation)
        assert!(session.is_expired_with_idle_timeout(1800));
    }

    #[test]
    fn test_is_expired_with_zero_idle_timeout() {
        let session = create_test_session();
        // Zero idle timeout means any elapsed time triggers expiry.
        // The session was just created so last_activity_at ~ now.
        // now - last_activity_at should be >= 0, which is >= 0, so expired.
        assert!(session.is_expired_with_idle_timeout(0));
    }

    #[test]
    fn test_new_session_has_correct_defaults() {
        let session = create_test_session();
        assert_eq!(session.proof_direction, "over_age");
        assert_eq!(session.environment, "production");
        assert_eq!(session.binding_mode, SessionBindingMode::Relaxed);
        assert!(session.proof_submitted_at.is_none());
        assert!(session.verified_at.is_none());
        assert!(session.user_agent.is_none());
        assert!(session.client_ip_hash.is_none());
        assert!(session.credential_data.is_none());
        assert!(session.error.is_none());
        assert!(session.verifying_key_id.is_none());
    }

    #[test]
    fn test_session_serialization_skip_none_fields() -> Result<(), Box<dyn std::error::Error>> {
        let session = create_test_session();
        let json = serde_json::to_string(&session)?;

        // Optional None fields with skip_serializing_if should be absent
        assert!(
            !json.contains("\"user_agent\""),
            "None user_agent should be skipped"
        );
        assert!(
            !json.contains("\"client_ip_hash\""),
            "None client_ip_hash should be skipped"
        );
        assert!(
            !json.contains("\"credential_data\""),
            "None credential_data should be skipped"
        );
        assert!(!json.contains("\"error\""), "None error should be skipped");
        Ok(())
    }

    #[test]
    fn test_session_serialization_includes_present_optionals(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut session = create_test_session();
        session.user_agent = Some("ua-hash".to_string());
        session.client_ip_hash = Some("ip-hash".to_string());
        session.mark_proof_ok("cred".to_string());

        let json = serde_json::to_string(&session)?;
        assert!(json.contains("\"user_agent\""));
        assert!(json.contains("\"client_ip_hash\""));
        assert!(json.contains("\"credential_data\""));
        Ok(())
    }

    #[test]
    fn test_session_new_custom_environment() {
        let session = HostedSession::new(
            "s1".to_string(),
            "pk".to_string(),
            "https://example.com".to_string(),
            "cc".to_string(),
            "cv".to_string(),
            "vcid".to_string(),
            "nonce".to_string(),
            9999999999,
            "sandbox".to_string(),
        );
        assert_eq!(session.environment, "sandbox");
    }

    #[test]
    fn test_update_activity_does_not_alter_other_fields() {
        let mut session = create_test_session();
        session.set_binding(Some("ip".to_string()), Some("ua".to_string()));
        session.increment_status_checks();
        let state_before = session.state;
        let id_before = session.session_id.clone();
        let expires_before = session.expires_at;
        let created_before = session.created_at;
        let checks_before = session.status_check_count;
        let ip_before = session.client_ip_hash.clone();
        let ua_before = session.user_agent.clone();

        session.last_activity_at = session.last_activity_at.saturating_sub(60);
        session.update_activity();

        assert_eq!(session.session_id, id_before);
        assert_eq!(session.state, state_before);
        assert_eq!(session.expires_at, expires_before);
        assert_eq!(session.created_at, created_before);
        assert_eq!(session.status_check_count, checks_before);
        assert_eq!(session.client_ip_hash, ip_before);
        assert_eq!(session.user_agent, ua_before);
    }

    #[test]
    fn test_update_activity_from_zero_timestamp() {
        let mut session = create_test_session();
        session.last_activity_at = 0;

        session.update_activity();

        let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0);
        assert!(session.last_activity_at >= now.saturating_sub(1));
    }

    #[test]
    fn test_update_activity_idempotent_within_same_second() {
        let mut session = create_test_session();
        session.update_activity();
        let first = session.last_activity_at;
        session.update_activity();
        let second = session.last_activity_at;

        assert!(second >= first);
        assert!(second.saturating_sub(first) <= 1);
    }

    #[test]
    fn test_set_binding_partial_ip_only() {
        let mut session = create_test_session();
        session.set_binding(Some("ip-hash".to_string()), None);

        assert_eq!(session.client_ip_hash.as_deref(), Some("ip-hash"));
        assert!(session.user_agent.is_none());
    }

    #[test]
    fn test_set_binding_partial_ua_only() {
        let mut session = create_test_session();
        session.set_binding(None, Some("ua-hash".to_string()));

        assert!(session.client_ip_hash.is_none());
        assert_eq!(session.user_agent.as_deref(), Some("ua-hash"));
    }

    #[test]
    fn test_set_binding_overwrites_previous_values() {
        let mut session = create_test_session();
        session.set_binding(Some("ip-v1".to_string()), Some("ua-v1".to_string()));
        session.set_binding(Some("ip-v2".to_string()), Some("ua-v2".to_string()));

        assert_eq!(session.client_ip_hash.as_deref(), Some("ip-v2"));
        assert_eq!(session.user_agent.as_deref(), Some("ua-v2"));
    }

    #[test]
    fn test_regenerate_id_twice_produces_distinct_ids() {
        let session = create_test_session();
        let (id_a, _) = session.regenerate_id(false);
        let (id_b, _) = session.regenerate_id(false);

        assert_ne!(id_a, id_b);
        assert_ne!(id_a, session.session_id);
        assert_ne!(id_b, session.session_id);
    }

    #[test]
    fn test_regenerate_id_preserves_error_field() {
        let mut session = create_test_session();
        session.mark_revoked("abuse".to_string());

        let (_, new_session) = session.regenerate_id(false);
        assert_eq!(new_session.error.as_deref(), Some("abuse"));
        assert_eq!(new_session.state, SessionState::Revoked);
    }

    #[test]
    fn test_regenerate_id_extend_expiry_zero_ttl() {
        let mut session = create_test_session();
        session.created_at = 1_000_000;
        session.expires_at = 1_000_000;

        let (_, new_session) = session.regenerate_id(true);

        let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0);
        assert!(new_session.expires_at >= now.saturating_sub(1));
        assert!(new_session.expires_at <= now.saturating_add(1));
    }
}
