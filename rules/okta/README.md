# Okta Detection Rules

Detection rules for Okta SystemLog events.

## Rules

| Rule | Description | Severity |
|------|-------------|----------|
| `okta_admin_role_assigned` | Detects admin privilege grants. Higher severity for Super Administrator. | INFO/HIGH |
| `okta_admin_mfa_disabled` | Global MFA disabled by admin. | HIGH |
| `okta_api_key_created` | Detects API token creation. | INFO |
| `okta_api_key_revoked` | API token revoked (upstream: Okta.APIKeyRevoked). | INFO |
| `okta_user_mfa_reset` | Detects MFA factor reset (single). | INFO |
| `okta_user_mfa_reset_all` | All MFA factors reset for a user (upstream: Okta.User.MFA.Reset.All). | MEDIUM |
| `okta_support_reset` | Password or MFA reset by Okta Support (upstream: Okta.Support.Reset). | HIGH |
| `okta_support_access` | Detects Okta support access to tenant (impersonation grant/initiate). | MEDIUM |
| `okta_brute_force_by_ip` | Detects failed login attempts exceeding threshold (20) from single IP. | INFO |
| `okta_group_admin_role_assigned` | Admin privileges assigned to a group (upstream: Okta.Group.Admin.Role.Assigned). | INFO |
| `okta_rate_limits` | Rate limit / concurrency violation events (upstream: Okta.Rate.Limits). | MEDIUM |
| `okta_anonymizing_vpn_login` | Sign-in from anonymizing VPN/proxy (upstream: Okta.Anonymizing.VPN.Login). | MEDIUM |
| `okta_org2org_creation_modification` | Org2Org app created or modified (upstream: Okta.Org2org.Creation.Modification). | HIGH/MEDIUM |
| `okta_password_extraction_via_scim` | Cleartext passwords extracted via SCIM app (upstream: Okta.Password.Extraction.via.SCIM). | HIGH |
| `okta_app_unauthorized_access_attempt` | Unauthorized access attempt to an app (upstream: Okta.App.Unauthorized.Access.Attempt). | MEDIUM |
| `okta_app_refresh_access_token_reuse` | Refresh token reuse detected (upstream: Okta.Refresh.Access.Token.Reuse). | HIGH |
| `okta_account_locked` | User account locked. | INFO |
| `okta_mfa_factor_suspended` | MFA factor suspended. | INFO |
| `okta_idp_modified` | Identity provider created or modified. | MEDIUM |
| `okta_phishing_blocked` | Phishing attempt blocked (FastPass). | INFO |
| `okta_password_accessed` | User accessed another user's app password. | MEDIUM |
| `okta_suspicious_activity_reported` | User reported suspicious activity. | MEDIUM |
| `okta_threatinsight_alert` | ThreatInsight threat detected. | MEDIUM |

Additional ported rules are documented in [docs/ported-rules.md](../../docs/ported-rules.md).

## Log Source

These rules process `Okta.SystemLog` events.

## EventBridge Integration

When using Okta Log Streaming via EventBridge, the events will be wrapped in an EventBridge envelope:

```json
{
  "version": "0",
  "id": "event-id",
  "detail-type": "Okta Log Event",
  "source": "aws.partner/okta.com/turo/...",
  "detail": {
    // Actual Okta SystemLog event
    "uuid": "...",
    "published": "...",
    "eventType": "user.session.start",
    ...
  }
}
```

The iota parser extracts the `detail` field for rule evaluation.
