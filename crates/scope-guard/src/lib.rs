use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::str::FromStr;
use thiserror::Error;
use url::Url;

#[derive(Error, Debug)]
pub enum ScopeError {
    #[error("Target '{0}' is outside authorized scope")]
    OutOfScope(String),
    #[error("Invalid target format: {0}")]
    InvalidFormat(String),
    #[error("No active scope rules defined for project")]
    EmptyScope,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ScopeRuleType {
    ExactDomain,
    WildcardSubdomain,
    IpAddress,
    CidrBlock,
    UrlPrefix,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeRule {
    pub id: String,
    pub rule_type: ScopeRuleType,
    pub pattern: String,
    pub description: Option<String>,
    pub is_allowed: bool, // true = allow, false = exclude
}

#[derive(Debug, Clone, Default)]
pub struct ScopeGuard {
    rules: Vec<ScopeRule>,
}

impl ScopeGuard {
    pub fn new(rules: Vec<ScopeRule>) -> Self {
        Self { rules }
    }

    pub fn add_rule(&mut self, rule: ScopeRule) {
        self.rules.push(rule);
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Validates whether a given raw target string is explicitly authorized.
    /// Returns Ok(()) if authorized, or Err(ScopeError) if unauthorized or out-of-scope.
    pub fn validate_target(&self, target: &str) -> Result<(), ScopeError> {
        let trimmed = target.trim();
        if trimmed.is_empty() {
            return Err(ScopeError::InvalidFormat("Empty target provided".to_string()));
        }

        if self.rules.is_empty() {
            return Err(ScopeError::EmptyScope);
        }

        let mut matched_allow = false;
        let mut matched_exclude = false;

        for rule in &self.rules {
            if self.matches_rule(rule, trimmed) {
                if rule.is_allowed {
                    matched_allow = true;
                } else {
                    matched_exclude = true;
                }
            }
        }

        if matched_exclude {
            return Err(ScopeError::OutOfScope(format!(
                "Target '{}' is explicitly excluded by scope rules",
                trimmed
            )));
        }

        if !matched_allow {
            return Err(ScopeError::OutOfScope(format!(
                "Target '{}' does not match any authorized scope rule",
                trimmed
            )));
        }

        Ok(())
    }

    fn matches_rule(&self, rule: &ScopeRule, target: &str) -> bool {
        let norm_target = target.to_lowercase();
        let norm_pattern = rule.pattern.to_lowercase();

        // Extract host if target is a URL
        let host = if let Ok(parsed_url) = Url::parse(target) {
            parsed_url.host_str().map(|h| h.to_lowercase()).unwrap_or_else(|| norm_target.clone())
        } else {
            norm_target.clone()
        };

        match rule.rule_type {
            ScopeRuleType::ExactDomain => {
                host == norm_pattern
            }
            ScopeRuleType::WildcardSubdomain => {
                let suffix = if norm_pattern.starts_with("*.") {
                    &norm_pattern[2..]
                } else if norm_pattern.starts_with('.') {
                    &norm_pattern[1..]
                } else {
                    &norm_pattern
                };

                host == suffix || host.ends_with(&format!(".{}", suffix))
            }
            ScopeRuleType::IpAddress => {
                if let (Ok(target_ip), Ok(rule_ip)) = (IpAddr::from_str(&host), IpAddr::from_str(&norm_pattern)) {
                    target_ip == rule_ip
                } else {
                    false
                }
            }
            ScopeRuleType::CidrBlock => {
                if let (Ok(target_ip), Ok(cidr)) = (IpAddr::from_str(&host), IpNetwork::from_str(&norm_pattern)) {
                    cidr.contains(target_ip)
                } else {
                    false
                }
            }
            ScopeRuleType::UrlPrefix => {
                norm_target.starts_with(&norm_pattern)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scope_guard_exact_domain() {
        let guard = ScopeGuard::new(vec![ScopeRule {
            id: "1".into(),
            rule_type: ScopeRuleType::ExactDomain,
            pattern: "example.com".into(),
            description: None,
            is_allowed: true,
        }]);

        assert!(guard.validate_target("example.com").is_ok());
        assert!(guard.validate_target("https://example.com/test").is_ok());
        assert!(guard.validate_target("sub.example.com").is_err());
        assert!(guard.validate_target("evil.com").is_err());
    }

    #[test]
    fn test_scope_guard_wildcard_domain() {
        let guard = ScopeGuard::new(vec![ScopeRule {
            id: "2".into(),
            rule_type: ScopeRuleType::WildcardSubdomain,
            pattern: "*.example.com".into(),
            description: None,
            is_allowed: true,
        }]);

        assert!(guard.validate_target("example.com").is_ok());
        assert!(guard.validate_target("api.example.com").is_ok());
        assert!(guard.validate_target("dev.api.example.com").is_ok());
        assert!(guard.validate_target("other.com").is_err());
    }

    #[test]
    fn test_scope_guard_cidr() {
        let guard = ScopeGuard::new(vec![ScopeRule {
            id: "3".into(),
            rule_type: ScopeRuleType::CidrBlock,
            pattern: "192.168.1.0/24".into(),
            description: None,
            is_allowed: true,
        }]);

        assert!(guard.validate_target("192.168.1.42").is_ok());
        assert!(guard.validate_target("192.168.2.1").is_err());
    }

    #[test]
    fn test_scope_guard_exclusion() {
        let guard = ScopeGuard::new(vec![
            ScopeRule {
                id: "4".into(),
                rule_type: ScopeRuleType::WildcardSubdomain,
                pattern: "*.example.com".into(),
                description: None,
                is_allowed: true,
            },
            ScopeRule {
                id: "5".into(),
                rule_type: ScopeRuleType::ExactDomain,
                pattern: "prod.example.com".into(),
                description: None,
                is_allowed: false, // excluded
            },
        ]);

        assert!(guard.validate_target("dev.example.com").is_ok());
        assert!(guard.validate_target("prod.example.com").is_err());
    }
}
