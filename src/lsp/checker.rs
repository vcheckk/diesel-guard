use super::{ServerState, config_cache::checker_cache_key_with_lsp_fallback};
use crate::SafetyChecker;
use crate::config::{Config, ConfigError};
use std::sync::Arc;
use std::time::SystemTime;

pub(super) struct CheckerCache {
    pub(super) key: CheckerCacheKey,
    pub(super) checker: Arc<SafetyChecker>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CheckerCacheKey {
    pub(super) config: String,
    pub(super) custom_checks_signature: Vec<CustomCheckFileSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CustomCheckFileSignature {
    pub(super) path: String,
    pub(super) modified: Option<SystemTime>,
    pub(super) len: Option<u64>,
    pub(super) content_hash: Option<u64>,
}

impl ServerState {
    pub(super) fn load_checker(
        &mut self,
    ) -> std::result::Result<(Arc<SafetyChecker>, Vec<String>), ConfigError> {
        let (config, key, cache_warnings) = self.load_checker_inputs()?;

        if let Some(checker) = self.cached_checker(&key) {
            return Ok((checker, Vec::new()));
        }

        Ok(self.build_cached_checker(config, key, cache_warnings))
    }

    fn load_checker_inputs(
        &self,
    ) -> std::result::Result<(Config, CheckerCacheKey, Vec<String>), ConfigError> {
        let mut config = super::load_lsp_config(&self.root)?;
        let mut cache_warnings = Vec::new();
        let key = checker_cache_key_with_lsp_fallback(&mut config, &mut cache_warnings)?;
        Ok((config, key, cache_warnings))
    }

    fn cached_checker(&mut self, key: &CheckerCacheKey) -> Option<Arc<SafetyChecker>> {
        let checker = self
            .checker_cache
            .as_ref()
            .filter(|cache| cache.key == *key)
            .map(|cache| Arc::clone(&cache.checker))?;
        self.last_config_error_message = None;
        Some(checker)
    }

    fn build_cached_checker(
        &mut self,
        config: Config,
        key: CheckerCacheKey,
        cache_warnings: Vec<String>,
    ) -> (Arc<SafetyChecker>, Vec<String>) {
        let (checker, mut warnings) = SafetyChecker::with_config_and_warnings(config);
        warnings.splice(0..0, cache_warnings);
        let checker = Arc::new(checker);
        self.checker_cache = Some(CheckerCache {
            key,
            checker: Arc::clone(&checker),
        });
        self.last_config_error_message = None;
        (checker, warnings)
    }
}
