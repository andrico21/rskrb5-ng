//! The Windows `API:` cache is omitted by owner decision D13: while no
//! installed store provider claims `API`, every cache-name route refuses the
//! name with a typed error.

/// Name-route tests of the omitted Windows `API:` cache.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error;

    use rskrb5_ng::{
        ccache::{CCache, file_store, stores::CacheVersion},
        error::Ccache as CacheError,
    };

    /// On Windows an `API:` name is the D13 error; other systems keep the
    /// unsupported cache type.
    #[test]
    fn windows_api_cache_is_omitted() -> Result<(), Box<dyn Error>> {
        // Given a process in which no store provider claims `API`.
        // When an `API:` name is loaded, resolved and opened as a collection.
        let refusals = [
            CCache::load_name("API:session").err().ok_or("load_name")?,
            file_store::resolve("API:session", CacheVersion::V4)
                .err()
                .ok_or("resolve")?,
            file_store::collection("API:", CacheVersion::V4)
                .err()
                .ok_or("collection")?,
        ];
        // Then each route returns the platform's typed refusal.
        let typed = refusals.iter().all(|refused| {
            if cfg!(windows) {
                matches!(refused, CacheError::UnsupportedWindowsApi)
            } else {
                matches!(refused, CacheError::UnsupportedCacheType { cache_type } if cache_type == "API")
            }
        });
        let shown: Vec<String> = refusals.iter().map(ToString::to_string).collect();
        assert!(typed, "{shown:?}");
        Ok(())
    }
}
