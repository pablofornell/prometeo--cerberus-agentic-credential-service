//! Environment variable names that an item must not set in a child process (AUD-5).
//!
//! An `env_bundle` item and the `extra` keys of a `cloud` item give names that `cerberus run`
//! puts into the environment of a child. Some names change what code the child runs (loader and
//! interpreter hooks), which certificates it trusts, where its traffic goes, or which Cerberus
//! token it uses. Core refuses these names in items that an agent writes, and the client does not
//! set them from an item. This module is the one list for both (DEC-T27-A2-1).
//!
//! A deny list is never complete (the T27 re-check found `OPENSSL_CONF`, `MAVEN_OPTS`,
//! `RUSTFLAGS` and many more). So a name in an item that an **agent** wrote must also pass an
//! allow rule, [`is_agent_env_name_allowed`]: it must look like a credential (DEC-T27-D1-1). The
//! deny list stays as the second layer, and it is the only check for items that a person wrote.
//!
//! Every compare ignores ASCII case, because Windows reads environment names without case.

/// Exact names that are forbidden.
pub const FORBIDDEN_ENV_NAMES: &[&str] = &[
    // Shell start-up and parsing.
    "PATH",
    "BASH_ENV",
    "ENV",
    "IFS",
    "SHELL",
    "SHELLOPTS",
    "BASHOPTS",
    "PS4",
    "PROMPT_COMMAND",
    "ZDOTDIR",
    "HOME",
    "CDPATH",
    // Commands that tools start on their own.
    "EDITOR",
    "VISUAL",
    "PAGER",
    "MANPAGER",
    "LESSOPEN",
    "LESSCLOSE",
    "BROWSER",
    // C library hooks.
    "GCONV_PATH",
    "GLIBC_TUNABLES",
    "LOCPATH",
    "NLSPATH",
    "HOSTALIASES",
    // Interpreter and runtime hooks (names that no prefix below covers).
    "RUBYOPT",
    "RUBYLIB",
    "NODE_PATH",
    "NODE_EXTRA_CA_CERTS",
    "NODE_TLS_REJECT_UNAUTHORIZED",
    "CLASSPATH",
    "RUSTC",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "RUSTDOC",
    "RUSTFLAGS",
    "RUSTDOCFLAGS",
    "GOFLAGS",
    "CC",
    "CXX",
    "LD",
    "LUA_INIT",
    "PHPRC",
    "PHP_INI_SCAN_DIR",
    "DOTNET_STARTUP_HOOKS",
    "VIMINIT",
    "EXINIT",
    "SUDO_ASKPASS",
    "CLOUDSDK_PYTHON",
    "GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES",
    // OpenSSL loads a provider or engine library named by these.
    "OPENSSL_CONF",
    "OPENSSL_MODULES",
    "OPENSSL_ENGINES",
    // Writes the TLS keys of the child to a file.
    "SSLKEYLOGFILE",
    // Windows shell and module search.
    "COMSPEC",
    "PATHEXT",
    "PSMODULEPATH",
    // Trust anchors.
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    // Proxies (they can send the traffic of the child to another host).
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "FTP_PROXY",
    "NO_PROXY",
];

/// Name prefixes that are forbidden.
pub const FORBIDDEN_ENV_PREFIXES: &[&str] = &[
    "LD_",
    "DYLD_",
    "PYTHON",
    "PERL",
    "BASH_FUNC_",
    "GIT_",
    "SSH_",
    "NPM_CONFIG_",
    "MALLOC_",
    "XDG_",
    "CERBERUS_",
    "LUA_INIT_",
    "CORECLR_",
    "COR_PROFILER",
    "CARGO_BUILD_",
    "CARGO_TARGET_",
    "CARGO_ENCODED_",
];

/// Name suffixes that are forbidden (`NODE_OPTIONS`, `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`,
/// `MAVEN_OPTS`, `JAVA_OPTS`, `GRADLE_OPTS` and similar).
pub const FORBIDDEN_ENV_SUFFIXES: &[&str] = &["_OPTIONS", "_OPTS"];

/// Exact names that an agent-written item may set (well-known credential variables that the
/// suffixes of [`AGENT_ENV_SUFFIXES`] do not cover, or that are listed to make the intent clear).
pub const AGENT_ENV_NAMES: &[&str] = &[
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_REGION",
    "AWS_DEFAULT_REGION",
    "AZURE_CLIENT_ID",
    "AZURE_TENANT_ID",
    "AZURE_CLIENT_SECRET",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "GITLAB_TOKEN",
    "NPM_TOKEN",
    "NODE_AUTH_TOKEN",
    "PGUSER",
    "PGPASSWORD",
    "MYSQL_PWD",
    "DATABASE_URL",
    "REDIS_URL",
    "MONGODB_URI",
    "SENTRY_DSN",
];

/// Name suffixes that make a name credential-shaped for an agent-written item. The part before
/// the suffix must not be empty (`_KEY` alone is refused).
pub const AGENT_ENV_SUFFIXES: &[&str] = &[
    "_TOKEN",
    "_KEY",
    "_KEY_ID",
    "_SECRET",
    "_PASSWORD",
    "_PASSWD",
    "_PASS",
    "_PWD",
    "_PASSPHRASE",
    "_USER",
    "_USERNAME",
    "_CLIENT_ID",
];

/// The longest name an agent-written item may set.
const MAX_AGENT_ENV_NAME: usize = 128;

/// True when `name` must not be set in a child process from an item. The compare ignores ASCII
/// case.
#[must_use]
pub fn is_forbidden_env_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    FORBIDDEN_ENV_NAMES.contains(&upper.as_str())
        || FORBIDDEN_ENV_PREFIXES.iter().any(|p| upper.starts_with(p))
        || FORBIDDEN_ENV_SUFFIXES.iter().any(|s| upper.ends_with(s))
}

/// True when an item that an **agent** wrote may set `name` in a child process (AUD-5,
/// DEC-T27-D1-1). The name, read without ASCII case, must be `[A-Z_][A-Z0-9_]*` (at most 128
/// characters), must not be on the deny list ([`is_forbidden_env_name`]), and must be in
/// [`AGENT_ENV_NAMES`] or end in one of [`AGENT_ENV_SUFFIXES`] after a non-empty part. Every other
/// name (`MAVEN_OPTS`, `OPENSSL_CONF`, `KUBECONFIG`, `DOCKER_HOST`, lower and mixed case forms of
/// them ...) is refused: a person must store it, or map it with `--var`.
#[must_use]
pub fn is_agent_env_name_allowed(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    let mut chars = upper.chars();
    let shaped = upper.len() <= MAX_AGENT_ENV_NAME
        && chars
            .next()
            .is_some_and(|c| c.is_ascii_uppercase() || c == '_')
        && chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
    shaped
        && !is_forbidden_env_name(&upper)
        && (AGENT_ENV_NAMES.contains(&upper.as_str())
            || AGENT_ENV_SUFFIXES
                .iter()
                .any(|s| upper.len() > s.len() && upper.ends_with(s)))
}

#[cfg(test)]
mod tests {
    use super::{is_agent_env_name_allowed, is_forbidden_env_name};

    #[test]
    fn loader_and_interpreter_hooks_are_forbidden() {
        for name in [
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "LD_AUDIT",
            "DYLD_INSERT_LIBRARIES",
            "NODE_OPTIONS",
            "JAVA_TOOL_OPTIONS",
            "_JAVA_OPTIONS",
            "PYTHONSTARTUP",
            "PYTHONPATH",
            "PERL5OPT",
            "PERL5LIB",
            "RUBYOPT",
            "BASH_ENV",
            "ENV",
            "PATH",
            "IFS",
            "BASH_FUNC_ls%%",
            "GIT_SSH_COMMAND",
            "SSH_AUTH_SOCK",
            "CERBERUS_TOKEN",
            "NPM_CONFIG_SCRIPT_SHELL",
            "HTTPS_PROXY",
            "SSL_CERT_FILE",
        ] {
            assert!(is_forbidden_env_name(name), "{name} must be forbidden");
        }
    }

    #[test]
    fn the_compare_ignores_case() {
        assert!(is_forbidden_env_name("ld_preload"));
        assert!(is_forbidden_env_name("Path"));
        assert!(is_forbidden_env_name("node_options"));
    }

    #[test]
    fn normal_secret_names_are_allowed() {
        for name in [
            "DATABASE_URL",
            "API_KEY",
            "STRIPE_SECRET_KEY",
            "AWS_ACCESS_KEY_ID",
            "AWS_SESSION_TOKEN",
            "NODE_ENV",
            "CARGO_REGISTRY_TOKEN",
            "GITHUB_TOKEN",
            "PGPASSWORD",
            "OPTIONS",
        ] {
            assert!(!is_forbidden_env_name(name), "{name} must be allowed");
        }
    }

    /// AUD-5 re-check: code-load hooks that the first list missed are on the deny list now.
    #[test]
    fn the_recheck_code_load_hooks_are_forbidden() {
        for name in [
            "OPENSSL_CONF",
            "OPENSSL_MODULES",
            "OPENSSL_ENGINES",
            "MAVEN_OPTS",
            "JAVA_OPTS",
            "GRADLE_OPTS",
            "GOFLAGS",
            "RUSTFLAGS",
            "CARGO_ENCODED_RUSTFLAGS",
            "CARGO_BUILD_RUSTC_WRAPPER",
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER",
            "CC",
            "CXX",
            "DOTNET_STARTUP_HOOKS",
            "CORECLR_PROFILER_PATH",
            "LUA_INIT",
            "LUA_INIT_5_4",
            "PHPRC",
            "VIMINIT",
            "SUDO_ASKPASS",
            "SSLKEYLOGFILE",
            "COMSPEC",
            "PSModulePath",
            "maven_opts",
        ] {
            assert!(is_forbidden_env_name(name), "{name} must be forbidden");
        }
        assert!(!is_forbidden_env_name("CARGO_REGISTRY_TOKEN"));
    }

    /// AUD-5 re-check (DEC-T27-D1-1): an agent item may only set credential-shaped names.
    #[test]
    fn agent_items_may_set_only_credential_names() {
        for name in [
            "MAVEN_OPTS",
            "maven_opts",
            "Maven_Opts",
            "OPENSSL_CONF",
            "openssl_conf",
            "OpenSSL_Conf",
            "RUSTFLAGS",
            "rustflags",
            "RustFlags",
            "KUBECONFIG",
            "AWS_CONFIG_FILE",
            "AWS_SHARED_CREDENTIALS_FILE",
            "GOOGLE_APPLICATION_CREDENTIALS",
            "DOCKER_HOST",
            "DOCKER_CONFIG",
            "JAVA_HOME",
            "GRADLE_USER_HOME",
            "TF_CLI_CONFIG_FILE",
            "ANSIBLE_CONFIG",
            "PIP_INDEX_URL",
            "YARN_RC_FILENAME",
            "CARGO_HOME",
            "NODE_ENV",
            "LD_PRELOAD",
            "SSH_AUTH_KEY",
            "GIT_ASKPASS",
            "CERBERUS_TOKEN",
            "_KEY",
            "_TOKEN",
            "",
            "1_TOKEN",
            "API-KEY",
            "API_KEY\u{0}",
        ] {
            assert!(!is_agent_env_name_allowed(name), "{name:?} must be refused");
        }
        for name in [
            "API_KEY",
            "STRIPE_SECRET_KEY",
            "OPENAI_API_KEY",
            "GITHUB_TOKEN",
            "github_token",
            "CARGO_REGISTRY_TOKEN",
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "DATABASE_URL",
            "PGPASSWORD",
            "DB_PASSWORD",
            "SMTP_USER",
            "SMTP_USERNAME",
            "WEBHOOK_SECRET",
            "AZURE_CLIENT_ID",
        ] {
            assert!(is_agent_env_name_allowed(name), "{name} must be allowed");
        }
        assert!(!is_agent_env_name_allowed(&format!(
            "{}_KEY",
            "A".repeat(125)
        )));
    }
}
