//! Identifier newtypes (ADR-0015).
//!
//! Entity IDs are UUIDv7. The text form is lower-case and hyphenated (36 characters).
//! Parsing is strict: only that canonical form is accepted, so one ID has one text form.

use std::fmt;
use std::str::FromStr;

/// Error for an ID text that is not a canonical lower-case hyphenated UUID.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid identifier")]
pub struct IdParseError;

/// Parses the canonical text form (36 characters, lower case, hyphens).
///
/// [`uuid_id!`] types and [`VaultId`] use it. It is public so the macro can call it.
pub fn parse_uuid_text(text: &str) -> Result<uuid::Uuid, IdParseError> {
    if text.len() != uuid::fmt::Hyphenated::LENGTH {
        return Err(IdParseError);
    }
    let id = uuid::Uuid::try_parse(text).map_err(|_| IdParseError)?;
    let mut buf = uuid::Uuid::encode_buffer();
    if id.hyphenated().encode_lower(&mut buf) != text {
        return Err(IdParseError);
    }
    Ok(id)
}

/// Generates a UUID newtype with `Display`, `FromStr`, `Serialize` and `Deserialize`.
///
/// The type gets `generate()` (a new UUIDv7), byte access and strict text parsing.
/// A crate that uses the macro needs `serde` and `uuid` as dependencies.
#[macro_export]
macro_rules! uuid_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug,
                 serde::Serialize, serde::Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(pub uuid::Uuid);

        impl $name {
            /// Makes a new random, time-ordered ID (UUIDv7).
            #[must_use]
            pub fn generate() -> Self {
                Self(uuid::Uuid::now_v7())
            }

            /// Wraps an existing UUID.
            #[must_use]
            pub const fn from_uuid(id: uuid::Uuid) -> Self {
                Self(id)
            }

            /// Makes the ID from its 16 bytes.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(uuid::Uuid::from_bytes(bytes))
            }

            /// The 16 bytes of the ID (used in AAD and MAC inputs).
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 16] {
                self.0.as_bytes()
            }

            /// The UUID inside.
            #[must_use]
            pub const fn as_uuid(&self) -> &uuid::Uuid {
                &self.0
            }
        }

        impl ::std::fmt::Display for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                ::std::fmt::Display::fmt(&self.0.hyphenated(), f)
            }
        }

        impl ::std::str::FromStr for $name {
            type Err = $crate::IdParseError;
            fn from_str(text: &str) -> Result<Self, Self::Err> {
                $crate::ids::parse_uuid_text(text).map(Self)
            }
        }

        impl TryFrom<String> for $name {
            type Error = $crate::IdParseError;
            fn try_from(text: String) -> Result<Self, Self::Error> {
                text.parse()
            }
        }

        impl From<$name> for String {
            fn from(id: $name) -> String {
                id.to_string()
            }
        }
    };
}

uuid_id!(
    /// ID of an item.
    ItemId
);
uuid_id!(
    /// ID of a workspace (tenant).
    WorkspaceId
);
uuid_id!(
    /// ID of an agent.
    AgentId
);
uuid_id!(
    /// ID of one API key of an agent.
    AgentKeyId
);
uuid_id!(
    /// ID of a grant.
    GrantId
);
uuid_id!(
    /// ID of a lease.
    LeaseId
);
uuid_id!(
    /// ID of an access request.
    AccessRequestId
);
uuid_id!(
    /// ID of a key slot.
    KeySlotId
);
uuid_id!(
    /// ID of one HTTP request or MCP tool call. The server always makes it (ADR-0015).
    RequestId
);

/// The operator ID is the ID of the operator's passphrase key slot (ADR-0009, DEC-007).
pub type OperatorId = KeySlotId;

/// The vault ID: 16 random bytes (UUIDv4) from `vault_header.vault_id` (ADR-0013).
///
/// It is used in every AAD and as the HKDF salt of the key tree.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct VaultId(pub [u8; 16]);

impl VaultId {
    /// Makes a new random vault ID (UUIDv4 bytes from the OS random generator).
    #[must_use]
    pub fn generate() -> Self {
        Self(uuid::Uuid::new_v4().into_bytes())
    }

    /// The 16 bytes of the ID.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Display for VaultId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&uuid::Uuid::from_bytes(self.0).hyphenated(), f)
    }
}

impl FromStr for VaultId {
    type Err = IdParseError;
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        parse_uuid_text(text).map(|id| Self(id.into_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_ids_are_v7_and_roundtrip_as_text() {
        let id = ItemId::generate();
        assert_eq!(id.0.get_version_num(), 7);
        let text = id.to_string();
        assert_eq!(text.len(), 36);
        assert_eq!(text, text.to_lowercase());
        assert_eq!(text.parse::<ItemId>(), Ok(id));
    }

    #[test]
    fn ids_sort_by_creation_time() {
        let first = AgentId::generate();
        let second = AgentId::generate();
        assert!(first < second);
    }

    #[test]
    fn parse_rejects_non_canonical_forms() {
        let id = LeaseId::generate();
        let canonical = id.to_string();
        let upper = canonical.to_uppercase();
        let simple = id.0.simple().to_string();
        let braced = format!("{{{canonical}}}");
        let urn = id.0.urn().to_string();
        for bad in [
            upper.as_str(),
            simple.as_str(),
            braced.as_str(),
            urn.as_str(),
            "",
            "not-an-id",
        ] {
            assert_eq!(
                bad.parse::<LeaseId>(),
                Err(IdParseError),
                "accepted {bad:?}"
            );
        }
    }

    #[test]
    fn serde_uses_the_canonical_text() {
        let id = RequestId::generate();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, format!("\"{id}\""));
        let back: RequestId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, id);
        let upper = format!("\"{}\"", id.to_string().to_uppercase());
        assert!(serde_json::from_str::<RequestId>(&upper).is_err());
    }

    #[test]
    fn bytes_roundtrip() {
        let id = KeySlotId::generate();
        assert_eq!(KeySlotId::from_bytes(*id.as_bytes()), id);
        assert_eq!(KeySlotId::from_uuid(*id.as_uuid()), id);
    }

    #[test]
    fn vault_id_is_v4_and_roundtrips() {
        let id = VaultId::generate();
        assert_eq!(uuid::Uuid::from_bytes(id.0).get_version_num(), 4);
        assert_eq!(id.to_string().parse::<VaultId>(), Ok(id));
        assert_ne!(VaultId::generate(), id);
    }
}
