//! The CSV flavours Cerberus knows: header names and how to tell them apart.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// An item field a column can feed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Field {
    /// Item title.
    Title,
    /// Item kind (`web_login`, `note`, ...).
    Kind,
    /// Login page or target.
    Url,
    /// User name.
    Username,
    /// Password.
    Password,
    /// The main secret of a kind that is not a login: note text, API key, token, connection URL.
    Secret,
    /// TOTP seed or `otpauth://` URI.
    Totp,
    /// Free notes. For a note item this is the text when `secret` is empty.
    Notes,
    /// Tags, separated by `,` or `;`.
    Tags,
    /// Item description (metadata, not secret).
    Description,
    /// Role label.
    Role,
    /// Category.
    Category,
    /// Environment: `dev`, `staging`, `prod` or `other`.
    Environment,
}

impl Field {
    /// Every field, in the order the mapping step lists them.
    pub const ALL: [Field; 13] = [
        Field::Title,
        Field::Kind,
        Field::Url,
        Field::Username,
        Field::Password,
        Field::Secret,
        Field::Totp,
        Field::Notes,
        Field::Tags,
        Field::Description,
        Field::Role,
        Field::Category,
        Field::Environment,
    ];

    /// The stable name used in mappings.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Field::Title => "title",
            Field::Kind => "kind",
            Field::Url => "url",
            Field::Username => "username",
            Field::Password => "password",
            Field::Secret => "secret",
            Field::Totp => "totp",
            Field::Notes => "notes",
            Field::Tags => "tags",
            Field::Description => "description",
            Field::Role => "role",
            Field::Category => "category",
            Field::Environment => "environment",
        }
    }

    /// The field with this name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Field> {
        Self::ALL.into_iter().find(|f| f.name() == name)
    }

    /// Header names (lower case) that feed this field in a file of `source`.
    fn aliases(self, source: CsvSource) -> &'static [&'static str] {
        use CsvSource as S;
        match (source, self) {
            (S::Bitwarden, Field::Title) => &["name"],
            (S::Bitwarden, Field::Kind) => &["type"],
            (S::Bitwarden, Field::Url) => &["login_uri"],
            (S::Bitwarden, Field::Username) => &["login_username"],
            (S::Bitwarden, Field::Password) => &["login_password"],
            (S::Bitwarden, Field::Totp) => &["login_totp"],
            (S::Bitwarden, Field::Notes) => &["notes"],
            (S::Bitwarden, Field::Tags) => &["folder"],
            (S::OnePassword, Field::Title) => &["title"],
            (S::OnePassword, Field::Kind) => &["type"],
            (S::OnePassword, Field::Url) => &["url", "website"],
            (S::OnePassword, Field::Username) => &["username"],
            (S::OnePassword, Field::Password) => &["password"],
            (S::OnePassword, Field::Totp) => &["otpauth"],
            (S::OnePassword, Field::Notes) => &["notes"],
            (S::OnePassword, Field::Tags) => &["tags", "folder"],
            (S::KeePassXc, Field::Title) => &["title"],
            (S::KeePassXc, Field::Url) => &["url"],
            (S::KeePassXc, Field::Username) => &["username"],
            (S::KeePassXc, Field::Password) => &["password"],
            (S::KeePassXc, Field::Totp) => &["totp"],
            (S::KeePassXc, Field::Notes) => &["notes"],
            (S::KeePassXc, Field::Tags) => &["group"],
            (S::Chrome, Field::Title) => &["name"],
            (S::Chrome, Field::Url) => &["url"],
            (S::Chrome, Field::Username) => &["username"],
            (S::Chrome, Field::Password) => &["password"],
            (S::Chrome, Field::Notes) => &["note", "notes"],
            (S::Firefox, Field::Url) => &["url"],
            (S::Firefox, Field::Username) => &["username"],
            (S::Firefox, Field::Password) => &["password"],
            (S::Auto | S::Generic, Field::Title) => &["title", "name"],
            (S::Auto | S::Generic, Field::Kind) => &["kind", "type"],
            (S::Auto | S::Generic, Field::Url) => &["url", "uri", "website", "login_uri", "target"],
            (S::Auto | S::Generic, Field::Username) => &["username", "user", "login"],
            (S::Auto | S::Generic, Field::Password) => &["password", "pass"],
            (S::Auto | S::Generic, Field::Secret) => &["secret", "value", "key", "token"],
            (S::Auto | S::Generic, Field::Totp) => &["totp", "otp", "otpauth"],
            (S::Auto | S::Generic, Field::Notes) => &["notes", "note", "comments"],
            (S::Auto | S::Generic, Field::Tags) => &["tags"],
            (S::Auto | S::Generic, Field::Description) => &["description"],
            (S::Auto | S::Generic, Field::Role) => &["role", "role_label"],
            (S::Auto | S::Generic, Field::Category) => &["category"],
            (S::Auto | S::Generic, Field::Environment) => &["environment", "env"],
            _ => &[],
        }
    }
}

/// Where the file came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CsvSource {
    /// Find the flavour from the header row.
    Auto,
    /// Bitwarden "export vault" CSV.
    Bitwarden,
    /// 1Password CSV (versions 7 and 8).
    OnePassword,
    /// KeePassXC "export to CSV".
    KeePassXc,
    /// Chrome, Edge, Brave and Opera password export.
    Chrome,
    /// Firefox "export logins" CSV.
    Firefox,
    /// A Cerberus export or any file with a column mapping.
    Generic,
}

impl CsvSource {
    /// The stable name used in the audit event.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            CsvSource::Auto => "auto",
            CsvSource::Bitwarden => "bitwarden",
            CsvSource::OnePassword => "onepassword",
            CsvSource::KeePassXc => "keepassxc",
            CsvSource::Chrome => "chrome",
            CsvSource::Firefox => "firefox",
            CsvSource::Generic => "generic",
        }
    }

    /// The flavour that matches the header row, if one does. Never returns `Auto`.
    #[must_use]
    pub fn detect(headers: &[String]) -> Option<CsvSource> {
        let has = |name: &str| headers.iter().any(|h| h.eq_ignore_ascii_case(name));
        if has("login_uri") && has("login_username") && has("name") {
            Some(CsvSource::Bitwarden)
        } else if has("url")
            && has("username")
            && has("password")
            && (has("httprealm") || has("formactionorigin") || has("guid"))
        {
            Some(CsvSource::Firefox)
        } else if has("group") && has("title") && has("username") && has("password") {
            Some(CsvSource::KeePassXc)
        } else if has("title")
            && has("password")
            && (has("otpauth")
                || has("website")
                || has("archived")
                || (has("type") && has("folder")))
        {
            Some(CsvSource::OnePassword)
        } else if has("title") && (has("kind") || has("secret") || has("workspace")) {
            Some(CsvSource::Generic)
        } else if has("name") && has("url") && has("username") && has("password") {
            Some(CsvSource::Chrome)
        } else {
            None
        }
    }
}

/// A column name in a mapping does not exist in the file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UnknownColumn(pub Field);

/// Field to column index, for one file.
#[derive(Debug)]
pub(crate) struct Columns {
    index: BTreeMap<Field, usize>,
}

impl Columns {
    /// The preset columns of `source`, then the user mapping on top (a column name in the header).
    pub(crate) fn resolve(
        headers: &[String],
        source: CsvSource,
        user: &BTreeMap<Field, String>,
    ) -> Result<Self, UnknownColumn> {
        let find = |name: &str| headers.iter().position(|h| h.eq_ignore_ascii_case(name));
        let mut index = BTreeMap::new();
        for field in Field::ALL {
            if let Some(i) = field.aliases(source).iter().find_map(|a| find(a)) {
                index.insert(field, i);
            }
        }
        for (field, column) in user {
            if column.is_empty() {
                index.remove(field);
                continue;
            }
            let i = headers
                .iter()
                .position(|h| h == column)
                .or_else(|| find(column))
                .ok_or(UnknownColumn(*field))?;
            index.insert(*field, i);
        }
        Ok(Self { index })
    }

    /// The cell of `field` in `cells`, `None` when the field has no column or the row is short.
    pub(crate) fn get<'a>(&self, field: Field, cells: &'a [Zeroizing<String>]) -> Option<&'a str> {
        let i = *self.index.get(&field)?;
        cells.get(i).map(|c| c.as_str())
    }
}
