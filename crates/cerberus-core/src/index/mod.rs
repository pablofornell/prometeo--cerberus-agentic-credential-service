//! In-memory index of decrypted metadata (ADR-0006).
//!
//! The vault service builds it at unlock and drops it at lock. It holds metadata only, never a
//! payload or a DEK. All text is `Zeroizing`, so the drop erases it. This module has the structure
//! and the lookups; resolve scoring is in a later task (ADR-0020).

mod meta;
mod text;

use std::collections::{BTreeSet, HashMap};

use cerberus_types::{AgentId, Environment, GrantId, ItemId, ItemKind, WorkspaceId};

pub use meta::{
    CreatedBy, GrantEntry, ItemMeta, KindSource, WorkspaceMeta, decode_item_meta,
    decode_workspace_meta, encode_item_meta, encode_workspace_meta, grant_entry,
};
pub use text::{Word, normalize, words};

/// The index. `Debug` shows only counts.
#[derive(Default)]
pub struct Index {
    items: HashMap<ItemId, ItemMeta>,
    /// Current version of each item, from the row whose sealed metadata opened under it (the AAD
    /// holds the version). Reads compare it with the plain row (AUD-6).
    versions: HashMap<ItemId, u32>,
    by_workspace: HashMap<WorkspaceId, BTreeSet<ItemId>>,
    by_environment: HashMap<Environment, BTreeSet<ItemId>>,
    by_kind: HashMap<ItemKind, BTreeSet<ItemId>>,
    tokens: HashMap<Word, BTreeSet<ItemId>>,
    workspaces: HashMap<WorkspaceId, WorkspaceMeta>,
    workspaces_by_slug: HashMap<Word, WorkspaceId>,
    grants_by_agent: HashMap<AgentId, Vec<GrantEntry>>,
}

impl std::fmt::Debug for Index {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Index")
            .field("items", &self.items.len())
            .field("workspaces", &self.workspaces.len())
            .field("tokens", &self.tokens.len())
            .finish_non_exhaustive()
    }
}

/// The words of an item that go into the token map: title, description, role label, tags, target.
fn item_words(meta: &ItemMeta) -> BTreeSet<Word> {
    let mut out = BTreeSet::new();
    let texts = [Some(&meta.title), Some(&meta.description)]
        .into_iter()
        .chain([meta.role_label.as_ref(), meta.target.as_ref()])
        .flatten()
        .chain(meta.tags.iter());
    for text in texts {
        out.extend(words(text).into_iter().map(Word::new));
    }
    out
}

fn slug_keys(meta: &WorkspaceMeta) -> Vec<Word> {
    std::iter::once(&meta.slug)
        .chain(meta.aliases.iter())
        .map(|name| Word::new(normalize(name)))
        .filter(|w| !w.as_str().is_empty())
        .collect()
}

fn remove_from<K: std::hash::Hash + Eq>(
    map: &mut HashMap<K, BTreeSet<ItemId>>,
    key: &K,
    id: &ItemId,
) {
    if let Some(set) = map.get_mut(key) {
        set.remove(id);
        if set.is_empty() {
            map.remove(key);
        }
    }
}

impl Index {
    /// Builds the index from all metadata.
    #[must_use]
    pub fn build(
        items: Vec<ItemMeta>,
        workspaces: Vec<WorkspaceMeta>,
        grants: Vec<GrantEntry>,
    ) -> Self {
        let mut index = Self::default();
        for workspace in workspaces {
            index.upsert_workspace(workspace);
        }
        for item in items {
            index.upsert_item(item);
        }
        for grant in grants {
            index.upsert_grant(grant);
        }
        index
    }

    /// Number of items.
    #[must_use]
    pub fn item_count(&self) -> usize {
        self.items.len()
    }

    /// Number of workspaces.
    #[must_use]
    pub fn workspace_count(&self) -> usize {
        self.workspaces.len()
    }

    /// One item.
    #[must_use]
    pub fn item(&self, id: &ItemId) -> Option<&ItemMeta> {
        self.items.get(id)
    }

    /// All items, in no fixed order.
    pub fn iter_items(&self) -> impl Iterator<Item = &ItemMeta> {
        self.items.values()
    }

    /// Items of one workspace.
    #[must_use]
    pub fn items_in_workspace(&self, id: &WorkspaceId) -> Option<&BTreeSet<ItemId>> {
        self.by_workspace.get(id)
    }

    /// Items of one environment.
    #[must_use]
    pub fn items_in_environment(&self, env: Environment) -> Option<&BTreeSet<ItemId>> {
        self.by_environment.get(&env)
    }

    /// Items of one kind.
    #[must_use]
    pub fn items_of_kind(&self, kind: ItemKind) -> Option<&BTreeSet<ItemId>> {
        self.by_kind.get(&kind)
    }

    /// Items that contain the normalized word `word`.
    #[must_use]
    pub fn items_with_word(&self, word: &str) -> Option<&BTreeSet<ItemId>> {
        self.tokens.get(word)
    }

    /// The current version of an item, as checked at unlock or set by the last write.
    #[must_use]
    pub fn item_version(&self, id: &ItemId) -> Option<u32> {
        self.versions.get(id).copied()
    }

    /// Adds an item at `version` or replaces it (see [`Self::upsert_item`]).
    pub fn upsert_item_at(&mut self, meta: ItemMeta, version: u32) {
        let id = meta.id;
        self.upsert_item(meta);
        self.versions.insert(id, version);
    }

    /// Adds an item or replaces it. Old words and sets of a replaced item are removed first. The
    /// known version stays; a write that makes a new version uses [`Self::upsert_item_at`].
    pub fn upsert_item(&mut self, meta: ItemMeta) {
        let version = self.versions.get(&meta.id).copied();
        self.remove_item(&meta.id);
        if let Some(version) = version {
            self.versions.insert(meta.id, version);
        }
        let id = meta.id;
        self.by_workspace
            .entry(meta.workspace_id)
            .or_default()
            .insert(id);
        self.by_environment
            .entry(meta.environment)
            .or_default()
            .insert(id);
        self.by_kind.entry(meta.kind).or_default().insert(id);
        for word in item_words(&meta) {
            self.tokens.entry(word).or_default().insert(id);
        }
        self.items.insert(id, meta);
    }

    /// Removes an item from every map. Returns the removed metadata.
    pub fn remove_item(&mut self, id: &ItemId) -> Option<ItemMeta> {
        self.versions.remove(id);
        let old = self.items.remove(id)?;
        remove_from(&mut self.by_workspace, &old.workspace_id, id);
        remove_from(&mut self.by_environment, &old.environment, id);
        remove_from(&mut self.by_kind, &old.kind, id);
        for word in item_words(&old) {
            remove_from(&mut self.tokens, &word, id);
        }
        Some(old)
    }

    /// One workspace.
    #[must_use]
    pub fn workspace(&self, id: &WorkspaceId) -> Option<&WorkspaceMeta> {
        self.workspaces.get(id)
    }

    /// All workspaces, in no fixed order.
    pub fn iter_workspaces(&self) -> impl Iterator<Item = &WorkspaceMeta> {
        self.workspaces.values()
    }

    /// The workspace whose slug or alias matches `name` after [`normalize`].
    #[must_use]
    pub fn workspace_by_slug(&self, name: &str) -> Option<WorkspaceId> {
        self.workspaces_by_slug
            .get(normalize(name).as_str())
            .copied()
    }

    /// Adds a workspace or replaces it.
    pub fn upsert_workspace(&mut self, meta: WorkspaceMeta) {
        self.remove_workspace(&meta.id);
        for key in slug_keys(&meta) {
            self.workspaces_by_slug.insert(key, meta.id);
        }
        self.workspaces.insert(meta.id, meta);
    }

    /// Removes a workspace and its slug entries. Items keep their workspace ID.
    pub fn remove_workspace(&mut self, id: &WorkspaceId) -> Option<WorkspaceMeta> {
        let old = self.workspaces.remove(id)?;
        for key in slug_keys(&old) {
            if self.workspaces_by_slug.get(&key) == Some(id) {
                self.workspaces_by_slug.remove(&key);
            }
        }
        Some(old)
    }

    /// Grants of one agent.
    #[must_use]
    pub fn grants_for(&self, agent: &AgentId) -> &[GrantEntry] {
        self.grants_by_agent.get(agent).map_or(&[], Vec::as_slice)
    }

    /// Adds a grant or replaces it (also when it moved to another agent).
    pub fn upsert_grant(&mut self, grant: GrantEntry) {
        self.remove_grant(&grant.id);
        self.grants_by_agent
            .entry(grant.agent_id)
            .or_default()
            .push(grant);
    }

    /// Removes a grant.
    pub fn remove_grant(&mut self, id: &GrantId) -> Option<GrantEntry> {
        let (agent, pos) = self.grants_by_agent.iter().find_map(|(agent, list)| {
            list.iter()
                .position(|g| g.id == *id)
                .map(|pos| (*agent, pos))
        })?;
        let list = self.grants_by_agent.get_mut(&agent)?;
        let removed = list.remove(pos);
        if list.is_empty() {
            self.grants_by_agent.remove(&agent);
        }
        Some(removed)
    }
}

#[cfg(test)]
mod tests {
    use crate::error::CoreError;
    use cerberus_crypto::SecretBytes;
    use cerberus_types::t0;
    use zeroize::Zeroizing;

    use super::*;

    fn z(text: &str) -> Zeroizing<String> {
        Zeroizing::new(text.to_owned())
    }

    fn item(ws: WorkspaceId, title: &str, env: Environment) -> ItemMeta {
        ItemMeta {
            id: ItemId::generate(),
            kind: ItemKind::WebLogin,
            workspace_id: ws,
            title: z(title),
            description: z("Login for the shop"),
            role_label: Some(z("Admin")),
            category: z("Web login"),
            tags: vec![z("billing")],
            environment: env,
            target: Some(z("https://shop.example.test")),
            created_by: CreatedBy::Operator(cerberus_types::KeySlotId::generate()),
            max_uses: None,
            use_count: 0,
            expires_at: None,
            updated_at: t0(),
            has_totp: false,
            custom: std::collections::BTreeMap::new(),
        }
    }

    fn workspace(slug: &str, aliases: &[&str]) -> WorkspaceMeta {
        WorkspaceMeta {
            id: WorkspaceId::generate(),
            slug: z(slug),
            name: z("Shop"),
            description: z(""),
            aliases: aliases.iter().map(|a| z(a)).collect(),
            updated_at: t0(),
        }
    }

    #[test]
    fn build_fills_every_map() {
        let ws = workspace("shop-frontend", &["Shop FE"]);
        let a = item(ws.id, "Staging Portal", Environment::Staging);
        let b = item(ws.id, "Prod Portal", Environment::Prod);
        let (a_id, b_id, ws_id) = (a.id, b.id, ws.id);
        let index = Index::build(vec![a, b], vec![ws], Vec::new());
        assert_eq!(index.item_count(), 2);
        assert_eq!(index.items_in_workspace(&ws_id).map(BTreeSet::len), Some(2));
        assert!(
            index
                .items_in_environment(Environment::Prod)
                .is_some_and(|s| s.contains(&b_id))
        );
        assert_eq!(
            index.items_of_kind(ItemKind::WebLogin).map(BTreeSet::len),
            Some(2)
        );
        let portal = index.items_with_word("portal").unwrap();
        assert!(portal.contains(&a_id) && portal.contains(&b_id));
        assert!(index.items_with_word("staging").unwrap().contains(&a_id));
        assert!(index.items_with_word("billing").is_some());
        assert!(index.items_with_word("example").is_some(), "target words");
        assert!(index.items_with_word("admin").is_some(), "role label words");
        assert_eq!(index.workspace_by_slug("SHOP-frontend "), Some(ws_id));
        assert_eq!(index.workspace_by_slug("shop fe"), Some(ws_id));
        assert_eq!(index.workspace_by_slug("other"), None);
    }

    #[test]
    fn upsert_replaces_old_words_and_remove_clears_everything() {
        let ws = WorkspaceId::generate();
        let mut meta = item(ws, "Alpha", Environment::Dev);
        let id = meta.id;
        let mut index = Index::default();
        index.upsert_item(meta.clone());
        assert!(index.items_with_word("alpha").is_some());
        meta.title = z("Beta");
        meta.environment = Environment::Prod;
        index.upsert_item(meta);
        assert!(index.items_with_word("alpha").is_none());
        assert!(index.items_with_word("beta").unwrap().contains(&id));
        assert!(index.items_in_environment(Environment::Dev).is_none());
        assert!(index.remove_item(&id).is_some());
        assert_eq!(index.item_count(), 0);
        assert!(index.tokens.is_empty());
        assert!(index.by_workspace.is_empty());
        assert!(index.by_environment.is_empty());
        assert!(index.by_kind.is_empty());
    }

    #[test]
    fn workspace_and_grant_updates() {
        let mut index = Index::default();
        let mut ws = workspace("api", &["backend"]);
        let ws_id = ws.id;
        index.upsert_workspace(ws.clone());
        ws.aliases.clear();
        index.upsert_workspace(ws);
        assert_eq!(index.workspace_by_slug("api"), Some(ws_id));
        assert_eq!(index.workspace_by_slug("backend"), None);
        assert!(index.remove_workspace(&ws_id).is_some());
        assert_eq!(index.workspace_by_slug("api"), None);

        let (agent_a, agent_b) = (AgentId::generate(), AgentId::generate());
        let mut grant = GrantEntry {
            id: GrantId::generate(),
            agent_id: agent_a,
            expires_at: None,
            updated_at: t0(),
            body: SecretBytes::new(b"{}".to_vec()),
        };
        index.upsert_grant(grant.clone());
        assert_eq!(index.grants_for(&agent_a).len(), 1);
        grant.agent_id = agent_b;
        index.upsert_grant(grant.clone());
        assert!(index.grants_for(&agent_a).is_empty());
        assert_eq!(index.grants_for(&agent_b).len(), 1);
        assert!(index.remove_grant(&grant.id).is_some());
        assert!(index.grants_for(&agent_b).is_empty());
    }

    #[test]
    fn debug_shows_no_metadata() {
        let ws = workspace("secret-slug", &[]);
        let it = item(ws.id, "Very Private Title", Environment::Dev);
        let index = Index::build(vec![it.clone()], vec![ws.clone()], Vec::new());
        for text in [format!("{index:?}"), format!("{it:?}"), format!("{ws:?}")] {
            assert!(!text.contains("Private"), "{text}");
            assert!(!text.contains("secret-slug"), "{text}");
            assert!(!text.contains("billing"), "{text}");
        }
    }

    #[test]
    fn meta_json_roundtrip_and_earlier_expiry() {
        use cerberus_store::ItemRow;
        let mut meta = item(WorkspaceId::generate(), "Roundtrip", Environment::Other);
        let sealed_expiry = t0() + jiff::SignedDuration::from_hours(2);
        meta.expires_at = Some(sealed_expiry);
        let json = encode_item_meta(&meta).unwrap();
        let row = ItemRow {
            id: meta.id,
            kind: meta.kind,
            expires_at: Some(t0() + jiff::SignedDuration::from_hours(5)),
            created_at: t0(),
            updated_at: t0(),
            current_version: 1,
            meta_ct: Vec::new(),
        };
        let (back, source) = decode_item_meta(&row, &SecretBytes::new(json.to_vec())).unwrap();
        assert_eq!(source, KindSource::Sealed);
        assert_eq!(back.title.as_str(), "Roundtrip");
        assert_eq!(
            back.expires_at,
            Some(sealed_expiry),
            "the earlier value wins"
        );
        assert!(decode_item_meta(&row, &SecretBytes::new(b"{}".to_vec())).is_err());
        // AUD-2: a sealed kind that is not the plain kind is refused.
        let other = ItemRow {
            kind: ItemKind::SshKey,
            ..row
        };
        assert!(matches!(
            decode_item_meta(&other, &SecretBytes::new(json.to_vec())),
            Err(CoreError::Corrupt)
        ));
    }

    /// The metadata JSON as T27 found it in existing vaults: no `kind` field (DEC-T27-A1-2). It
    /// still decodes, and it says that the kind came from the plain column.
    #[test]
    fn pre_t27_meta_json_decodes_with_a_plain_kind() {
        use cerberus_store::ItemRow;
        let ws = WorkspaceId::generate();
        let operator = cerberus_types::OperatorId::generate();
        let legacy = format!(
            concat!(
                r#"{{"workspace_id":{ws},"title":"Old login","description":"fake","#,
                r#""role_label":null,"category":"Web login","tags":["fake"],"#,
                r#""environment":"staging","target":null,"created_by":{{"operator":{op}}},"#,
                r#""max_uses":null,"use_count":3,"expires_at_ms":null,"has_totp":false,"#,
                r#""custom":{{}}}}"#
            ),
            ws = serde_json::to_string(&ws).unwrap(),
            op = serde_json::to_string(&operator).unwrap(),
        );
        let row = ItemRow {
            id: ItemId::generate(),
            kind: ItemKind::WebLogin,
            expires_at: None,
            created_at: t0(),
            updated_at: t0(),
            current_version: 1,
            meta_ct: Vec::new(),
        };
        let (meta, source) =
            decode_item_meta(&row, &SecretBytes::new(legacy.into_bytes())).unwrap();
        assert_eq!(source, KindSource::Plain);
        assert_eq!(meta.kind, ItemKind::WebLogin);
        assert_eq!(meta.use_count, 3);
        assert_eq!(meta.workspace_id, ws);
        // The encoder now writes the kind.
        let json: serde_json::Value =
            serde_json::from_slice(&encode_item_meta(&meta).unwrap()).unwrap();
        assert_eq!(json["kind"], "web_login");
    }

    #[test]
    fn the_version_follows_upserts_and_goes_with_a_remove() {
        let ws = workspace("v", &[]);
        let it = item(ws.id, "Versioned", Environment::Dev);
        let id = it.id;
        let mut index = Index::build(Vec::new(), vec![ws], Vec::new());
        index.upsert_item_at(it.clone(), 3);
        index.upsert_item(it.clone());
        assert_eq!(index.item_version(&id), Some(3));
        index.upsert_item_at(it, 4);
        assert_eq!(index.item_version(&id), Some(4));
        index.remove_item(&id);
        assert_eq!(index.item_version(&id), None);
    }
}
