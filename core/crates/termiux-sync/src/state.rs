//! Field-level last-writer-wins state: each record is a map of fields, each field carries
//! the hybrid-logical-clock stamp of its last write; deletions are stamped tombstones.
//! Merging is commutative, associative and idempotent, so devices converge regardless of
//! the order in which they see each other's state.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Hybrid logical clock stamp; ordering is (time, counter, device), so ties between
/// devices are broken deterministically.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Stamp {
    pub time: u64,
    pub counter: u32,
    pub device: String,
}

/// Issues stamps that are always newer than anything seen before on this device.
#[derive(Debug, Clone)]
pub struct Clock {
    device: String,
    last: (u64, u32),
}

impl Clock {
    pub fn new(device: impl Into<String>) -> Self {
        Self { device: device.into(), last: (0, 0) }
    }

    pub fn now(&mut self) -> Stamp {
        let wall = termiux_model::now().max(0) as u64;
        self.last = if wall > self.last.0 { (wall, 0) } else { (self.last.0, self.last.1 + 1) };
        Stamp { time: self.last.0, counter: self.last.1, device: self.device.clone() }
    }

    /// Moves past a stamp seen from another device, so later local writes win over it
    /// even if this device's wall clock is behind.
    pub fn observe(&mut self, stamp: &Stamp) {
        if (stamp.time, stamp.counter) > self.last {
            self.last = (stamp.time, stamp.counter);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Field {
    pub value: serde_json::Value,
    pub stamp: Stamp,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    pub fields: BTreeMap<String, Field>,
    pub deleted: Option<Stamp>,
}

impl Entry {
    /// Live unless the tombstone is newer than every field write (a later edit revives it).
    pub fn is_live(&self) -> bool {
        match &self.deleted {
            None => !self.fields.is_empty(),
            Some(deleted) => self.fields.values().any(|f| &f.stamp > deleted),
        }
    }

    /// The record as a JSON object.
    pub fn value(&self) -> serde_json::Value {
        serde_json::Value::Object(self.fields.iter().map(|(k, f)| (k.clone(), f.value.clone())).collect())
    }

    fn merge(&mut self, other: &Entry) {
        for (name, theirs) in &other.fields {
            match self.fields.get(name) {
                Some(ours) if ours.stamp >= theirs.stamp => {}
                _ => {
                    self.fields.insert(name.clone(), theirs.clone());
                }
            }
        }
        if other.deleted > self.deleted {
            self.deleted = other.deleted.clone();
        }
    }

    fn max_stamp(&self) -> Option<&Stamp> {
        self.fields.values().map(|f| &f.stamp).chain(self.deleted.as_ref()).max()
    }
}

/// All synced records, keyed by `collection/id`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SyncState {
    pub entries: BTreeMap<String, Entry>,
}

pub fn entry_key(collection: &str, id: &str) -> String {
    format!("{collection}/{id}")
}

impl SyncState {
    pub fn merge(&mut self, other: &SyncState) {
        for (key, theirs) in &other.entries {
            self.entries.entry(key.clone()).or_default().merge(theirs);
        }
    }

    /// Records a local version of a record: fields whose value changed get a new stamp.
    /// Returns whether anything changed.
    pub fn record_local(&mut self, key: &str, value: &serde_json::Value, clock: &mut Clock) -> bool {
        let serde_json::Value::Object(fields) = value else { return false };
        let entry = self.entries.entry(key.to_string()).or_default();
        let was_live = entry.is_live();
        let mut changed = false;
        for (name, v) in fields {
            if !was_live || entry.fields.get(name).is_none_or(|f| &f.value != v) {
                entry.fields.insert(name.clone(), Field { value: v.clone(), stamp: clock.now() });
                changed = true;
            }
        }
        changed
    }

    /// Records a local deletion.
    pub fn delete_local(&mut self, key: &str, clock: &mut Clock) {
        if let Some(entry) = self.entries.get_mut(key)
            && entry.is_live()
        {
            entry.deleted = Some(clock.now());
        }
    }

    /// Live records of a collection as (id, value).
    pub fn live(&self, collection: &str) -> Vec<(String, serde_json::Value)> {
        let prefix = format!("{collection}/");
        self.entries
            .iter()
            .filter(|(k, e)| k.starts_with(&prefix) && e.is_live())
            .map(|(k, e)| (k[prefix.len()..].to_string(), e.value()))
            .collect()
    }

    pub fn is_live(&self, key: &str) -> bool {
        self.entries.get(key).is_some_and(Entry::is_live)
    }

    pub fn latest_stamp(&self) -> Option<&Stamp> {
        self.entries.values().filter_map(Entry::max_stamp).max()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn state_with(key: &str, value: serde_json::Value, clock: &mut Clock) -> SyncState {
        let mut s = SyncState::default();
        s.record_local(key, &value, clock);
        s
    }

    #[test]
    fn concurrent_edits_to_different_fields_both_survive() {
        let mut a_clock = Clock::new("a");
        let base = state_with("hosts/1", json!({"id": "1", "label": "web", "port": 22}), &mut a_clock);

        let mut a = base.clone();
        a.record_local("hosts/1", &json!({"id": "1", "label": "web-prod", "port": 22}), &mut a_clock);
        let mut b_clock = Clock::new("b");
        b_clock.observe(base.latest_stamp().unwrap());
        let mut b = base.clone();
        b.record_local("hosts/1", &json!({"id": "1", "label": "web", "port": 2222}), &mut b_clock);

        let mut ab = a.clone();
        ab.merge(&b);
        let mut ba = b.clone();
        ba.merge(&a);
        assert_eq!(ab, ba, "merge is commutative");
        assert_eq!(ab.live("hosts"), vec![("1".into(), json!({"id": "1", "label": "web-prod", "port": 2222}))]);

        let mut again = ab.clone();
        again.merge(&ab);
        assert_eq!(again, ab, "merge is idempotent");
    }

    #[test]
    fn same_field_last_writer_wins() {
        let mut a_clock = Clock::new("a");
        let mut b_clock = Clock::new("b");
        let a = state_with("hosts/1", json!({"label": "from a"}), &mut a_clock);
        b_clock.observe(a.latest_stamp().unwrap());
        let b = state_with("hosts/1", json!({"label": "from b"}), &mut b_clock);
        let mut merged = a.clone();
        merged.merge(&b);
        assert_eq!(merged.live("hosts")[0].1, json!({"label": "from b"}), "b wrote after observing a");
    }

    #[test]
    fn delete_vs_later_edit() {
        let mut clock = Clock::new("a");
        let mut s = state_with("hosts/1", json!({"label": "x"}), &mut clock);
        s.delete_local("hosts/1", &mut clock);
        assert!(s.live("hosts").is_empty());

        // An edit stamped after the delete revives the record.
        let mut other = s.clone();
        other.entries.get_mut("hosts/1").unwrap().fields.get_mut("label").unwrap().stamp = clock.now();
        s.merge(&other);
        assert_eq!(s.live("hosts").len(), 1);
    }

    #[test]
    fn unchanged_fields_keep_their_stamps() {
        let mut clock = Clock::new("a");
        let mut s = state_with("hosts/1", json!({"label": "x", "port": 22}), &mut clock);
        let before = s.entries["hosts/1"].fields["port"].stamp.clone();
        assert!(s.record_local("hosts/1", &json!({"label": "y", "port": 22}), &mut clock));
        assert_eq!(s.entries["hosts/1"].fields["port"].stamp, before);
        assert!(!s.record_local("hosts/1", &json!({"label": "y", "port": 22}), &mut clock), "no-op");
    }

    #[test]
    fn clock_moves_past_observed_stamps() {
        let mut clock = Clock::new("slow");
        let future = Stamp { time: u64::MAX / 2, counter: 7, device: "fast".into() };
        clock.observe(&future);
        assert!(clock.now() > future);
    }
}
