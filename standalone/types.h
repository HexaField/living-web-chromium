// Living Web Standalone Library
// Core types - no Chromium dependencies
#ifndef LIVING_WEB_TYPES_H_
#define LIVING_WEB_TYPES_H_

#include <cstdint>
#include <string>
#include <optional>
#include <vector>

namespace living_web {

struct SemanticTriple {
  std::string source;
  std::string target;
  std::optional<std::string> predicate;

  bool Matches(const std::optional<std::string>& q_source,
               const std::optional<std::string>& q_target,
               const std::optional<std::string>& q_predicate) const {
    if (q_source && *q_source != source) return false;
    if (q_target && *q_target != target) return false;
    if (q_predicate && predicate != q_predicate) return false;
    return true;
  }

  bool operator==(const SemanticTriple& other) const {
    return source == other.source && target == other.target &&
           predicate == other.predicate;
  }
};

struct ContentProof {
  std::string key;
  std::string signature;
};

struct SignedTriple {
  SemanticTriple data;
  std::string author;
  std::string timestamp;
  ContentProof proof;

  bool operator==(const SignedTriple& other) const {
    return data == other.data && author == other.author &&
           timestamp == other.timestamp;
  }
};

struct TripleQuery {
  std::optional<std::string> source;
  std::optional<std::string> target;
  std::optional<std::string> predicate;
  std::optional<std::string> from_date;
  std::optional<std::string> until_date;
  std::optional<uint32_t> limit;
};

struct DIDKeyPair {
  std::string id;
  std::string did;
  std::string display_name;
  std::string algorithm;
  std::string created_at;
  bool is_locked = false;
  std::vector<uint8_t> public_key;
  std::vector<uint8_t> private_key;
};

struct SignedContentResult {
  std::string author;
  std::string timestamp;
  std::string data_json;
  std::string proof_key;
  std::string proof_sig;
};

// Validation result for governance
struct ValidationResult {
  bool accepted = true;
  std::string rejecting_constraint_id;
  std::string rejecting_kind;
  std::string reason;
};

// Governance constraint definitions
struct CapabilityConstraintDef {
  std::string constraint_id;
  std::string enforcement;
  std::vector<std::string> predicates;
};

struct TemporalConstraintDef {
  std::string constraint_id;
  std::optional<uint32_t> min_interval_seconds;
  std::optional<uint32_t> max_count_per_window;
  uint32_t window_seconds = 60;
  std::vector<std::string> applies_to_predicates;
};

struct ContentConstraintDef {
  std::string constraint_id;
  std::vector<std::string> blocked_patterns;
  std::optional<uint32_t> max_text_length;
  std::optional<uint32_t> min_text_length;
  std::string url_policy;
  std::vector<std::string> url_list;
  std::vector<std::string> allowed_media_types;
  std::vector<std::string> applies_to_predicates;
};

struct CredentialConstraintDef {
  std::string constraint_id;
  std::string required_credential_type;
  std::string issuer_pattern;
  uint32_t min_age_hours = 0;
};

struct ConstraintsAtScope {
  std::vector<CapabilityConstraintDef> capabilities;
  std::vector<TemporalConstraintDef> temporals;
  std::vector<ContentConstraintDef> contents;
  std::vector<CredentialConstraintDef> credentials;
};

// Sync types
struct GraphDiff {
  std::string revision;
  std::vector<SignedTriple> additions;
  std::vector<SignedTriple> removals;
  std::vector<std::string> dependencies;
  std::string author;
  double timestamp = 0;
};

struct PeerInfo {
  std::string did;
  double last_seen = 0;
  bool is_online = false;
};

// Sync state
enum class SyncState {
  kIdle,
  kSyncing,
  kSynced,
  kError,
};

}  // namespace living_web

#endif  // LIVING_WEB_TYPES_H_
