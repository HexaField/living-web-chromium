// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/graph_sync/sync_backend.h"

#include <ctime>
#include <iomanip>
#include <sstream>

#include "content/browser/graph/oxigraph_store.h"
#include "crypto/sha2.h"
#include "third_party/ed25519/ed25519.h"

namespace content {

namespace {

// RFC 3339 UTC timestamp, matching the file-local helper in graph_backend.cc,
// group_backend.cc and governance_backend.cc so sync commits stamp identically
// to graph / group / governance writes.
std::string NowRfc3339() {
  auto now = std::time(nullptr);
  auto* tm = std::gmtime(&now);
  std::ostringstream ss;
  ss << std::put_time(tm, "%Y-%m-%dT%H:%M:%SZ");
  return ss.str();
}

}  // namespace

// ---- §5.2.2 diff construction ----------------------------------------------

bool SyncBackend::CommitDiff(GraphBackend* W,
                             const std::string& author_cred_id,
                             const std::vector<living_web::Triple>& additions,
                             const std::vector<living_web::Triple>& removals,
                             const CommitOptions& opts,
                             GraphDiff* out) {
  std::optional<std::string> wdid = W ? W->did() : std::nullopt;
  if (!wdid || wdid->empty()) {
    last_error_ = "InvalidStateError";  // sync requires a DID (§Abstract)
    return false;
  }
  const DIDKeyPair* author = identity_->GetCredential(author_cred_id);
  if (!author) {
    last_error_ = "InvalidStateError";
    return false;
  }

  GraphDiff diff;
  diff.graph_did = *wdid;
  diff.author = author->did;
  diff.timestamp = opts.timestamp.empty() ? NowRfc3339() : opts.timestamp;
  diff.diffs_since_snapshot = opts.diffs_since_snapshot;
  diff.snapshot_promotion = opts.snapshot_promotion;
  diff.capability_proof = opts.capability_proof;
  diff.dependencies = living_web::SortDependencies(opts.dependencies);

  const std::string method =
      author->did + "#" +
      *living_web::did_key::Ed25519PublicKeyMultibase(author->public_key);

  if (!AuthorReifiers(*wdid, author, additions, diff.timestamp, method,
                      &diff.additions) ||
      !AuthorReifiers(*wdid, author, removals, diff.timestamp, method,
                      &diff.removals)) {
    return false;  // last_error_ set
  }

  std::string canon_add, canon_rem, err;
  if (!CanonicalizeDiffTriples(diff.additions, &canon_add, &err) ||
      !CanonicalizeDiffTriples(diff.removals, &canon_rem, &err)) {
    last_error_ = "canonicalization_failed: " + err;
    return false;
  }

  diff.revision = living_web::ToLowerHex(
      crypto::SHA256HashString(living_web::BuildRevisionPreimage(
          *wdid, canon_add, canon_rem, diff.dependencies)));

  const std::string leaf =
      (diff.capability_proof && !diff.capability_proof->chain.empty())
          ? diff.capability_proof->chain.front()
          : std::string();
  diff.commit_id = living_web::ToLowerHex(
      crypto::SHA256HashString(living_web::BuildCommitIdPreimage(
          diff.revision, diff.author, diff.timestamp, leaf)));

  const std::string msg = living_web::BuildSignatureMessage(diff.commit_id);
  auto sig = identity_->SignRaw(author->id,
                                std::vector<uint8_t>(msg.begin(), msg.end()));
  if (!sig) {
    last_error_ = "InvalidStateError";  // locked/unknown credential
    return false;
  }
  diff.signature = living_web::did_key::MultibaseEncode(*sig);

  RecordAccepted(diff);
  if (out)
    *out = std::move(diff);
  return true;
}

// ---- §9.2.1 validateDiff ---------------------------------------------------

SyncValidationResult SyncBackend::ValidateDiff(GraphBackend* W,
                                               const GraphDiff& diff) {
  SyncValidationResult res;
  std::optional<std::string> wdid = W ? W->did() : std::nullopt;
  if (!wdid || wdid->empty() || *wdid != diff.graph_did)
    return Reject(&res, "capability", "", "graph_did_mismatch");

  // §14.4 replay: an already-applied revision is a no-op accept.
  if (Chain(diff.graph_did).revisions.count(diff.revision))
    return res;  // accepted (idempotent)

  // Step 0 — verify bundle signature (recompute revision + commitId).
  std::string canon_add, canon_rem, err;
  if (!CanonicalizeDiffTriples(diff.additions, &canon_add, &err) ||
      !CanonicalizeDiffTriples(diff.removals, &canon_rem, &err))
    return Reject(&res, "capability", "", "canonicalization_failed");

  const std::string revision = living_web::ToLowerHex(
      crypto::SHA256HashString(living_web::BuildRevisionPreimage(
          diff.graph_did, canon_add, canon_rem,
          living_web::SortDependencies(diff.dependencies))));
  if (revision != diff.revision)
    return Reject(&res, "capability", "", "revision_invalid");

  const std::string leaf =
      (diff.capability_proof && !diff.capability_proof->chain.empty())
          ? diff.capability_proof->chain.front()
          : std::string();
  const std::string commit_id = living_web::ToLowerHex(
      crypto::SHA256HashString(living_web::BuildCommitIdPreimage(
          revision, diff.author, diff.timestamp, leaf)));
  if (commit_id != diff.commit_id)
    return Reject(&res, "capability", "", "commit_invalid");

  if (!VerifyBundleSignature(W, diff, commit_id))
    return Reject(&res, "capability", "", "signature_invalid");

  // Steps 1–3 — capability chain + caveats, per addition and removal. The
  // GovernanceBackend collects constraints (§6.2), walks the chain to
  // BootstrapRoot (§7), re-evaluates content caveats (§9), applies deny-wins
  // (§6.3), and honours the enforcement mode (§9.4) internally.
  for (const DiffTriple& dt : diff.additions) {
    GovernanceValidationResult g =
        governance_->CanAddTriple(W, dt.triple, diff.author);
    if (!g.allowed)
      return Reject(&res, g.constraint_kind, g.rejected_by, g.reason);
  }
  for (const DiffTriple& dt : diff.removals) {
    GovernanceValidationResult g =
        governance_->CanAddTriple(W, dt.triple, diff.author);
    if (!g.allowed)
      return Reject(&res, g.constraint_kind, g.rejected_by, g.reason);
  }

  // Step 4 — verify each reifier signature against the resolved author, and
  // bind every reifier's author to the diff's committing agent (§5.2.2: the
  // reifiers are committer-authored, so a diff cannot smuggle triples attributed
  // to a different agent).
  for (const DiffTriple& dt : diff.additions)
    if (!VerifyReifier(W, diff.graph_did, diff.author, dt))
      return Reject(&res, "capability", "", "reifier_signature_invalid");
  for (const DiffTriple& dt : diff.removals)
    if (!VerifyReifier(W, diff.graph_did, diff.author, dt))
      return Reject(&res, "capability", "", "reifier_signature_invalid");

  // Step 5 — dependencies (§5.2.1).
  if (!ValidateDependencies(diff))
    return Reject(&res, "capability", "", dependency_error_);

  // §14.5 timestamp plausibility (any path that trusts the timestamp MUST).
  if (std::string ts_reason; !CheckTimestamp(diff, &ts_reason))
    return Reject(&res, "temporal", "", ts_reason);

  // Step 6 — accept and record.
  RecordAccepted(diff);
  return res;
}

// ---- §7.3 sync-space derivation --------------------------------------------

std::optional<std::string> SyncBackend::DeriveSpace(
    GraphBackend* W,
    living_web::SpaceTopology topology,
    const std::string& custom_name) {
  std::optional<std::string> wdid = W ? W->did() : std::nullopt;
  if (!wdid || wdid->empty()) {
    last_error_ = "InvalidStateError";
    return std::nullopt;
  }
  std::string namespace_id =
      group_detail::FirstIriOf(W, *wdid, living_web::kContextParticipatesIn)
          .value_or(*wdid);
  std::string input = living_web::BuildSpaceDerivationInput(
      topology, IsRestricted(W), namespace_id, *wdid, custom_name);
  return std::string(living_web::kSpaceScheme) +
         living_web::ToLowerHex(crypto::SHA256HashString(input));
}

// ---- private helpers -------------------------------------------------------

bool SyncBackend::AuthorReifiers(const std::string& graph_did,
                                 const DIDKeyPair* author,
                                 const std::vector<living_web::Triple>& triples,
                                 const std::string& timestamp,
                                 const std::string& method,
                                 std::vector<DiffTriple>* out) {
  out->clear();
  out->reserve(triples.size());
  for (const living_web::Triple& t : triples) {
    std::string payload = crypto::SHA256HashString(
        living_web::BuildSignaturePreimage(t, timestamp, graph_did));
    auto sig = identity_->SignRaw(
        author->id, std::vector<uint8_t>(payload.begin(), payload.end()));
    if (!sig) {
      last_error_ = "InvalidStateError";
      return false;
    }
    DiffTriple dt;
    dt.triple = t;
    dt.author = author->did;
    dt.timestamp = timestamp;
    dt.method = method;
    dt.signature = living_web::did_key::MultibaseEncode(*sig);
    out->push_back(std::move(dt));
  }
  return true;
}

bool SyncBackend::CanonicalizeDiffTriples(
    const std::vector<DiffTriple>& triples,
    std::string* out,
    std::string* err) {
  if (triples.empty()) {
    out->clear();
    return true;
  }
  std::string block;
  for (size_t i = 0; i < triples.size(); ++i) {
    const DiffTriple& dt = triples[i];
    block += living_web::BuildTripleWithReifierNquads(
        dt.triple, "_:r" + std::to_string(i), dt.author, dt.timestamp,
        dt.method, dt.signature);
  }
  return living_web::OxigraphStore::Canonicalize(
      block, living_web::CanonHash::kSha256, out, err);
}

std::vector<std::vector<uint8_t>> SyncBackend::ResolveAuthorKeys(
    GraphBackend* W,
    const std::string& author) {
  std::vector<std::vector<uint8_t>> keys;
  if (living_web::did_graph::IsDidGraph(author)) {
    living_web::DidDocument doc;
    if (group_detail::ProjectDidDocument(W, author, &doc) && !doc.deactivated) {
      for (const std::string& md : doc.capability_delegation) {
        const living_web::VerificationMethod* vm = doc.FindMethod(md);
        if (!vm)
          continue;
        if (auto pk =
                living_web::DecodePublicKeyMultibase(vm->public_key_multibase))
          keys.push_back(std::move(*pk));
      }
    }
  } else if (auto pk = living_web::ParseAnyDidEd25519(author)) {
    keys.push_back(std::move(*pk));
  }
  return keys;
}

bool SyncBackend::VerifyBundleSignature(GraphBackend* W,
                                        const GraphDiff& diff,
                                        const std::string& commit_id) {
  std::string msg = living_web::BuildSignatureMessage(commit_id);
  auto sig = living_web::did_key::MultibaseDecode(diff.signature);
  if (!sig || sig->size() != 64)
    return false;
  for (const auto& pub : ResolveAuthorKeys(W, diff.author)) {
    if (pub.size() == 32 &&
        ed25519_verify(sig->data(),
                       reinterpret_cast<const uint8_t*>(msg.data()), msg.size(),
                       pub.data()) == 1)
      return true;
  }
  return false;
}

bool SyncBackend::VerifyReifier(GraphBackend* W,
                                const std::string& graph_did,
                                const std::string& diff_author,
                                const DiffTriple& dt) {
  if (dt.author != diff_author)
    return false;
  std::string payload = crypto::SHA256HashString(
      living_web::BuildSignaturePreimage(dt.triple, dt.timestamp, graph_did));
  auto sig = living_web::did_key::MultibaseDecode(dt.signature);
  if (!sig || sig->size() != 64)
    return false;
  for (const auto& pub : ResolveAuthorKeys(W, dt.author)) {
    if (pub.size() == 32 &&
        ed25519_verify(sig->data(),
                       reinterpret_cast<const uint8_t*>(payload.data()),
                       payload.size(), pub.data()) == 1)
      return true;
  }
  return false;
}

bool SyncBackend::ValidateDependencies(const GraphDiff& diff) {
  ChainState& chain = Chain(diff.graph_did);
  if (diff.dependencies.empty()) {
    if (!chain.revisions.empty() && !diff.snapshot_promotion) {
      dependency_error_ = "chain_root_conflict";
      return false;
    }
    return true;
  }
  for (const std::string& dep : diff.dependencies) {
    if (!chain.revisions.count(dep)) {
      dependency_error_ = "missing_dependency";
      return false;
    }
  }
  return true;
}

bool SyncBackend::CheckTimestamp(const GraphDiff& diff, std::string* reason) {
  int64_t ts = 0;
  if (!sync_detail::Rfc3339ToEpoch(diff.timestamp, &ts)) {
    *reason = "timestamp_malformed";
    return false;
  }
  if (ts > static_cast<int64_t>(std::time(nullptr)) + 300) {
    *reason = "timestamp_future";
    return false;
  }
  ChainState& chain = Chain(diff.graph_did);
  for (const std::string& dep : diff.dependencies) {
    auto it = chain.ts_of.find(dep);
    if (it == chain.ts_of.end())
      continue;
    int64_t dts = 0;
    if (sync_detail::Rfc3339ToEpoch(it->second, &dts) && ts < dts) {
      *reason = "timestamp_causal";
      return false;
    }
  }
  auto am = chain.author_max.find(diff.author);
  if (am != chain.author_max.end()) {
    int64_t ats = 0;
    if (sync_detail::Rfc3339ToEpoch(am->second, &ats) && ts < ats) {
      *reason = "timestamp_monotonic";
      return false;
    }
  }
  return true;
}

void SyncBackend::RecordAccepted(const GraphDiff& diff) {
  ChainState& chain = Chain(diff.graph_did);
  chain.revisions.insert(diff.revision);
  chain.ts_of[diff.revision] = diff.timestamp;
  auto& am = chain.author_max[diff.author];
  if (am.empty() || am < diff.timestamp)
    am = diff.timestamp;
}

}  // namespace content
