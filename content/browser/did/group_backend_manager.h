// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// GroupBackendManager — the browser-process port of the §8.2 `GroupManager`
// (navigator.graph group extension) of Spec 03. A faithful C++ port of
// living_web::GroupManager (standalone/group_provider.h).
//
// A group's DID document *is* triples in a host GraphBackend, so this manager
// leans on the per-realm GraphBackendManager to allocate and own those host
// graphs (unlike the standalone, whose GraphManager hands ownership to the
// caller — here the GraphBackendManager retains it, and this manager simply
// indexes each group's host by did:graph so participation edges between
// locally-mounted groups resolve, §4.7). It also holds a non-owning pointer to
// the identity provider, which stores every group's initial key so that
// group-authored writes resolve through the ordinary SignRaw path.

#ifndef CONTENT_BROWSER_DID_GROUP_BACKEND_MANAGER_H_
#define CONTENT_BROWSER_DID_GROUP_BACKEND_MANAGER_H_

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "base/memory/raw_ptr.h"
#include "content/browser/did/did_key_provider.h"
#include "content/browser/did/group_backend.h"
#include "content/browser/graph/graph_backend_manager.h"

namespace content {

class GroupBackendManager {
 public:
  GroupBackendManager(DIDKeyProvider* identity, GraphBackendManager* graphs);

  GroupBackendManager(const GroupBackendManager&) = delete;
  GroupBackendManager& operator=(const GroupBackendManager&) = delete;

  ~GroupBackendManager();

  const std::string& last_error() const { return last_error_; }

  // §8.2 createGroup: allocate a fresh host graph and groupify it. The initial
  // key holds all four capability sections (a group-of-one works out of the
  // box, §11); extra |initial_delegates| are granted capabilityInvocation. When
  // |participates_in| is set the group authors its own
  // context://participates_in edge (§7.1) — the parent must still accept it via
  // GroupBackend::Invite (§6.2). nullptr + last_error() on failure.
  std::unique_ptr<GroupBackend> CreateGroup(const GroupCreationOptions& opts);

  // §8.2 groupify: turn an existing host graph (owned by the GraphBackendManager
  // and identified elsewhere by its id) into a group. Rejects with
  // "InvalidStateError" if it already carries a group://didIdentity binding —
  // groupification is one-way (§4.2). The manager indexes it by DID so
  // participation resolves; ownership stays with the GraphBackendManager.
  std::unique_ptr<GroupBackend> Groupify(GraphBackend* existing,
                                         const GroupifyOptions& opts);

  // §8.2 forkGroup (§4.8): mint a fresh identity, copy the parent's graph state,
  // strip the parent identity, and write the child seed with forkedFrom/
  // forkedAtRevision. |parent| is a did:graph or a current IRI of a locally
  // mounted group. Announces `<parent> group://forkedTo <child>` on the parent
  // when |announce_fork| (§4.8 step 6). The root-capability mint (§4.8 step 5)
  // and the constraint-kind superset check (§4.8.1 → NotSupportedError) belong
  // to the Capability Framework (Spec 04) and Constraint Vocabulary (Spec 08).
  std::unique_ptr<GroupBackend> ForkGroup(const std::string& parent,
                                          const ForkOptions& opts);

  // §8.2 openGroup: a handle over an already-known group named by did:graph or
  // by current IRI. Only locally-mounted groups resolve (§4.7). nullptr +
  // "NotFoundError" otherwise.
  std::unique_ptr<GroupBackend> OpenGroup(const std::string& iri_or_did);

  // Every group this manager currently mounts.
  std::vector<std::unique_ptr<GroupBackend>> ListGroups();

  // Resolve a did:graph or a current graph IRI to the host GraphBackend, or
  // nullptr. Public so participation descents across group handles resolve.
  GraphBackend* LookupHost(const std::string& key);

 private:
  friend class GroupBackend;

  // A GroupBackend view over a mounted host graph, acting as the group's own key
  // by default (it holds every section, §11).
  std::unique_ptr<GroupBackend> MakeHandle(GraphBackend* g);

  // The provider credential id of the group's own initial key (method "graph",
  // did == |group_did|), or empty if the caller never held it.
  std::string GroupCredentialId(const std::string& group_did) const;

  static bool HasBinding(GraphBackend* g);

  // The one-way groupification bootstrap (§4.2). Mints the initial Ed25519
  // keypair, derives the did:graph, adopts the key into the provider, binds it
  // to |g|, and writes the seed (binding + syncModule + the creator method in
  // all four sections + metadata + optional fork lineage) followed by the
  // governed initial-delegate grants (capabilityInvocation). Returns the adopted
  // group credential, or nullptr with last_error_ set. The creator DID is
  // captured BEFORE adoption, because adopting into an empty provider would make
  // the group key active and corrupt the read.
  const DIDKeyPair* DoGroupify(
      GraphBackend* g,
      const std::string& sync_module,
      const std::optional<std::string>& display_name,
      const std::optional<std::string>& description,
      const std::vector<std::string>& initial_delegates,
      const std::optional<std::string>& forked_from,
      const std::optional<std::string>& forked_at);

  // §4.8 step 3: remove every triple that identifies |parent_did| as a group
  // from a freshly-copied |child| — the binding, the DID document, the metadata,
  // and the participation edges the parent declared. The group's content triples
  // (subject != the parent identity) are left intact with their reifiers: fork
  // inherits the verifiable history.
  void StripIdentity(GraphBackend* child, const std::string& parent_did);

  raw_ptr<DIDKeyProvider> identity_;         // Not owned.
  raw_ptr<GraphBackendManager> graphs_;      // Not owned.
  std::map<std::string, raw_ptr<GraphBackend>> did_index_;  // Not owned.
  std::string last_error_;
};

}  // namespace content

#endif  // CONTENT_BROWSER_DID_GROUP_BACKEND_MANAGER_H_
