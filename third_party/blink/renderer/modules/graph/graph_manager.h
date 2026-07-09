// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// GraphManager — the navigator.graph entry point for creating and materialising
// graphs (Personal Linked Data Graphs spec §3.4, §4.1, §5.5). Per-realm; holds
// the browser-process PersonalGraphManager remote. create() and fromSnapshot()
// each mint a PersonalGraphHost pipe, hand the receiver to the browser, and on
// reply construct a renderer-side Graph from the returned GraphInfo.

#ifndef THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_GRAPH_MANAGER_H_
#define THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_GRAPH_MANAGER_H_

#include "base/functional/callback.h"
#include "mojo/public/mojom/graph/graph.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/modules/graph/graph.h"
#include "third_party/blink/renderer/modules/graph/group.h"
#include "third_party/blink/renderer/platform/bindings/script_wrappable.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/member.h"
#include "third_party/blink/renderer/platform/mojo/heap_mojo_remote.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

class ForkOptions;
class GraphCreationOptions;
class GraphFromSnapshotOptions;
class GraphSnapshot;
class GroupCreationOptions;
class GroupifyOptions;
class ScriptState;
class V8SnapshotFormat;

class GraphManager final : public ScriptWrappable {
  DEFINE_WRAPPERTYPEINFO();

 public:
  explicit GraphManager(ExecutionContext*);

  // §3.4 / §5.3.4 supportedSnapshotFormats (static, UA-wide capability). Backs
  // the IDL `static readonly attribute FrozenArray<SnapshotFormat>`. Contains
  // the three REQUIRED formats; jsonld is OPTIONAL and omitted.
  static Vector<V8SnapshotFormat> supportedSnapshotFormats();

  // §4.1 create a fresh, empty, local graph.
  ScriptPromise<Graph> create(ScriptState*, const GraphCreationOptions* options);
  // §5.5 verify and materialise a graph from a snapshot.
  ScriptPromise<Graph> fromSnapshot(ScriptState*,
                                    GraphSnapshot* snapshot,
                                    const GraphFromSnapshotOptions* options);

  // §8.2 group surface (Decentralised Group Identity). createGroup, forkGroup
  // and openGroup mint a fresh host-graph PersonalGraphHost pipe plus a GroupHost
  // pipe; groupify reuses the caller's existing |graph| (by its internal id) and
  // binds only a GroupHost.
  ScriptPromise<Group> createGroup(ScriptState*,
                                   const GroupCreationOptions* options);
  ScriptPromise<Group> groupify(ScriptState*,
                                Graph* graph,
                                const GroupifyOptions* options);
  ScriptPromise<Group> forkGroup(ScriptState*,
                                 const String& parent_iri_or_did,
                                 const ForkOptions* options);
  ScriptPromise<Group> openGroup(ScriptState*, const String& iri_or_did);
  ScriptPromise<IDLSequence<Group>> listGroups(ScriptState*);

  // Opens |iri_or_did| into a Group (minting a fresh GroupHost + host-graph
  // PersonalGraphHost binding) and hands it to |on_done|, or nullptr if it could
  // not be opened. Backs Group::ResolveGroupList (parentGroups/childGroups and
  // listGroups()).
  void OpenGroupByDid(const String& iri_or_did,
                      base::OnceCallback<void(Group*)> on_done);

  void Trace(Visitor*) const override;

 private:
  // Bind the PersonalGraphManager remote via the browser interface broker.
  void ConnectToBrowser();
  // Bind the GroupManager remote via the browser interface broker.
  void ConnectToGroupService();

  // Assemble a Group from a GroupInfo and the two freshly-bound host pipes: the
  // GroupHost (governance) and the host graph's PersonalGraphHost (the Group's
  // `graph` attribute). |this| becomes the Group's minting manager.
  Group* BuildGroup(
      ExecutionContext* context,
      const graph::mojom::blink::GroupInfoPtr& info,
      mojo::PendingRemote<graph::mojom::blink::GroupHost> group_host,
      mojo::PendingRemote<graph::mojom::blink::PersonalGraphHost> graph_host);

  Member<ExecutionContext> execution_context_;
  HeapMojoRemote<graph::mojom::blink::PersonalGraphManager> service_;
  HeapMojoRemote<graph::mojom::blink::GroupManager> group_service_;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_GRAPH_MANAGER_H_
