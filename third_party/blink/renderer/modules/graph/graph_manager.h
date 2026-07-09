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

#include "mojo/public/mojom/graph/graph.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/modules/graph/graph.h"
#include "third_party/blink/renderer/platform/bindings/script_wrappable.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/member.h"
#include "third_party/blink/renderer/platform/mojo/heap_mojo_remote.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

class GraphCreationOptions;
class GraphFromSnapshotOptions;
class GraphSnapshot;
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

  void Trace(Visitor*) const override;

 private:
  // Bind the PersonalGraphManager remote via the browser interface broker.
  void ConnectToBrowser();

  Member<ExecutionContext> execution_context_;
  HeapMojoRemote<graph::mojom::blink::PersonalGraphManager> service_;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_GRAPH_MANAGER_H_
