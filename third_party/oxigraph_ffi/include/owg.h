// C ABI for the Oxigraph-backed graph substrate of the Living Web
// (Spec 02 — Personal Linked Data Graphs).
//
// This header is the single source of truth for the boundary between the
// browser-process graph service / standalone C++ harness and the Rust engine
// (`third_party/oxigraph_ffi`). It mirrors the `#[no_mangle] extern "C"`
// surface of `src/lib.rs` exactly; keep the two in lockstep.
//
// Capabilities exposed, all mandated by Spec 02 and none hand-rolled:
//   * a persistent (RocksDB) or in-memory RDF 1.2 quad store,
//   * RDF Dataset Canonicalization (rdfc-1.0) — the `graph://<hash>` foundation,
//   * SPARQL 1.2 evaluation, including holonic named-graph datasets.
//
// Interchange is string-oriented: RDF 1.2 N-Quads (with `<<( s p o )>>` triple
// terms for reifiers) for graph data, and the SPARQL 1.1 JSON Results format
// for SELECT/ASK query results.
//
// Ownership:
//   * every `OwgBuf` returned by value owns heap memory and MUST be released
//     with `owg_buf_free`;
//   * store handles (`void*`) MUST be released with `owg_store_free`;
//   * `owg_last_error` returns detail for the most recent failed call on the
//     current thread, valid only until the next call on that thread.

#ifndef LIVING_WEB_THIRD_PARTY_OXIGRAPH_FFI_OWG_H_
#define LIVING_WEB_THIRD_PARTY_OXIGRAPH_FFI_OWG_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// RDF serialisation format codes (shared by every format-taking entry point).
typedef enum {
  OWG_FORMAT_NQUADS = 0,    // RDF 1.2 N-Quads (dataset; the ingest format)
  OWG_FORMAT_NTRIPLES = 1,  // RDF 1.2 N-Triples (default graph only)
  OWG_FORMAT_TURTLE = 2,    // RDF 1.2 Turtle (default graph only)
  OWG_FORMAT_TRIG = 3       // RDF 1.2 TriG (dataset)
} OwgFormat;

// Blank-node hashing function for rdfc-1.0. The canonical N-Quads output is the
// same shape either way; this only selects the digest used during labelling.
typedef enum {
  OWG_HASH_SHA256 = 0,
  OWG_HASH_SHA384 = 1
} OwgHash;

// Result discriminant written through the `out_kind` out-parameter of
// owg_store_query.
typedef enum {
  OWG_QUERY_SOLUTIONS = 0,  // SELECT  -> SPARQL 1.1 JSON Results
  OWG_QUERY_BOOLEAN = 1,    // ASK     -> SPARQL 1.1 JSON Results (boolean)
  OWG_QUERY_GRAPH = 2       // CONSTRUCT/DESCRIBE -> RDF 1.2 N-Triples
} OwgQueryKind;

// An owned byte buffer handed across the ABI. `data` is NULL on failure (call
// owg_last_error for detail). Release every non-null buffer with owg_buf_free.
typedef struct {
  uint8_t* data;
  size_t len;
  size_t cap;
} OwgBuf;

// A named graph contributed to a holonic SPARQL dataset: its `graph://` IRI and
// the RDF 1.2 N-Quads of its triples (expressed in their own default graph).
typedef struct {
  const char* iri;
  const char* nquads;
  size_t nquads_len;
} OwgNamedGraph;

// Most recent error on the calling thread, or NULL if the last call succeeded.
// Valid until the next FFI call on this thread; do not free.
const char* owg_last_error(void);

// Releases a buffer previously returned by value from this library.
void owg_buf_free(OwgBuf buf);

// ---- store lifecycle -------------------------------------------------------

// Fresh in-memory store, or NULL on failure.
void* owg_store_new_memory(void);

// Opens (creating if absent) a persistent RocksDB store at `path`, or NULL on
// failure.
void* owg_store_open(const char* path);

// Releases a store handle.
void owg_store_free(void* handle);

// Number of quads in the store, or -1 on error.
int64_t owg_store_len(void* handle);

// Empties the store. 0 on success, -1 on error.
int owg_store_clear(void* handle);

// ---- ingest / egest --------------------------------------------------------

// Loads RDF 1.2 N-Quads into the store's default graph. Atomic: nothing is
// committed on a parse error. Blank nodes are renamed consistently within the
// call, so a reifier and its provenance triples stay linked when supplied in
// one call. 0 on success, -1 on error.
int owg_store_load_nquads(void* handle, const char* data, size_t len);

// Removes the quads described by the supplied N-Quads document. Returns the
// number of quads removed, or -1 on error.
int64_t owg_store_remove_nquads(void* handle, const char* data, size_t len);

// Serialises the whole store as RDF 1.2 N-Quads (non-canonical order).
OwgBuf owg_store_dump_nquads(void* handle);

// Serialises the store's default graph in `fmt` (an OwgFormat). Dataset formats
// (N-Quads, TriG) serialise every quad; graph formats (N-Triples, Turtle)
// serialise the default graph, which is where Spec 02 keeps all triples.
OwgBuf owg_store_serialize(void* handle, int fmt);

// ---- canonicalisation (content-hash foundation) ----------------------------

// Canonicalises an RDF 1.2 N-Quads document with rdfc-1.0. `hash` is an OwgHash
// selecting the blank-node hashing function. The returned bytes are the exact
// UTF-8 sequence Spec 02 §5.2 hashes to form the `graph://` IRI: each quad
// serialised as one canonical N-Quads line, lines sorted, concatenated.
OwgBuf owg_canonicalize_nquads(const char* data, size_t len, int hash);

// Computes the `graph://<hash>` content-address IRI of an RDF 1.2 N-Quads
// document (Spec 02 §5.2): "graph://" followed by the lowercase-hex SHA-256 of
// the rdfc-1.0 canonical N-Quads bytes. An empty document yields the well-known
// empty-graph IRI (graph:// + SHA-256("")). Null buffer on error.
OwgBuf owg_graph_iri(const char* data, size_t len);

// Converts an RDF 1.2 document between syntaxes (`in_fmt`/`out_fmt` are
// OwgFormat codes). Used to normalise Turtle / N-Quads snapshot inputs into the
// N-Quads the store ingests.
OwgBuf owg_convert(const char* data,
                   size_t len,
                   int in_fmt,
                   int out_fmt);

// ---- SPARQL ----------------------------------------------------------------

// Evaluates a SPARQL 1.2 query. The store's default graph is the query's
// default graph, snapshotted at call-start into an ephemeral dataset so
// concurrent writes are not observed mid-query (§7.2). Each OwgNamedGraph is
// loaded as a named graph keyed by its IRI, addressable via
// `GRAPH <graph://...> { ... }`.
//
// `*out_kind` (an OwgQueryKind) is set to distinguish SELECT / ASK / CONSTRUCT.
// Returns the serialised result, or a null buffer on error.
OwgBuf owg_store_query(void* handle,
                       const char* sparql,
                       size_t sparql_len,
                       const OwgNamedGraph* named,
                       size_t n_named,
                       int* out_kind);

// Applies a SPARQL 1.2 Update (e.g. `DELETE … WHERE`) to the store's default
// graph as one atomic transaction. Spec 02 removeTriple uses this to delete a
// data triple together with its blank-node reifier by binding the reifier as a
// variable — a deletion label-based N-Quads removal cannot express. Returns 0 on
// success, -1 on error.
int owg_store_update(void* handle, const char* data, size_t len);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // LIVING_WEB_THIRD_PARTY_OXIGRAPH_FFI_OWG_H_
