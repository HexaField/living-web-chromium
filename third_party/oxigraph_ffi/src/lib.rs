// C-ABI wrapper over Oxigraph for the Living Web graph substrate (Spec 02 —
// Personal Linked Data Graphs).
//
// This crate is the RDF engine behind the browser-process graph service and the
// standalone C++ test harness. It provides exactly three capabilities, all of
// which Spec 02 mandates and none of which are hand-rolled:
//
//   * a persistent (RocksDB) or in-memory quad store over RDF 1.2 data,
//   * RDF Dataset Canonicalization (rdfc-1.0) — the `graph://<hash>` foundation,
//   * SPARQL 1.2 evaluation, including holonic named-graph datasets.
//
// The interchange format across the ABI is RDF 1.2 N-Quads (with `<<( s p o )>>`
// triple terms for reifiers) and, for query results, the SPARQL 1.1 JSON Results
// format. Keeping the ABI string-oriented keeps the surface small and the C++
// mirror faithful.
//
// Memory ownership: every `OwgBuf` returned by value is heap-allocated by Rust
// and MUST be released with `owg_buf_free`. Store handles are released with
// `owg_store_free`. Error detail for the most recent failed call on the current
// thread is available from `owg_last_error`.

use std::cell::RefCell;
use std::ffi::{c_char, c_int, CStr, CString};
use std::io::Cursor;
use std::os::raw::c_void;
use std::ptr;
use std::slice;

use oxigraph::io::{RdfFormat, RdfParser, RdfSerializer};
use oxigraph::model::dataset::{CanonicalizationAlgorithm, CanonicalizationHashAlgorithm};
use oxigraph::model::{Dataset, GraphName, NamedNode, Quad};
use oxigraph::sparql::results::{QueryResultsFormat, QueryResultsSerializer};
use oxigraph::sparql::{QueryResults, SparqlEvaluator};
use oxigraph::store::Store;

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

fn set_error(msg: impl Into<String>) {
    let c = CString::new(msg.into()).unwrap_or_else(|_| CString::new("error").unwrap());
    LAST_ERROR.with(|e| *e.borrow_mut() = Some(c));
}

fn clear_error() {
    LAST_ERROR.with(|e| *e.borrow_mut() = None);
}

/// Returns a pointer to a NUL-terminated string describing the most recent error
/// on the calling thread, or NULL if the last FFI call succeeded. The pointer is
/// valid until the next FFI call on this thread.
#[no_mangle]
pub extern "C" fn owg_last_error() -> *const c_char {
    LAST_ERROR.with(|e| match &*e.borrow() {
        Some(c) => c.as_ptr(),
        None => ptr::null(),
    })
}

/// An owned byte buffer handed across the ABI. `data` is NULL on failure.
/// Release with `owg_buf_free`.
#[repr(C)]
pub struct OwgBuf {
    data: *mut u8,
    len: usize,
    cap: usize,
}

impl OwgBuf {
    fn from_vec(mut v: Vec<u8>) -> Self {
        v.shrink_to_fit();
        let buf = OwgBuf {
            data: v.as_mut_ptr(),
            len: v.len(),
            cap: v.capacity(),
        };
        std::mem::forget(v);
        buf
    }

    fn null() -> Self {
        OwgBuf {
            data: ptr::null_mut(),
            len: 0,
            cap: 0,
        }
    }
}

/// Frees a buffer previously returned by value from this library.
#[no_mangle]
pub unsafe extern "C" fn owg_buf_free(buf: OwgBuf) {
    if !buf.data.is_null() {
        drop(Vec::from_raw_parts(buf.data, buf.len, buf.cap));
    }
}

// ---- helpers ---------------------------------------------------------------

unsafe fn bytes<'a>(data: *const c_char, len: usize) -> Option<&'a [u8]> {
    if data.is_null() {
        return None;
    }
    Some(slice::from_raw_parts(data as *const u8, len))
}

unsafe fn store_ref<'a>(handle: *mut c_void) -> Option<&'a Store> {
    if handle.is_null() {
        set_error("null store handle");
        return None;
    }
    Some(&*(handle as *const Store))
}

// N-Quads format is RDF 1.2 (triple-term aware) because the crate is built with
// the `rdf-12` feature; the same RdfFormat variant carries the extended syntax.
fn fmt_from_code(code: c_int) -> Option<RdfFormat> {
    match code {
        0 => Some(RdfFormat::NQuads),
        1 => Some(RdfFormat::NTriples),
        2 => Some(RdfFormat::Turtle),
        3 => Some(RdfFormat::TriG),
        _ => None,
    }
}

// ---- store lifecycle -------------------------------------------------------

/// Creates a fresh in-memory store. Returns NULL on failure.
#[no_mangle]
pub extern "C" fn owg_store_new_memory() -> *mut c_void {
    clear_error();
    match Store::new() {
        Ok(s) => Box::into_raw(Box::new(s)) as *mut c_void,
        Err(e) => {
            set_error(format!("store new: {e}"));
            ptr::null_mut()
        }
    }
}

/// Opens (creating if absent) a persistent RocksDB-backed store at `path`.
/// Returns NULL on failure.
#[no_mangle]
pub unsafe extern "C" fn owg_store_open(path: *const c_char) -> *mut c_void {
    clear_error();
    if path.is_null() {
        set_error("null path");
        return ptr::null_mut();
    }
    let path = match CStr::from_ptr(path).to_str() {
        Ok(p) => p,
        Err(_) => {
            set_error("path is not valid UTF-8");
            return ptr::null_mut();
        }
    };
    match Store::open(path) {
        Ok(s) => Box::into_raw(Box::new(s)) as *mut c_void,
        Err(e) => {
            set_error(format!("store open: {e}"));
            ptr::null_mut()
        }
    }
}

/// Releases a store handle.
#[no_mangle]
pub unsafe extern "C" fn owg_store_free(handle: *mut c_void) {
    if !handle.is_null() {
        drop(Box::from_raw(handle as *mut Store));
    }
}

/// Number of quads in the store, or -1 on error.
#[no_mangle]
pub unsafe extern "C" fn owg_store_len(handle: *mut c_void) -> i64 {
    clear_error();
    let Some(store) = store_ref(handle) else {
        return -1;
    };
    match store.len() {
        Ok(n) => n as i64,
        Err(e) => {
            set_error(format!("len: {e}"));
            -1
        }
    }
}

/// Empties the store. Returns 0 on success, -1 on error.
#[no_mangle]
pub unsafe extern "C" fn owg_store_clear(handle: *mut c_void) -> c_int {
    clear_error();
    let Some(store) = store_ref(handle) else {
        return -1;
    };
    match store.clear() {
        Ok(()) => 0,
        Err(e) => {
            set_error(format!("clear: {e}"));
            -1
        }
    }
}

// ---- ingest / egest --------------------------------------------------------

/// Loads RDF 1.2 N-Quads into the store's default graph. The load is atomic: on
/// a parse error nothing is committed. Blank nodes are renamed consistently
/// within the call so a reifier and its provenance triples stay linked when
/// supplied together. Returns 0 on success, -1 on error.
#[no_mangle]
pub unsafe extern "C" fn owg_store_load_nquads(
    handle: *mut c_void,
    data: *const c_char,
    len: usize,
) -> c_int {
    clear_error();
    let Some(store) = store_ref(handle) else {
        return -1;
    };
    let Some(buf) = bytes(data, len) else {
        set_error("null data");
        return -1;
    };
    match store.load_from_reader(RdfParser::from_format(RdfFormat::NQuads), Cursor::new(buf)) {
        Ok(()) => 0,
        Err(e) => {
            set_error(format!("load: {e}"));
            -1
        }
    }
}

/// Removes the quads described by the supplied N-Quads document from the store.
/// Blank-node-bearing quads are matched structurally after a local
/// canonicalisation so that reifier removal is label-independent. Returns the
/// number of quads removed, or -1 on error.
#[no_mangle]
pub unsafe extern "C" fn owg_store_remove_nquads(
    handle: *mut c_void,
    data: *const c_char,
    len: usize,
) -> i64 {
    clear_error();
    let Some(store) = store_ref(handle) else {
        return -1;
    };
    let Some(buf) = bytes(data, len) else {
        set_error("null data");
        return -1;
    };
    let mut removed = 0i64;
    for quad in RdfParser::from_format(RdfFormat::NQuads).for_reader(Cursor::new(buf)) {
        let quad = match quad {
            Ok(q) => q,
            Err(e) => {
                set_error(format!("remove parse: {e}"));
                return -1;
            }
        };
        // Store::remove returns Result<(), _> without signalling presence, so
        // probe existence first to report an accurate removed count.
        match store.contains(quad.as_ref()) {
            Ok(true) => match store.remove(quad.as_ref()) {
                Ok(()) => removed += 1,
                Err(e) => {
                    set_error(format!("remove: {e}"));
                    return -1;
                }
            },
            Ok(false) => {}
            Err(e) => {
                set_error(format!("remove contains: {e}"));
                return -1;
            }
        }
    }
    removed
}

/// Serialises the whole store as RDF 1.2 N-Quads (non-canonical order).
#[no_mangle]
pub unsafe extern "C" fn owg_store_dump_nquads(handle: *mut c_void) -> OwgBuf {
    clear_error();
    let Some(store) = store_ref(handle) else {
        return OwgBuf::null();
    };
    let mut out = Vec::new();
    match store.dump_to_writer(RdfSerializer::from_format(RdfFormat::NQuads), &mut out) {
        Ok(_) => OwgBuf::from_vec(out),
        Err(e) => {
            set_error(format!("dump: {e}"));
            OwgBuf::null()
        }
    }
}

/// Serialises the store's default graph in the requested RDF 1.2 syntax.
/// `fmt`: 0=N-Quads, 1=N-Triples, 2=Turtle, 3=TriG. Dataset formats (N-Quads,
/// TriG) serialise every quad; graph formats (N-Triples, Turtle) serialise the
/// default graph, which is where Spec 02 keeps all triples.
#[no_mangle]
pub unsafe extern "C" fn owg_store_serialize(handle: *mut c_void, fmt: c_int) -> OwgBuf {
    clear_error();
    let Some(store) = store_ref(handle) else {
        return OwgBuf::null();
    };
    let Some(format) = fmt_from_code(fmt) else {
        set_error("unknown format code");
        return OwgBuf::null();
    };
    let mut out = Vec::new();
    let result = if format.supports_datasets() {
        store
            .dump_to_writer(RdfSerializer::from_format(format), &mut out)
            .map(|_| ())
    } else {
        store
            .dump_graph_to_writer(
                GraphName::DefaultGraph.as_ref(),
                RdfSerializer::from_format(format),
                &mut out,
            )
            .map(|_| ())
    };
    match result {
        Ok(()) => OwgBuf::from_vec(out),
        Err(e) => {
            set_error(format!("serialize: {e}"));
            OwgBuf::null()
        }
    }
}

// ---- canonicalisation (content-hash foundation) ----------------------------

fn parse_nquads_to_dataset(buf: &[u8]) -> Result<Dataset, String> {
    let mut dataset = Dataset::new();
    for quad in RdfParser::from_format(RdfFormat::NQuads).for_reader(Cursor::new(buf)) {
        let quad: Quad = quad.map_err(|e| format!("canon parse: {e}"))?;
        dataset.insert(&quad);
    }
    Ok(dataset)
}

fn hash_from_code(hash: c_int) -> Result<CanonicalizationHashAlgorithm, String> {
    match hash {
        0 => Ok(CanonicalizationHashAlgorithm::Sha256),
        1 => Ok(CanonicalizationHashAlgorithm::Sha384),
        _ => Err("unknown hash code".to_string()),
    }
}

/// Produces the exact UTF-8 byte sequence Spec 02 §5.2 hashes: the N-Quads
/// document canonicalised with rdfc-1.0, each quad emitted as one canonical
/// N-Quads line, the lines sorted and concatenated. Shared by the public
/// canonicalisation entry point and the `graph://` content-address computation
/// so the two never diverge.
fn canonical_nquads_string(
    buf: &[u8],
    hash_algorithm: CanonicalizationHashAlgorithm,
) -> Result<String, String> {
    let mut dataset = parse_nquads_to_dataset(buf)?;
    dataset.canonicalize(CanonicalizationAlgorithm::Rdfc10 { hash_algorithm });

    let mut lines: Vec<String> = Vec::with_capacity(dataset.len());
    for quad in dataset.iter() {
        let mut line = Vec::new();
        let mut ser = RdfSerializer::from_format(RdfFormat::NQuads).for_writer(&mut line);
        ser.serialize_quad(quad)
            .map_err(|e| format!("canon serialize: {e}"))?;
        ser.finish().map_err(|e| format!("canon finish: {e}"))?;
        lines.push(String::from_utf8(line).map_err(|_| "canon output not UTF-8".to_string())?);
    }
    lines.sort();
    Ok(lines.concat())
}

/// Canonicalises an RDF 1.2 N-Quads document with RDF Dataset Canonicalization
/// (rdfc-1.0). `hash`: 0=SHA-256, 1=SHA-384 (the bnode-hashing function; the
/// output is canonical N-Quads either way). The returned bytes are the exact
/// UTF-8 sequence Spec 02 §5.2 hashes to form the `graph://` IRI: each quad
/// serialised as one canonical N-Quads line, lines sorted, concatenated.
#[no_mangle]
pub unsafe extern "C" fn owg_canonicalize_nquads(
    data: *const c_char,
    len: usize,
    hash: c_int,
) -> OwgBuf {
    clear_error();
    let Some(buf) = bytes(data, len) else {
        set_error("null data");
        return OwgBuf::null();
    };
    let hash_algorithm = match hash_from_code(hash) {
        Ok(h) => h,
        Err(e) => {
            set_error(e);
            return OwgBuf::null();
        }
    };
    match canonical_nquads_string(buf, hash_algorithm) {
        Ok(s) => OwgBuf::from_vec(s.into_bytes()),
        Err(e) => {
            set_error(e);
            OwgBuf::null()
        }
    }
}

/// Computes the `graph://<hash>` content-address IRI of an RDF 1.2 N-Quads
/// document (Spec 02 §5.2): `"graph://"` followed by the lowercase-hex SHA-256
/// of the rdfc-1.0 canonical N-Quads bytes (blank-node hashing fixed to SHA-256,
/// the digest §5.2 mandates for the IRI). An empty document canonicalises to the
/// empty string, whose SHA-256 gives the well-known empty-graph IRI. Returns a
/// null buffer on error.
#[no_mangle]
pub unsafe extern "C" fn owg_graph_iri(data: *const c_char, len: usize) -> OwgBuf {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;

    clear_error();
    let Some(buf) = bytes(data, len) else {
        set_error("null data");
        return OwgBuf::null();
    };
    let canonical = match canonical_nquads_string(buf, CanonicalizationHashAlgorithm::Sha256) {
        Ok(s) => s,
        Err(e) => {
            set_error(e);
            return OwgBuf::null();
        }
    };
    let digest = Sha256::digest(canonical.as_bytes());
    let mut iri = String::with_capacity(8 + 64);
    iri.push_str("graph://");
    for byte in digest {
        // Infallible: writing to a String never errors.
        let _ = write!(iri, "{byte:02x}");
    }
    OwgBuf::from_vec(iri.into_bytes())
}

/// Converts an RDF 1.2 document between syntaxes. `in_fmt`/`out_fmt` use the
/// format codes of `owg_store_serialize`. Used by snapshot materialisation to
/// normalise Turtle / N-Quads inputs into the N-Quads the store ingests.
#[no_mangle]
pub unsafe extern "C" fn owg_convert(
    data: *const c_char,
    len: usize,
    in_fmt: c_int,
    out_fmt: c_int,
) -> OwgBuf {
    clear_error();
    let Some(buf) = bytes(data, len) else {
        set_error("null data");
        return OwgBuf::null();
    };
    let (Some(inf), Some(outf)) = (fmt_from_code(in_fmt), fmt_from_code(out_fmt)) else {
        set_error("unknown format code");
        return OwgBuf::null();
    };
    let mut out = Vec::new();
    let mut ser = RdfSerializer::from_format(outf).for_writer(&mut out);
    for quad in RdfParser::from_format(inf).for_reader(Cursor::new(buf)) {
        let quad = match quad {
            Ok(q) => q,
            Err(e) => {
                set_error(format!("convert parse: {e}"));
                return OwgBuf::null();
            }
        };
        // Graph formats (N-Triples/Turtle) only carry the default graph; drop
        // any graph name so a default-graph-only dataset round-trips cleanly.
        if let Err(e) = ser.serialize_quad(quad.as_ref()) {
            set_error(format!("convert serialize: {e}"));
            return OwgBuf::null();
        }
    }
    match ser.finish() {
        Ok(_) => OwgBuf::from_vec(out),
        Err(e) => {
            set_error(format!("convert finish: {e}"));
            OwgBuf::null()
        }
    }
}

// ---- SPARQL ----------------------------------------------------------------

/// A named graph contributed to a holonic SPARQL dataset: its `graph://` IRI and
/// the RDF 1.2 N-Quads of its triples (in their own default graph).
#[repr(C)]
pub struct OwgNamedGraph {
    iri: *const c_char,
    nquads: *const c_char,
    nquads_len: usize,
}

/// Evaluates a SPARQL 1.2 query. The store's default graph is the query's
/// default graph (snapshotted at call-start into an ephemeral dataset so
/// concurrent writes are not observed mid-query, per §7.2). Each `OwgNamedGraph`
/// is loaded as a named graph keyed by its IRI, addressable via
/// `GRAPH <graph://...> { ... }`.
///
/// `out_kind` is set to 0 for SELECT (SPARQL JSON results), 1 for ASK (SPARQL
/// JSON boolean), 2 for CONSTRUCT/DESCRIBE (N-Triples). Returns the serialised
/// result, or a null buffer on error.
#[no_mangle]
pub unsafe extern "C" fn owg_store_query(
    handle: *mut c_void,
    sparql: *const c_char,
    sparql_len: usize,
    named: *const OwgNamedGraph,
    n_named: usize,
    out_kind: *mut c_int,
) -> OwgBuf {
    clear_error();
    let Some(store) = store_ref(handle) else {
        return OwgBuf::null();
    };
    let Some(qbytes) = bytes(sparql, sparql_len) else {
        set_error("null query");
        return OwgBuf::null();
    };
    let query = match std::str::from_utf8(qbytes) {
        Ok(q) => q,
        Err(_) => {
            set_error("query is not valid UTF-8");
            return OwgBuf::null();
        }
    };

    // Snapshot the store's default graph into an ephemeral in-memory dataset.
    let scratch = match Store::new() {
        Ok(s) => s,
        Err(e) => {
            set_error(format!("scratch store: {e}"));
            return OwgBuf::null();
        }
    };
    for quad in store.iter() {
        match quad {
            Ok(q) => {
                if let Err(e) = scratch.insert(q.as_ref()) {
                    set_error(format!("snapshot insert: {e}"));
                    return OwgBuf::null();
                }
            }
            Err(e) => {
                set_error(format!("snapshot read: {e}"));
                return OwgBuf::null();
            }
        }
    }

    // Load each named graph into the ephemeral dataset under its IRI.
    if !named.is_null() {
        let entries = slice::from_raw_parts(named, n_named);
        for entry in entries {
            if entry.iri.is_null() {
                set_error("named graph missing iri");
                return OwgBuf::null();
            }
            let iri = match CStr::from_ptr(entry.iri).to_str() {
                Ok(s) => s,
                Err(_) => {
                    set_error("named graph iri not UTF-8");
                    return OwgBuf::null();
                }
            };
            let graph_name = match NamedNode::new(iri) {
                Ok(n) => n,
                Err(e) => {
                    set_error(format!("named graph iri invalid: {e}"));
                    return OwgBuf::null();
                }
            };
            let Some(ng_bytes) = bytes(entry.nquads, entry.nquads_len) else {
                set_error("named graph missing data");
                return OwgBuf::null();
            };
            if let Err(e) = scratch.load_from_reader(
                RdfParser::from_format(RdfFormat::NQuads)
                    .with_default_graph(GraphName::NamedNode(graph_name)),
                Cursor::new(ng_bytes),
            ) {
                set_error(format!("named graph load: {e}"));
                return OwgBuf::null();
            }
        }
    }

    // parse_query and execute report distinct error types (syntax vs
    // evaluation), so they cannot share a single `?`/and_then chain.
    let prepared = match SparqlEvaluator::new().parse_query(query) {
        Ok(q) => q,
        Err(e) => {
            set_error(format!("query parse: {e}"));
            return OwgBuf::null();
        }
    };
    let results = match prepared.on_store(&scratch).execute() {
        Ok(r) => r,
        Err(e) => {
            set_error(format!("query execute: {e}"));
            return OwgBuf::null();
        }
    };

    match results {
        QueryResults::Solutions(solutions) => {
            if !out_kind.is_null() {
                *out_kind = 0;
            }
            let mut out = Vec::new();
            let variables = solutions.variables().to_vec();
            let serializer = QueryResultsSerializer::from_format(QueryResultsFormat::Json);
            let mut writer = match serializer.serialize_solutions_to_writer(&mut out, variables) {
                Ok(w) => w,
                Err(e) => {
                    set_error(format!("results header: {e}"));
                    return OwgBuf::null();
                }
            };
            for solution in solutions {
                match solution {
                    Ok(s) => {
                        if let Err(e) = writer.serialize(&s) {
                            set_error(format!("results row: {e}"));
                            return OwgBuf::null();
                        }
                    }
                    Err(e) => {
                        set_error(format!("results eval: {e}"));
                        return OwgBuf::null();
                    }
                }
            }
            if let Err(e) = writer.finish() {
                set_error(format!("results finish: {e}"));
                return OwgBuf::null();
            }
            OwgBuf::from_vec(out)
        }
        QueryResults::Boolean(value) => {
            if !out_kind.is_null() {
                *out_kind = 1;
            }
            let mut out = Vec::new();
            let serializer = QueryResultsSerializer::from_format(QueryResultsFormat::Json);
            if let Err(e) = serializer.serialize_boolean_to_writer(&mut out, value) {
                set_error(format!("ask serialize: {e}"));
                return OwgBuf::null();
            }
            OwgBuf::from_vec(out)
        }
        QueryResults::Graph(triples) => {
            if !out_kind.is_null() {
                *out_kind = 2;
            }
            let mut out = Vec::new();
            let mut ser = RdfSerializer::from_format(RdfFormat::NTriples).for_writer(&mut out);
            for triple in triples {
                match triple {
                    Ok(t) => {
                        if let Err(e) = ser.serialize_triple(t.as_ref()) {
                            set_error(format!("construct serialize: {e}"));
                            return OwgBuf::null();
                        }
                    }
                    Err(e) => {
                        set_error(format!("construct eval: {e}"));
                        return OwgBuf::null();
                    }
                }
            }
            match ser.finish() {
                Ok(_) => OwgBuf::from_vec(out),
                Err(e) => {
                    set_error(format!("construct finish: {e}"));
                    OwgBuf::null()
                }
            }
        }
    }
}

/// Applies a SPARQL 1.2 Update (`DELETE … WHERE`, `INSERT DATA`, …) to the
/// store's default graph. Spec 02 `removeTriple` uses this to delete a data
/// triple together with its blank-node reifier by binding the reifier as a
/// variable, which label-based N-Quads removal cannot express. The update runs
/// as a single atomic transaction. Returns 0 on success, -1 on error.
#[no_mangle]
pub unsafe extern "C" fn owg_store_update(
    handle: *mut c_void,
    data: *const c_char,
    len: usize,
) -> c_int {
    clear_error();
    let Some(store) = store_ref(handle) else {
        return -1;
    };
    let Some(buf) = bytes(data, len) else {
        set_error("null data");
        return -1;
    };
    let update = match std::str::from_utf8(buf) {
        Ok(u) => u,
        Err(_) => {
            set_error("update is not valid UTF-8");
            return -1;
        }
    };
    // parse_update and execute report distinct error types (syntax vs
    // evaluation), so they cannot share a single `?` chain.
    let prepared = match SparqlEvaluator::new().parse_update(update) {
        Ok(u) => u,
        Err(e) => {
            set_error(format!("update parse: {e}"));
            return -1;
        }
    };
    match prepared.on_store(store).execute() {
        Ok(()) => 0,
        Err(e) => {
            set_error(format!("update execute: {e}"));
            -1
        }
    }
}
