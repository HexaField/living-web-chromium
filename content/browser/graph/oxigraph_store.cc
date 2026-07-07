// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/graph/oxigraph_store.h"

#include "third_party/oxigraph_ffi/include/owg.h"

namespace living_web {
namespace {

// Captures the current thread-local FFI error into a C++ string.
std::string CaptureError() {
  const char* err = owg_last_error();
  return err ? std::string(err) : std::string("unknown oxigraph error");
}

// Moves an owned OwgBuf into a std::string and frees it. Returns false when the
// buffer is null (an FFI failure).
bool TakeBuf(OwgBuf buf, std::string* out) {
  if (buf.data == nullptr)
    return false;
  out->assign(reinterpret_cast<const char*>(buf.data), buf.len);
  owg_buf_free(buf);
  return true;
}

}  // namespace

OxigraphStore::OxigraphStore() {
  handle_ = owg_store_new_memory();
  if (!handle_)
    last_error_ = CaptureError();
}

OxigraphStore::OxigraphStore(const std::string& path) {
  handle_ = owg_store_open(path.c_str());
  if (!handle_)
    last_error_ = CaptureError();
}

OxigraphStore::~OxigraphStore() {
  if (handle_)
    owg_store_free(handle_);
}

OxigraphStore::OxigraphStore(OxigraphStore&& other) noexcept
    : handle_(other.handle_), last_error_(std::move(other.last_error_)) {
  other.handle_ = nullptr;
}

OxigraphStore& OxigraphStore::operator=(OxigraphStore&& other) noexcept {
  if (this != &other) {
    if (handle_)
      owg_store_free(handle_);
    handle_ = other.handle_;
    last_error_ = std::move(other.last_error_);
    other.handle_ = nullptr;
  }
  return *this;
}

bool OxigraphStore::LoadNquads(const std::string& nquads) {
  if (owg_store_load_nquads(handle_, nquads.data(), nquads.size()) != 0) {
    last_error_ = CaptureError();
    return false;
  }
  return true;
}

int64_t OxigraphStore::RemoveNquads(const std::string& nquads) {
  int64_t n = owg_store_remove_nquads(handle_, nquads.data(), nquads.size());
  if (n < 0)
    last_error_ = CaptureError();
  return n;
}

bool OxigraphStore::Clear() {
  if (owg_store_clear(handle_) != 0) {
    last_error_ = CaptureError();
    return false;
  }
  return true;
}

int64_t OxigraphStore::Len() {
  int64_t n = owg_store_len(handle_);
  if (n < 0)
    last_error_ = CaptureError();
  return n;
}

bool OxigraphStore::DumpNquads(std::string* out) {
  if (!TakeBuf(owg_store_dump_nquads(handle_), out)) {
    last_error_ = CaptureError();
    return false;
  }
  return true;
}

bool OxigraphStore::Serialize(RdfFormat format, std::string* out) {
  if (!TakeBuf(owg_store_serialize(handle_, static_cast<int>(format)), out)) {
    last_error_ = CaptureError();
    return false;
  }
  return true;
}

SparqlResult OxigraphStore::Query(
    const std::string& sparql,
    const std::vector<NamedGraphInput>& named_graphs) {
  SparqlResult result;

  // The OwgNamedGraph array borrows the IRIs and N-Quads held in |named_graphs|,
  // which must outlive the call — they do (this is a synchronous call).
  std::vector<OwgNamedGraph> named;
  named.reserve(named_graphs.size());
  for (const auto& ng : named_graphs) {
    OwgNamedGraph entry;
    entry.iri = ng.iri.c_str();
    entry.nquads = ng.nquads.data();
    entry.nquads_len = ng.nquads.size();
    named.push_back(entry);
  }

  int out_kind = 0;
  OwgBuf buf = owg_store_query(handle_, sparql.data(), sparql.size(),
                               named.empty() ? nullptr : named.data(),
                               named.size(), &out_kind);
  if (buf.data == nullptr) {
    result.ok = false;
    result.error = CaptureError();
    last_error_ = result.error;
    return result;
  }
  result.ok = true;
  result.kind = static_cast<SparqlResultKind>(out_kind);
  result.payload.assign(reinterpret_cast<const char*>(buf.data), buf.len);
  owg_buf_free(buf);
  return result;
}

bool OxigraphStore::Update(const std::string& sparql) {
  if (owg_store_update(handle_, sparql.data(), sparql.size()) != 0) {
    last_error_ = CaptureError();
    return false;
  }
  return true;
}

// static
bool OxigraphStore::GraphIri(const std::string& nquads,
                             std::string* out,
                             std::string* error) {
  if (!TakeBuf(owg_graph_iri(nquads.data(), nquads.size()), out)) {
    if (error)
      *error = CaptureError();
    return false;
  }
  return true;
}

// static
bool OxigraphStore::Canonicalize(const std::string& nquads,
                                 CanonHash hash,
                                 std::string* out,
                                 std::string* error) {
  OwgBuf buf = owg_canonicalize_nquads(nquads.data(), nquads.size(),
                                       static_cast<int>(hash));
  if (!TakeBuf(buf, out)) {
    if (error)
      *error = CaptureError();
    return false;
  }
  return true;
}

// static
bool OxigraphStore::Convert(const std::string& data,
                            RdfFormat in_format,
                            RdfFormat out_format,
                            std::string* out,
                            std::string* error) {
  OwgBuf buf = owg_convert(data.data(), data.size(),
                           static_cast<int>(in_format),
                           static_cast<int>(out_format));
  if (!TakeBuf(buf, out)) {
    if (error)
      *error = CaptureError();
    return false;
  }
  return true;
}

}  // namespace living_web
