// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_DID_DID_CREDENTIAL_H_
#define CONTENT_BROWSER_DID_DID_CREDENTIAL_H_

#include <string>

namespace content {

// DIDCredential info struct — matches DIDCredentialInfo in Mojo.
struct DIDCredentialInfo {
  std::string id;
  std::string did;
  std::string algorithm;
  std::string display_name;
  std::string created_at;
  bool is_locked = false;
};

}  // namespace content

#endif  // CONTENT_BROWSER_DID_DID_CREDENTIAL_H_
