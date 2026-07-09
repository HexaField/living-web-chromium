// C-ABI wrapper over OpenMLS (RFC 9420) for the Living Web Default Sync Module
// (Spec 09 — drafts/09_default-sync-module.md).
//
// This crate is the MLS engine behind the browser-process default-sync backend
// and the standalone C++ test harness. Spec 09 §6.3 mounts a real MLS group per
// encrypted space; the ceremony (group creation, Add/Remove/Update Commits,
// Welcomes, the ratchet tree) and the epoch key schedule are RFC 9420 and are
// delivered by OpenMLS, none hand-rolled — exactly as Spec 02's RDF substrate is
// delivered by Oxigraph.
//
// The seam to the Chromium-independent Spec 09 core is `mls_member_export_secret`
// (the RFC 9420 §8.5 exporter): called with label="lw-sync space frame",
// context=spaceUri, out_len=32 it returns the 32-byte space traffic secret that
// the core's DeriveSpaceTrafficSecret() computes, from which the core derives
// the AEAD frame key/nonce (§6.3.9) and seals/opens frames (§6.3.10).
//
// Memory ownership: every `MlsBuf` returned by value is heap-allocated by Rust
// and MUST be released with `mls_buf_free`; member handles with `mls_member_free`.
// Error detail for the most recent failed call on the current thread is
// available from `mls_last_error`.

use std::cell::RefCell;
use std::ffi::{c_char, c_int, CString};
use std::ptr;
use std::slice;

use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use tls_codec::{Deserialize as _, Serialize as _};

// The single MLS cipher suite pinned by Spec 09 §6.3.2:
// MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 (0x0001).
const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

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

/// Pointer to a NUL-terminated string describing the most recent error on the
/// calling thread, or NULL if the last FFI call succeeded. Valid until the next
/// FFI call on this thread.
#[no_mangle]
pub extern "C" fn mls_last_error() -> *const c_char {
    LAST_ERROR.with(|e| match &*e.borrow() {
        Some(c) => c.as_ptr(),
        None => ptr::null(),
    })
}

/// An owned byte buffer handed across the ABI. `data` is NULL on failure.
#[repr(C)]
pub struct MlsBuf {
    data: *mut u8,
    len: usize,
    cap: usize,
}

impl MlsBuf {
    fn from_vec(mut v: Vec<u8>) -> Self {
        v.shrink_to_fit();
        let buf = MlsBuf {
            data: v.as_mut_ptr(),
            len: v.len(),
            cap: v.capacity(),
        };
        std::mem::forget(v);
        buf
    }

    fn null() -> Self {
        MlsBuf {
            data: ptr::null_mut(),
            len: 0,
            cap: 0,
        }
    }
}

/// Frees a buffer previously returned by value from this library.
#[no_mangle]
pub unsafe extern "C" fn mls_buf_free(buf: MlsBuf) {
    if !buf.data.is_null() {
        drop(Vec::from_raw_parts(buf.data, buf.len, buf.cap));
    }
}

// ---- member ----------------------------------------------------------------

/// An MLS member: its crypto provider (with in-memory storage), its Ed25519
/// signature key pair + basic credential, and (once created or joined) its
/// MLS group.
pub struct MlsMember {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential_with_key: CredentialWithKey,
    group: Option<MlsGroup>,
}

unsafe fn bytes<'a>(data: *const u8, len: usize) -> Option<&'a [u8]> {
    if data.is_null() {
        return None;
    }
    Some(slice::from_raw_parts(data, len))
}

unsafe fn member_mut<'a>(m: *mut MlsMember) -> Option<&'a mut MlsMember> {
    if m.is_null() {
        set_error("null member handle");
        return None;
    }
    Some(&mut *m)
}

/// Creates a member whose BasicCredential carries `identity`. Generates a fresh
/// Ed25519 signature key pair and stores it in the member's provider storage.
#[no_mangle]
pub unsafe extern "C" fn mls_member_new(
    identity: *const c_char,
    identity_len: usize,
) -> *mut MlsMember {
    clear_error();
    let id = match bytes(identity as *const u8, identity_len) {
        Some(b) => b.to_vec(),
        None => {
            set_error("null identity");
            return ptr::null_mut();
        }
    };
    let provider = OpenMlsRustCrypto::default();
    let signer = match SignatureKeyPair::new(SignatureScheme::ED25519) {
        Ok(s) => s,
        Err(e) => {
            set_error(format!("signature keygen: {e:?}"));
            return ptr::null_mut();
        }
    };
    if let Err(e) = signer.store(provider.storage()) {
        set_error(format!("store signer: {e:?}"));
        return ptr::null_mut();
    }
    let credential_with_key = CredentialWithKey {
        credential: BasicCredential::new(id).into(),
        signature_key: signer.public().into(),
    };
    Box::into_raw(Box::new(MlsMember {
        provider,
        signer,
        credential_with_key,
        group: None,
    }))
}

/// Releases a member and its group state.
#[no_mangle]
pub unsafe extern "C" fn mls_member_free(member: *mut MlsMember) {
    if !member.is_null() {
        drop(Box::from_raw(member));
    }
}

/// The member's 32-byte Ed25519 signature public key.
#[no_mangle]
pub unsafe extern "C" fn mls_member_signature_public_key(member: *mut MlsMember) -> MlsBuf {
    clear_error();
    let m = match member_mut(member) {
        Some(m) => m,
        None => return MlsBuf::null(),
    };
    MlsBuf::from_vec(m.signer.public().to_vec())
}

/// A fresh KeyPackage for this member, serialised as an MLS message.
#[no_mangle]
pub unsafe extern "C" fn mls_member_key_package(member: *mut MlsMember) -> MlsBuf {
    clear_error();
    let m = match member_mut(member) {
        Some(m) => m,
        None => return MlsBuf::null(),
    };
    let bundle = match KeyPackage::builder().build(
        CIPHERSUITE,
        &m.provider,
        &m.signer,
        m.credential_with_key.clone(),
    ) {
        Ok(b) => b,
        Err(e) => {
            set_error(format!("build key package: {e:?}"));
            return MlsBuf::null();
        }
    };
    let out = MlsMessageOut::from(bundle.key_package().clone());
    match out.tls_serialize_detached() {
        Ok(v) => MlsBuf::from_vec(v),
        Err(e) => {
            set_error(format!("serialize key package: {e:?}"));
            MlsBuf::null()
        }
    }
}

/// This member founds a new MLS group with the given group_id (Spec 09 §6.3.1).
#[no_mangle]
pub unsafe extern "C" fn mls_member_create_group(
    member: *mut MlsMember,
    group_id: *const u8,
    group_id_len: usize,
) -> c_int {
    clear_error();
    let m = match member_mut(member) {
        Some(m) => m,
        None => return -1,
    };
    let gid = match bytes(group_id, group_id_len) {
        Some(b) => b,
        None => {
            set_error("null group id");
            return -1;
        }
    };
    match MlsGroup::builder()
        .with_group_id(GroupId::from_slice(gid))
        .ciphersuite(CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .build(&m.provider, &m.signer, m.credential_with_key.clone())
    {
        Ok(g) => {
            m.group = Some(g);
            0
        }
        Err(e) => {
            set_error(format!("create group: {e:?}"));
            -1
        }
    }
}

/// This member adds the holder of `key_package`, committing and merging the Add.
#[no_mangle]
pub unsafe extern "C" fn mls_member_add(
    member: *mut MlsMember,
    key_package: *const u8,
    kp_len: usize,
    out_commit: *mut MlsBuf,
    out_welcome: *mut MlsBuf,
) -> c_int {
    clear_error();
    let m = match member_mut(member) {
        Some(m) => m,
        None => return -1,
    };
    let kp_bytes = match bytes(key_package, kp_len) {
        Some(b) => b,
        None => {
            set_error("null key package");
            return -1;
        }
    };
    let msg = match MlsMessageIn::tls_deserialize_exact(kp_bytes) {
        Ok(x) => x,
        Err(e) => {
            set_error(format!("parse key package: {e:?}"));
            return -1;
        }
    };
    let kp_in = match msg.extract() {
        MlsMessageBodyIn::KeyPackage(k) => k,
        _ => {
            set_error("message is not a KeyPackage");
            return -1;
        }
    };
    let kp = match kp_in.validate(m.provider.crypto(), ProtocolVersion::Mls10) {
        Ok(k) => k,
        Err(e) => {
            set_error(format!("validate key package: {e:?}"));
            return -1;
        }
    };
    if m.group.is_none() {
        set_error("member has no group");
        return -1;
    }
    let (commit, welcome, _gi) = {
        let group = m.group.as_mut().unwrap();
        match group.add_members(&m.provider, &m.signer, &[kp]) {
            Ok(t) => t,
            Err(e) => {
                set_error(format!("add member: {e:?}"));
                return -1;
            }
        }
    };
    if let Err(e) = m.group.as_mut().unwrap().merge_pending_commit(&m.provider) {
        set_error(format!("merge pending commit: {e:?}"));
        return -1;
    }
    let commit_bytes = match commit.tls_serialize_detached() {
        Ok(v) => v,
        Err(e) => {
            set_error(format!("serialize commit: {e:?}"));
            return -1;
        }
    };
    let welcome_bytes = match welcome.tls_serialize_detached() {
        Ok(v) => v,
        Err(e) => {
            set_error(format!("serialize welcome: {e:?}"));
            return -1;
        }
    };
    if !out_commit.is_null() {
        *out_commit = MlsBuf::from_vec(commit_bytes);
    }
    if !out_welcome.is_null() {
        *out_welcome = MlsBuf::from_vec(welcome_bytes);
    }
    0
}

/// This member joins from a Welcome (the ratchet tree travels inside it).
#[no_mangle]
pub unsafe extern "C" fn mls_member_join(
    member: *mut MlsMember,
    welcome: *const u8,
    welcome_len: usize,
) -> c_int {
    clear_error();
    let m = match member_mut(member) {
        Some(m) => m,
        None => return -1,
    };
    let wbytes = match bytes(welcome, welcome_len) {
        Some(b) => b,
        None => {
            set_error("null welcome");
            return -1;
        }
    };
    let msg = match MlsMessageIn::tls_deserialize_exact(wbytes) {
        Ok(x) => x,
        Err(e) => {
            set_error(format!("parse welcome: {e:?}"));
            return -1;
        }
    };
    let welcome = match msg.extract() {
        MlsMessageBodyIn::Welcome(w) => w,
        _ => {
            set_error("message is not a Welcome");
            return -1;
        }
    };
    let join_config = MlsGroupJoinConfig::builder().build();
    let staged = match StagedWelcome::new_from_welcome(&m.provider, &join_config, welcome, None) {
        Ok(s) => s,
        Err(e) => {
            set_error(format!("stage welcome: {e:?}"));
            return -1;
        }
    };
    match staged.into_group(&m.provider) {
        Ok(g) => {
            m.group = Some(g);
            0
        }
        Err(e) => {
            set_error(format!("join group: {e:?}"));
            -1
        }
    }
}

/// This member applies a Commit produced by another member.
#[no_mangle]
pub unsafe extern "C" fn mls_member_process_commit(
    member: *mut MlsMember,
    commit: *const u8,
    commit_len: usize,
) -> c_int {
    clear_error();
    let m = match member_mut(member) {
        Some(m) => m,
        None => return -1,
    };
    let cbytes = match bytes(commit, commit_len) {
        Some(b) => b,
        None => {
            set_error("null commit");
            return -1;
        }
    };
    let msg = match MlsMessageIn::tls_deserialize_exact(cbytes) {
        Ok(x) => x,
        Err(e) => {
            set_error(format!("parse commit: {e:?}"));
            return -1;
        }
    };
    let proto = match msg.try_into_protocol_message() {
        Ok(p) => p,
        Err(e) => {
            set_error(format!("to protocol message: {e:?}"));
            return -1;
        }
    };
    if m.group.is_none() {
        set_error("member has no group");
        return -1;
    }
    let processed = {
        let group = m.group.as_mut().unwrap();
        match group.process_message(&m.provider, proto) {
            Ok(p) => p,
            Err(e) => {
                set_error(format!("process message: {e:?}"));
                return -1;
            }
        }
    };
    match processed.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged) => {
            match m
                .group
                .as_mut()
                .unwrap()
                .merge_staged_commit(&m.provider, *staged)
            {
                Ok(()) => 0,
                Err(e) => {
                    set_error(format!("merge staged commit: {e:?}"));
                    -1
                }
            }
        }
        _ => {
            set_error("processed message was not a commit");
            -1
        }
    }
}

/// This member issues a self-Update Commit, committing and merging it.
#[no_mangle]
pub unsafe extern "C" fn mls_member_update(member: *mut MlsMember, out_commit: *mut MlsBuf) -> c_int {
    clear_error();
    let m = match member_mut(member) {
        Some(m) => m,
        None => return -1,
    };
    if m.group.is_none() {
        set_error("member has no group");
        return -1;
    }
    let commit_bytes = {
        let group = m.group.as_mut().unwrap();
        let bundle = match group.self_update(&m.provider, &m.signer, LeafNodeParameters::default()) {
            Ok(b) => b,
            Err(e) => {
                set_error(format!("self update: {e:?}"));
                return -1;
            }
        };
        match bundle.commit().tls_serialize_detached() {
            Ok(v) => v,
            Err(e) => {
                set_error(format!("serialize commit: {e:?}"));
                return -1;
            }
        }
    };
    if let Err(e) = m.group.as_mut().unwrap().merge_pending_commit(&m.provider) {
        set_error(format!("merge pending commit: {e:?}"));
        return -1;
    }
    if !out_commit.is_null() {
        *out_commit = MlsBuf::from_vec(commit_bytes);
    }
    0
}

/// This member removes the member at `leaf_index`, committing and merging it.
#[no_mangle]
pub unsafe extern "C" fn mls_member_remove(
    member: *mut MlsMember,
    leaf_index: u32,
    out_commit: *mut MlsBuf,
) -> c_int {
    clear_error();
    let m = match member_mut(member) {
        Some(m) => m,
        None => return -1,
    };
    if m.group.is_none() {
        set_error("member has no group");
        return -1;
    }
    let commit_bytes = {
        let group = m.group.as_mut().unwrap();
        let (commit, _welcome, _gi) = match group.remove_members(
            &m.provider,
            &m.signer,
            &[LeafNodeIndex::new(leaf_index)],
        ) {
            Ok(t) => t,
            Err(e) => {
                set_error(format!("remove member: {e:?}"));
                return -1;
            }
        };
        match commit.tls_serialize_detached() {
            Ok(v) => v,
            Err(e) => {
                set_error(format!("serialize commit: {e:?}"));
                return -1;
            }
        }
    };
    if let Err(e) = m.group.as_mut().unwrap().merge_pending_commit(&m.provider) {
        set_error(format!("merge pending commit: {e:?}"));
        return -1;
    }
    if !out_commit.is_null() {
        *out_commit = MlsBuf::from_vec(commit_bytes);
    }
    0
}

/// The member's own leaf index, or -1 if not in a group.
#[no_mangle]
pub unsafe extern "C" fn mls_member_own_leaf_index(member: *mut MlsMember) -> i64 {
    clear_error();
    let m = match member_mut(member) {
        Some(m) => m,
        None => return -1,
    };
    match m.group.as_ref() {
        Some(g) => g.own_leaf_index().u32() as i64,
        None => {
            set_error("member has no group");
            -1
        }
    }
}

/// The group's current epoch, or -1 if not in a group.
#[no_mangle]
pub unsafe extern "C" fn mls_member_epoch(member: *mut MlsMember) -> i64 {
    clear_error();
    let m = match member_mut(member) {
        Some(m) => m,
        None => return -1,
    };
    match m.group.as_ref() {
        Some(g) => g.epoch().as_u64() as i64,
        None => {
            set_error("member has no group");
            -1
        }
    }
}

/// The number of members in the group, or -1 if not in a group.
#[no_mangle]
pub unsafe extern "C" fn mls_member_count(member: *mut MlsMember) -> i64 {
    clear_error();
    let m = match member_mut(member) {
        Some(m) => m,
        None => return -1,
    };
    match m.group.as_ref() {
        Some(g) => g.members().count() as i64,
        None => {
            set_error("member has no group");
            -1
        }
    }
}

/// The RFC 9420 §8.5 MLS-Exporter for the current epoch (the Spec 09 §6.3.9
/// seam). Returns the `out_len`-byte exported secret.
#[no_mangle]
pub unsafe extern "C" fn mls_member_export_secret(
    member: *mut MlsMember,
    label: *const c_char,
    label_len: usize,
    context: *const u8,
    context_len: usize,
    out_len: usize,
) -> MlsBuf {
    clear_error();
    let m = match member_mut(member) {
        Some(m) => m,
        None => return MlsBuf::null(),
    };
    let label_bytes = match bytes(label as *const u8, label_len) {
        Some(b) => b,
        None => {
            set_error("null label");
            return MlsBuf::null();
        }
    };
    let label_str = match std::str::from_utf8(label_bytes) {
        Ok(s) => s,
        Err(_) => {
            set_error("label is not valid UTF-8");
            return MlsBuf::null();
        }
    };
    let ctx: &[u8] = if context.is_null() {
        &[]
    } else {
        slice::from_raw_parts(context, context_len)
    };
    let group = match m.group.as_ref() {
        Some(g) => g,
        None => {
            set_error("member has no group");
            return MlsBuf::null();
        }
    };
    match group.export_secret(m.provider.crypto(), label_str, ctx, out_len) {
        Ok(v) => MlsBuf::from_vec(v),
        Err(e) => {
            set_error(format!("export secret: {e:?}"));
            MlsBuf::null()
        }
    }
}
