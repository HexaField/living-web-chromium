// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/flows/flow_definition.h"

#include <cstddef>
#include <cstdlib>

#include "content/browser/did/jcs.h"

namespace living_web {
namespace flows {

namespace {

constexpr size_t kNpos = std::string::npos;

size_t SkipWs(const std::string& s, size_t i) {
  while (i < s.size() &&
         (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r')) {
    ++i;
  }
  return i;
}

// Index just past the JSON string starting at s[i] (s[i] == '"'); kNpos if the
// string is unterminated.
size_t ScanString(const std::string& s, size_t i) {
  for (size_t j = i + 1; j < s.size(); ++j) {
    if (s[j] == '\\') {
      ++j;  // skip the escaped character
      continue;
    }
    if (s[j] == '"')
      return j + 1;
  }
  return kNpos;
}

// Index just past the JSON value beginning at the first non-whitespace character
// at or after |i|; kNpos on malformation. Handles strings, objects, arrays, and
// bare primitives (number/true/false/null).
size_t ScanValue(const std::string& s, size_t i) {
  i = SkipWs(s, i);
  if (i >= s.size())
    return kNpos;
  char c = s[i];
  if (c == '"')
    return ScanString(s, i);
  if (c == '{' || c == '[') {
    char open = c;
    char close = (c == '{') ? '}' : ']';
    int depth = 0;
    for (size_t j = i; j < s.size(); ++j) {
      char d = s[j];
      if (d == '"') {
        size_t e = ScanString(s, j);
        if (e == kNpos)
          return kNpos;
        j = e - 1;  // loop's ++j lands just past the string
        continue;
      }
      if (d == open) {
        ++depth;
      } else if (d == close) {
        --depth;
        if (depth == 0)
          return j + 1;
      }
    }
    return kNpos;
  }
  size_t j = i;
  while (j < s.size()) {
    char d = s[j];
    if (d == ',' || d == '}' || d == ']' || d == ' ' || d == '\t' ||
        d == '\n' || d == '\r') {
      break;
    }
    ++j;
  }
  return (j == i) ? kNpos : j;
}

std::string JsonUnescape(const std::string& s) {
  std::string out;
  out.reserve(s.size());
  for (size_t i = 0; i < s.size(); ++i) {
    if (s[i] != '\\' || i + 1 >= s.size()) {
      out += s[i];
      continue;
    }
    char e = s[++i];
    switch (e) {
      case '"': out += '"'; break;
      case '\\': out += '\\'; break;
      case '/': out += '/'; break;
      case 'n': out += '\n'; break;
      case 't': out += '\t'; break;
      case 'r': out += '\r'; break;
      case 'b': out += '\b'; break;
      case 'f': out += '\f'; break;
      case 'u': {
        if (i + 4 < s.size()) {
          auto hex = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return 10 + c - 'a';
            if (c >= 'A' && c <= 'F') return 10 + c - 'A';
            return -1;
          };
          int h0 = hex(s[i + 1]), h1 = hex(s[i + 2]), h2 = hex(s[i + 3]),
              h3 = hex(s[i + 4]);
          if (h0 >= 0 && h1 >= 0 && h2 >= 0 && h3 >= 0) {
            unsigned cp = (h0 << 12) | (h1 << 8) | (h2 << 4) | h3;
            if (cp < 0x80) {
              out += static_cast<char>(cp);
            } else if (cp < 0x800) {
              out += static_cast<char>(0xC0 | (cp >> 6));
              out += static_cast<char>(0x80 | (cp & 0x3F));
            } else {
              out += static_cast<char>(0xE0 | (cp >> 12));
              out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
              out += static_cast<char>(0x80 | (cp & 0x3F));
            }
            i += 4;
            break;
          }
        }
        out += 'u';
        break;
      }
      default:
        out += e;
    }
  }
  return out;
}

// The verbatim raw substring of a top-level object field's value (string, array,
// object, or primitive). Returns false if |obj| is not a JSON object or the field
// is absent.
bool RawField(const std::string& obj, const std::string& field,
              std::string* out) {
  size_t i = SkipWs(obj, 0);
  if (i >= obj.size() || obj[i] != '{')
    return false;
  ++i;
  while (true) {
    i = SkipWs(obj, i);
    if (i >= obj.size() || obj[i] == '}')
      return false;
    if (obj[i] != '"')
      return false;
    size_t key_end = ScanString(obj, i);
    if (key_end == kNpos)
      return false;
    std::string key = JsonUnescape(obj.substr(i + 1, key_end - i - 2));
    i = SkipWs(obj, key_end);
    if (i >= obj.size() || obj[i] != ':')
      return false;
    ++i;
    size_t val_start = SkipWs(obj, i);
    size_t val_end = ScanValue(obj, val_start);
    if (val_end == kNpos)
      return false;
    if (key == field) {
      *out = obj.substr(val_start, val_end - val_start);
      return true;
    }
    i = SkipWs(obj, val_end);
    if (i >= obj.size())
      return false;
    if (obj[i] == ',') {
      ++i;
      continue;
    }
    return false;  // '}' or anything else: field not found
  }
}

// A top-level string field, unescaped. False if absent or not a JSON string.
bool StringField(const std::string& obj, const std::string& field,
                 std::string* out) {
  std::string raw;
  if (!RawField(obj, field, &raw))
    return false;
  if (raw.empty() || raw[0] != '"')
    return false;
  size_t e = ScanString(raw, 0);
  if (e == kNpos)
    return false;
  *out = JsonUnescape(raw.substr(1, e - 2));
  return true;
}

// True iff the field is present. |*is_string| reports whether it is a JSON
// string. Lets a caller distinguish "absent" (OPTIONAL) from "present but wrong
// JSON type" (malformed).
bool FieldPresent(const std::string& obj, const std::string& field,
                  bool* is_string) {
  std::string raw;
  if (!RawField(obj, field, &raw)) {
    *is_string = false;
    return false;
  }
  *is_string = !raw.empty() && raw[0] == '"';
  return true;
}

// A top-level boolean field. |*found| is set iff the field is present; the return
// value is true only when the present value is a JSON boolean (written to |*out|).
bool BoolField(const std::string& obj, const std::string& field, bool* out,
               bool* found) {
  *found = false;
  std::string raw;
  if (!RawField(obj, field, &raw))
    return false;
  *found = true;
  if (raw == "true") {
    *out = true;
    return true;
  }
  if (raw == "false") {
    *out = false;
    return true;
  }
  return false;  // present but not a boolean
}

// Split the raw `[ ... ]` substring of a JSON array into its top-level element
// substrings (verbatim, each trimmed of surrounding whitespace). Returns false if
// |raw| is not a JSON array.
bool RawArrayElements(const std::string& raw, std::vector<std::string>* out) {
  out->clear();
  size_t i = SkipWs(raw, 0);
  if (i >= raw.size() || raw[i] != '[')
    return false;
  ++i;
  i = SkipWs(raw, i);
  if (i < raw.size() && raw[i] == ']')
    return true;  // empty array
  while (i < raw.size()) {
    size_t vs = SkipWs(raw, i);
    size_t ve = ScanValue(raw, vs);
    if (ve == kNpos)
      return false;
    out->push_back(raw.substr(vs, ve - vs));
    i = SkipWs(raw, ve);
    if (i >= raw.size())
      return false;
    if (raw[i] == ',') {
      ++i;
      continue;
    }
    if (raw[i] == ']')
      return true;
    return false;
  }
  return false;
}

// Parse one §4.2 state object. Returns false + |*error| on malformation.
bool ParseState(const std::string& elem, FlowState* out, std::string* error) {
  auto fail = [&](const std::string& e) {
    if (error)
      *error = e;
    return false;
  };
  FlowState st;

  if (!StringField(elem, "name", &st.name) || st.name.empty())
    return fail("flow state: missing or empty required field \"name\"");
  if (!IsValidFlowStateName(st.name))
    return fail("flow state: \"name\" must match [a-zA-Z_][a-zA-Z0-9_]*: " +
                st.name);

  bool is_string = false;
  if (FieldPresent(elem, "displayName", &is_string)) {
    if (!is_string)
      return fail("flow state: \"displayName\" must be a string");
    std::string dn;
    StringField(elem, "displayName", &dn);
    st.display_name = dn;
  }

  bool b = false, found = false;
  if (BoolField(elem, "isTerminal", &b, &found))
    st.is_terminal = b;
  else if (found)
    return fail("flow state: \"isTerminal\" must be a boolean");

  *out = st;
  return true;
}

// Parse one §4.4 action. Accepts the canonical subject/object keys and the §17
// source/target aliases.
bool ParseAction(const std::string& elem, FlowAction* out, std::string* error) {
  auto fail = [&](const std::string& e) {
    if (error)
      *error = e;
    return false;
  };
  FlowAction a;

  if (!StringField(elem, "type", &a.action_uri) || a.action_uri.empty())
    return fail("flow action: missing required field \"type\"");
  if (a.action_uri == kFlowActionAddLink) {
    a.kind = FlowActionKind::kAddLink;
  } else if (a.action_uri == kFlowActionSetSingleTarget) {
    a.kind = FlowActionKind::kSetSingleTarget;
  } else if (a.action_uri == kFlowActionRemoveLink) {
    a.kind = FlowActionKind::kRemoveLink;
  } else {
    return fail("flow action: unknown type URI \"" + a.action_uri +
                "\" (expected a flow://actions/* form)");
  }

  if (!StringField(elem, "subject", &a.subject) &&
      !StringField(elem, "source", &a.subject)) {
    return fail("flow action: missing required field \"subject\"");
  }
  if (a.subject.empty())
    return fail("flow action: \"subject\" must be non-empty");

  if (!StringField(elem, "predicate", &a.predicate) || a.predicate.empty())
    return fail("flow action: missing required field \"predicate\"");

  if (!StringField(elem, "object", &a.object) &&
      !StringField(elem, "target", &a.object)) {
    return fail("flow action: missing required field \"object\"");
  }
  if (a.object.empty())
    return fail("flow action: \"object\" must be non-empty");

  *out = a;
  return true;
}

// Parse the §8.1 `temporal` object. Returns false + |*error| when a declared
// delay is not a valid ISO 8601 duration or onDeadline is not a §8.1 token.
bool ParseTemporal(const std::string& raw, FlowTemporal* out,
                   std::string* error) {
  auto fail = [&](const std::string& e) {
    if (error)
      *error = e;
    return false;
  };
  FlowTemporal t;

  bool is_string = false;
  if (FieldPresent(raw, "minDelay", &is_string)) {
    if (!is_string)
      return fail("flow temporal: \"minDelay\" must be a string");
    std::string d;
    StringField(raw, "minDelay", &d);
    int64_t secs = 0;
    if (!ParseIso8601Duration(d, &secs))
      return fail("flow temporal: \"minDelay\" is not an ISO 8601 duration: " + d);
    t.min_delay = d;
  }
  if (FieldPresent(raw, "maxDelay", &is_string)) {
    if (!is_string)
      return fail("flow temporal: \"maxDelay\" must be a string");
    std::string d;
    StringField(raw, "maxDelay", &d);
    int64_t secs = 0;
    if (!ParseIso8601Duration(d, &secs))
      return fail("flow temporal: \"maxDelay\" is not an ISO 8601 duration: " + d);
    t.max_delay = d;
  }
  if (FieldPresent(raw, "onDeadline", &is_string)) {
    if (!is_string)
      return fail("flow temporal: \"onDeadline\" must be a string");
    std::string od;
    StringField(raw, "onDeadline", &od);
    auto parsed = ParseOnDeadline(od);
    if (!parsed)
      return fail("flow temporal: unknown \"onDeadline\" value: " + od);
    t.on_deadline = *parsed;
  }

  *out = t;
  return true;
}

// Parse one §4.3 transition object (endpoint resolution against defined states is
// done by the caller once all states are known).
bool ParseTransition(const std::string& elem, FlowTransition* out,
                     std::string* error) {
  auto fail = [&](const std::string& e) {
    if (error)
      *error = e;
    return false;
  };
  FlowTransition tr;

  if (!StringField(elem, "name", &tr.name) || tr.name.empty())
    return fail("flow transition: missing or empty required field \"name\"");
  if (!StringField(elem, "fromState", &tr.from_state) || tr.from_state.empty())
    return fail("flow transition \"" + tr.name +
                "\": missing required field \"fromState\"");
  if (!StringField(elem, "toState", &tr.to_state) || tr.to_state.empty())
    return fail("flow transition \"" + tr.name +
                "\": missing required field \"toState\"");

  bool is_string = false;
  if (FieldPresent(elem, "displayName", &is_string)) {
    if (!is_string)
      return fail("flow transition: \"displayName\" must be a string");
    std::string dn;
    StringField(elem, "displayName", &dn);
    tr.display_name = dn;
  }
  if (FieldPresent(elem, "guard", &is_string)) {
    if (!is_string)
      return fail("flow transition: \"guard\" must be a string");
    std::string g;
    StringField(elem, "guard", &g);
    if (!g.empty())
      tr.guard = g;
  }
  if (FieldPresent(elem, "guardDescription", &is_string)) {
    if (!is_string)
      return fail("flow transition: \"guardDescription\" must be a string");
    std::string gd;
    StringField(elem, "guardDescription", &gd);
    tr.guard_description = gd;
  }
  if (FieldPresent(elem, "role", &is_string)) {
    if (!is_string)
      return fail("flow transition: \"role\" must be a string");
    std::string r;
    StringField(elem, "role", &r);
    if (!r.empty())
      tr.role = r;
  }
  if (FieldPresent(elem, "triggersSubFlow", &is_string)) {
    if (!is_string)
      return fail("flow transition: \"triggersSubFlow\" must be a string");
    std::string sf;
    StringField(elem, "triggersSubFlow", &sf);
    if (!sf.empty())
      tr.triggers_sub_flow = sf;
  }

  std::string temporal_raw;
  if (RawField(elem, "temporal", &temporal_raw)) {
    if (temporal_raw.empty() || temporal_raw[0] != '{')
      return fail("flow transition: \"temporal\" must be an object");
    if (!ParseTemporal(temporal_raw, &tr.temporal, error))
      return false;
  }

  std::string actions_raw;
  if (RawField(elem, "actions", &actions_raw)) {
    std::vector<std::string> action_elems;
    if (!RawArrayElements(actions_raw, &action_elems))
      return fail("flow transition: \"actions\" must be an array");
    for (const std::string& ae : action_elems) {
      FlowAction a;
      if (!ParseAction(ae, &a, error))
        return false;
      tr.actions.push_back(a);
    }
  }

  *out = tr;
  return true;
}

}  // namespace

bool IsValidFlowStateName(const std::string& name) {
  if (name.empty())
    return false;
  char c0 = name[0];
  bool head = (c0 >= 'a' && c0 <= 'z') || (c0 >= 'A' && c0 <= 'Z') || c0 == '_';
  if (!head)
    return false;
  for (size_t i = 1; i < name.size(); ++i) {
    char c = name[i];
    bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_';
    if (!ok)
      return false;
  }
  return true;
}

std::optional<OnDeadline> ParseOnDeadline(const std::string& token) {
  if (token == "auto-transition")
    return OnDeadline::kAutoTransition;
  if (token == "error-state")
    return OnDeadline::kErrorState;
  if (token == "notify")
    return OnDeadline::kNotify;
  return std::nullopt;
}

std::string OnDeadlineToken(OnDeadline on_deadline) {
  switch (on_deadline) {
    case OnDeadline::kAutoTransition: return "auto-transition";
    case OnDeadline::kErrorState: return "error-state";
    case OnDeadline::kNotify: return "notify";
    case OnDeadline::kNone: return std::string();
  }
  return std::string();
}

const FlowState* FindState(const FlowDefinition& flow, const std::string& name) {
  for (const FlowState& s : flow.states) {
    if (s.name == name)
      return &s;
  }
  return nullptr;
}

const FlowTransition* FindTransition(const FlowDefinition& flow,
                                     const std::string& name) {
  for (const FlowTransition& t : flow.transitions) {
    if (t.name == name)
      return &t;
  }
  return nullptr;
}

bool ParseIso8601Duration(const std::string& duration, int64_t* out_seconds) {
  if (duration.size() < 2 || duration[0] != 'P')
    return false;
  int64_t total = 0;
  bool in_time = false;
  bool any = false;
  size_t i = 1;
  while (i < duration.size()) {
    if (duration[i] == 'T') {
      if (in_time)
        return false;  // a second 'T' is malformed
      in_time = true;
      ++i;
      continue;
    }
    size_t start = i;
    while (i < duration.size() && duration[i] >= '0' && duration[i] <= '9')
      ++i;
    if (i == start || i >= duration.size())
      return false;  // no digits, or digits with no trailing unit
    int64_t n = 0;
    for (size_t k = start; k < i; ++k) {
      n = n * 10 + (duration[k] - '0');
      if (n > 1000LL * 1000 * 1000 * 1000)  // clamp absurd values, avoid overflow
        return false;
    }
    char unit = duration[i];
    ++i;
    int64_t mult = 0;
    if (!in_time) {
      switch (unit) {
        case 'Y': mult = 365LL * 86400; break;
        case 'M': mult = 30LL * 86400; break;
        case 'W': mult = 7LL * 86400; break;
        case 'D': mult = 86400; break;
        default: return false;  // H/M/S require the time section
      }
    } else {
      switch (unit) {
        case 'H': mult = 3600; break;
        case 'M': mult = 60; break;
        case 'S': mult = 1; break;
        default: return false;  // Y/W/D are date-section units
      }
    }
    total += n * mult;
    any = true;
  }
  if (!any)
    return false;  // "P" or "PT" alone
  *out_seconds = total;
  return true;
}

std::string FlowNodeIri(const std::string& flow_name) {
  return "flow://" + flow_name;
}

std::string FlowStateNodeIri(const std::string& flow_name,
                             const std::string& state_name) {
  return "flow://" + flow_name + "/state/" + state_name;
}

std::string FlowTransitionNodeIri(const std::string& flow_name,
                                  const std::string& transition_name) {
  return "flow://" + flow_name + "/transition/" + transition_name;
}

std::optional<std::string> CanonicalizeFlowJson(const std::string& json) {
  return jcs::Canonicalize(json);
}

bool ParseFlowDefinition(const std::string& json, FlowDefinition* out,
                         std::string* error) {
  FlowDefinition f;
  auto fail = [&](const std::string& e) {
    if (error)
      *error = e;
    f.valid = false;
    *out = f;
    return false;
  };

  if (!StringField(json, "name", &f.name) || f.name.empty())
    return fail("flow: missing or empty required field \"name\"");
  if (!StringField(json, "namespace", &f.ns) || f.ns.empty())
    return fail("flow: missing or empty required field \"namespace\"");
  if (!StringField(json, "appliesTo", &f.applies_to) || f.applies_to.empty())
    return fail("flow: missing or empty required field \"appliesTo\"");
  if (!StringField(json, "initialState", &f.initial_state) ||
      f.initial_state.empty()) {
    return fail("flow: missing or empty required field \"initialState\"");
  }

  std::string states_raw;
  if (!RawField(json, "states", &states_raw))
    return fail("flow: missing required field \"states\"");
  std::vector<std::string> state_elems;
  if (!RawArrayElements(states_raw, &state_elems))
    return fail("flow: \"states\" must be an array");
  for (const std::string& se : state_elems) {
    FlowState st;
    if (!ParseState(se, &st, error))
      return fail(error ? *error : "flow: malformed state");
    if (FindState(f, st.name))
      return fail("flow: duplicate state name \"" + st.name + "\"");
    f.states.push_back(st);
  }
  if (f.states.empty())
    return fail("flow: \"states\" must declare at least one state");

  // §4.1 — initialState MUST name a defined state.
  if (!FindState(f, f.initial_state)) {
    return fail("flow: \"initialState\" names an undefined state \"" +
                f.initial_state + "\"");
  }

  std::string trans_raw;
  if (!RawField(json, "transitions", &trans_raw))
    return fail("flow: missing required field \"transitions\"");
  std::vector<std::string> trans_elems;
  if (!RawArrayElements(trans_raw, &trans_elems))
    return fail("flow: \"transitions\" must be an array");
  for (const std::string& te : trans_elems) {
    FlowTransition tr;
    if (!ParseTransition(te, &tr, error))
      return fail(error ? *error : "flow: malformed transition");
    if (FindTransition(f, tr.name))
      return fail("flow: duplicate transition name \"" + tr.name + "\"");
    // §4.3 — endpoints MUST name defined states.
    const FlowState* from = FindState(f, tr.from_state);
    if (!from) {
      return fail("flow transition \"" + tr.name +
                  "\": fromState names an undefined state \"" + tr.from_state +
                  "\"");
    }
    if (!FindState(f, tr.to_state)) {
      return fail("flow transition \"" + tr.name +
                  "\": toState names an undefined state \"" + tr.to_state +
                  "\"");
    }
    // §4.2 / §6.4 — no transition may leave a terminal state.
    if (from->is_terminal) {
      return fail("flow transition \"" + tr.name +
                  "\": leaves terminal state \"" + tr.from_state + "\"");
    }
    f.transitions.push_back(tr);
  }

  f.valid = true;
  if (error)
    error->clear();
  *out = f;
  return true;
}

}  // namespace flows
}  // namespace living_web
