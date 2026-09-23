# Experimental Suricata 8.0 Plugin Utilities

Minimal Rust bindings for the Suricata 8.0.x experimental plugin ABI.

This crate intentionally exposes only the structs, constants, callbacks, and
functions needed by the out-of-tree Rust plugins using it.

## Helpers

On top of the raw bindings, the crate provides safer helpers modeled on the
`suricata-ffi` crate for Suricata 9, so plugin code can look similar on both:

- Logging macros: `SCLogError!`, `SCLogWarning!`, `SCLogNotice!`,
  `SCLogInfo!`, `SCLogPerf!`, `SCLogConfig!`, `SCLogDebug!` and
  `SCFatalError!`. They record the caller's file, line and function, and use
  the plugin crate name as the log module.
- Typed storage: `FlowStorage<T>` and `ThreadStorage<T>` store a `Box<T>` per
  flow or thread and drop it when Suricata frees the storage.
- Keywords: `register_packet_keyword()` with a `PacketKeyword` description.
- Keyword setup: `signature_is_negated()`, `signature_sigmatches()`,
  `SigMatch::context_as()`, `signature_append_sigmatch()`, and
  `sigmatch_ctx_free::<T>` as the keyword free callback.
- Registration: `plugin!(name: ..., author: ..., license: ..., init: ...)`
  defines the `SCPlugin` and exports `SCPluginRegister()`.
