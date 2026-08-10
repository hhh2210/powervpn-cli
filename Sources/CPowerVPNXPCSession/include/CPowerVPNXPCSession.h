#ifndef C_POWER_VPN_XPC_SESSION_H
#define C_POWER_VPN_XPC_SESSION_H

#include <dispatch/dispatch.h>
#include <stdbool.h>
#include <stdint.h>
#include <xpc/xpc.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct PowerVPNXPCSession *PowerVPNXPCSessionRef;

typedef enum PowerVPNXPCSessionStatus {
  PowerVPNXPCSessionStatusOK = 0,
  PowerVPNXPCSessionStatusUnsupportedOS = 1,
  PowerVPNXPCSessionStatusInvalidArgument = 2,
  PowerVPNXPCSessionStatusCreateFailed = 3,
  PowerVPNXPCSessionStatusRequirementFailed = 4,
  PowerVPNXPCSessionStatusActivationFailed = 5,
  PowerVPNXPCSessionStatusCancelled = 6,
  PowerVPNXPCSessionStatusReplyFailed = 7,
} PowerVPNXPCSessionStatus;

/// The raw message is borrowed and valid only for the callback duration.
typedef void (^PowerVPNXPCSessionIncomingHandler)(xpc_object_t message);

/// Cancellation is terminal. The rich XPC error is deliberately not exposed.
typedef void (^PowerVPNXPCSessionCancellationHandler)(
    PowerVPNXPCSessionStatus status);

/// A successful callback owns no reference to the borrowed raw reply.
typedef void (^PowerVPNXPCSessionReplyHandler)(
    PowerVPNXPCSessionStatus status, xpc_object_t reply);

/// Performs value-free runtime and peer-requirement validation without
/// creating a session or contacting the helper.
PowerVPNXPCSessionStatus power_vpn_xpc_session_runtime_preflight(void);

/// Creates one inactive, non-reconnecting session to the fixed privileged helper.
///
/// The caller must invoke this on `target_queue`, and must serialize every later
/// call on that same queue. macOS versions before 14.4 fail before session
/// creation because they cannot install the required peer-signing constraint.
PowerVPNXPCSessionRef power_vpn_xpc_session_create(
    dispatch_queue_t target_queue,
    PowerVPNXPCSessionIncomingHandler incoming_handler,
    PowerVPNXPCSessionCancellationHandler cancellation_handler,
    PowerVPNXPCSessionStatus *out_status);

/// Returns true only when the request was handed to libxpc's async send API.
/// It does not prove delivery, acknowledgement, or helper mutation.
bool power_vpn_xpc_session_send(
    PowerVPNXPCSessionRef session, xpc_object_t request,
    PowerVPNXPCSessionReplyHandler reply_handler);

/// Idempotently prevents later wrapper sends and cancels the underlying session.
void power_vpn_xpc_session_cancel(PowerVPNXPCSessionRef session);

/// Releases the wrapper. The caller must cancel it first.
void power_vpn_xpc_session_release(PowerVPNXPCSessionRef session);

/// Fixed constants exposed for compile-time/offline contract tests only.
const char *power_vpn_xpc_session_service_name(void);
const char *power_vpn_xpc_session_peer_requirement(void);

#ifdef __cplusplus
}
#endif

#endif
