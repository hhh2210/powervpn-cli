#include "CPowerVPNXPCSession.h"

#include <Block.h>
#include <Security/Security.h>
#include <stdatomic.h>
#include <stdlib.h>

static const char kServiceName[] = "com.leadsec.charon-xpc";
static const char kPeerRequirement[] =
    "anchor apple generic and identifier \"com.leadsec.charon-xpc\" and "
    "(certificate leaf[field.1.2.840.113635.100.6.1.9] /* exists */ or "
    "certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and "
    "certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and "
    "certificate leaf[subject.OU] = M75ATYZ92T)";

struct PowerVPNXPCSession {
  atomic_uint references;
  atomic_bool activated;
  atomic_bool closed;
  atomic_bool cancellation_delivered;
  xpc_session_t session;
  PowerVPNXPCSessionIncomingHandler incoming_handler;
  PowerVPNXPCSessionCancellationHandler cancellation_handler;
};

static void session_retain(PowerVPNXPCSessionRef session) {
  atomic_fetch_add_explicit(&session->references, 1, memory_order_relaxed);
}

static void session_release(PowerVPNXPCSessionRef session) {
  if (atomic_fetch_sub_explicit(&session->references, 1, memory_order_acq_rel) !=
      1) {
    return;
  }
  Block_release(session->incoming_handler);
  Block_release(session->cancellation_handler);
  xpc_release(session->session);
  free(session);
}

static PowerVPNXPCSessionStatus validate_requirement(void) {
  CFStringRef text = CFStringCreateWithCString(
      kCFAllocatorDefault, kPeerRequirement, kCFStringEncodingUTF8);
  if (text == NULL) {
    return PowerVPNXPCSessionStatusRequirementFailed;
  }
  SecRequirementRef requirement = NULL;
  OSStatus status =
      SecRequirementCreateWithString(text, kSecCSDefaultFlags, &requirement);
  CFRelease(text);
  if (requirement != NULL) {
    CFRelease(requirement);
  }
  return status == errSecSuccess ? PowerVPNXPCSessionStatusOK
                                 : PowerVPNXPCSessionStatusRequirementFailed;
}

PowerVPNXPCSessionStatus power_vpn_xpc_session_runtime_preflight(void) {
  if (__builtin_available(macOS 14.4, *)) {
    return validate_requirement();
  }
  return PowerVPNXPCSessionStatusUnsupportedOS;
}

PowerVPNXPCSessionRef power_vpn_xpc_session_create(
    dispatch_queue_t target_queue,
    PowerVPNXPCSessionIncomingHandler incoming_handler,
    PowerVPNXPCSessionCancellationHandler cancellation_handler,
    PowerVPNXPCSessionStatus *out_status) {
  PowerVPNXPCSessionStatus status = power_vpn_xpc_session_runtime_preflight();
  if (out_status != NULL) {
    *out_status = status;
  }
  if (status != PowerVPNXPCSessionStatusOK || target_queue == NULL ||
      incoming_handler == NULL || cancellation_handler == NULL) {
    if (status == PowerVPNXPCSessionStatusOK && out_status != NULL) {
      *out_status = PowerVPNXPCSessionStatusInvalidArgument;
    }
    return NULL;
  }

  xpc_rich_error_t error = NULL;
  xpc_session_t xpc_session = xpc_session_create_mach_service(
      kServiceName, target_queue,
      XPC_SESSION_CREATE_INACTIVE | XPC_SESSION_CREATE_MACH_PRIVILEGED, &error);
  if (error != NULL) {
    xpc_release(error);
  }
  if (xpc_session == NULL) {
    if (out_status != NULL) {
      *out_status = PowerVPNXPCSessionStatusCreateFailed;
    }
    return NULL;
  }

  PowerVPNXPCSessionRef wrapper = calloc(1, sizeof(*wrapper));
  if (wrapper == NULL) {
    // Releasing an inactive session is an API misuse. Preserve fail-closed
    // behavior without activating or contacting the helper.
    if (out_status != NULL) {
      *out_status = PowerVPNXPCSessionStatusCreateFailed;
    }
    return NULL;
  }
  atomic_init(&wrapper->references, 1);
  atomic_init(&wrapper->activated, false);
  atomic_init(&wrapper->closed, false);
  atomic_init(&wrapper->cancellation_delivered, false);
  wrapper->session = xpc_session;
  wrapper->incoming_handler = Block_copy(incoming_handler);
  wrapper->cancellation_handler = Block_copy(cancellation_handler);

  xpc_session_set_incoming_message_handler(xpc_session, ^(xpc_object_t message) {
    session_retain(wrapper);
    if (!atomic_load_explicit(&wrapper->closed, memory_order_acquire)) {
      wrapper->incoming_handler(message);
    }
    session_release(wrapper);
  });
  xpc_session_set_cancel_handler(xpc_session, ^(xpc_rich_error_t error) {
    (void)error;
    atomic_store_explicit(&wrapper->closed, true, memory_order_release);
    if (!atomic_exchange_explicit(&wrapper->cancellation_delivered, true,
                                  memory_order_acq_rel)) {
      wrapper->cancellation_handler(PowerVPNXPCSessionStatusCancelled);
      session_release(wrapper);
    }
  });

  int requirement_status = -1;
  if (__builtin_available(macOS 14.4, *)) {
    requirement_status = xpc_session_set_peer_code_signing_requirement(
        xpc_session, kPeerRequirement);
  }
  if (requirement_status != 0) {
    // The constant was parsed immediately before session creation. If the XPC
    // runtime nevertheless rejects it, do not activate merely to release an
    // inactive session: leaking this one wrapper is safer than launching the
    // privileged helper on a failed preflight.
    if (out_status != NULL) {
      *out_status = PowerVPNXPCSessionStatusRequirementFailed;
    }
    return NULL;
  }
  if (out_status != NULL) {
    *out_status = PowerVPNXPCSessionStatusOK;
  }
  return wrapper;
}

bool power_vpn_xpc_session_send(
    PowerVPNXPCSessionRef session, xpc_object_t request,
    PowerVPNXPCSessionReplyHandler reply_handler) {
  if (session == NULL || request == NULL || reply_handler == NULL ||
      atomic_load_explicit(&session->closed, memory_order_acquire)) {
    return false;
  }
  if (!atomic_load_explicit(&session->activated, memory_order_acquire)) {
    // Hold one callback-lifetime reference before activation. The terminal
    // cancellation handler releases it exactly once.
    session_retain(session);
    atomic_store_explicit(&session->activated, true, memory_order_release);
    xpc_rich_error_t error = NULL;
    if (!xpc_session_activate(session->session, &error)) {
      atomic_store_explicit(&session->closed, true, memory_order_release);
      if (error != NULL) {
        xpc_release(error);
      }
      return false;
    }
    if (error != NULL) {
      xpc_release(error);
    }
  }
  if (atomic_load_explicit(&session->closed, memory_order_acquire)) {
    return false;
  }

  PowerVPNXPCSessionReplyHandler copied = Block_copy(reply_handler);
  session_retain(session);
  xpc_session_send_message_with_reply_async(
      session->session, request,
      ^(xpc_object_t reply, xpc_rich_error_t error) {
        PowerVPNXPCSessionStatus status =
            reply != NULL && error == NULL ? PowerVPNXPCSessionStatusOK
                                           : PowerVPNXPCSessionStatusReplyFailed;
        copied(status, reply);
        session_release(session);
      });
  Block_release(copied);
  return true;
}

void power_vpn_xpc_session_cancel(PowerVPNXPCSessionRef session) {
  if (session == NULL) {
    return;
  }
  bool was_closed =
      atomic_exchange_explicit(&session->closed, true, memory_order_acq_rel);
  if (!was_closed &&
      atomic_load_explicit(&session->activated, memory_order_acquire)) {
    xpc_session_cancel(session->session);
  }
}

void power_vpn_xpc_session_release(PowerVPNXPCSessionRef session) {
  if (session == NULL) {
    return;
  }
  if (!atomic_load_explicit(&session->activated, memory_order_acquire)) {
    // See create(): releasing an inactive session is an API misuse. Production
    // creates and sends synchronously on one queue, so this is defensive only.
    return;
  }
  power_vpn_xpc_session_cancel(session);
  session_release(session);
}

const char *power_vpn_xpc_session_service_name(void) { return kServiceName; }

const char *power_vpn_xpc_session_peer_requirement(void) {
  return kPeerRequirement;
}
