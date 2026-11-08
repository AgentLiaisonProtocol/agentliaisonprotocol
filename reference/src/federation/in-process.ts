// SPDX-License-Identifier: FSL-1.1-ALv2
// In-process federation: brokers in one process deliver to each other through a function call, with the envelope
// serialized and parsed as on the wire. Authentication comes from the envelope itself (signature by the sender's
// pinned home-broker key, aud), so this transport adds nothing a network attacker couldn't, just like HTTPS POST.

import type { DeliveryResult, FederationTransport, InboundContext, InboundResult } from "../core/interfaces.ts";
import type { AnyEnvelope, BrokerId } from "../core/types.ts";

export interface InboundHandler {
  acceptInbound(envelope: unknown, ctx?: InboundContext): Promise<InboundResult>;
}

export interface WireLogEntry {
  from: BrokerId;
  to: BrokerId;
  envelope_id: string;
  type: string;
  result: string;
}

export class InProcessFederation {
  private readonly handlers = new Map<BrokerId, InboundHandler>();
  /** Every delivery attempt, for transcripts and tests. */
  readonly wire: WireLogEntry[] = [];

  register(id: BrokerId, handler: InboundHandler): void {
    this.handlers.set(id, handler);
  }

  unregister(id: BrokerId): void {
    this.handlers.delete(id);
  }

  /** A transport for the broker `fromId` (used only to label the wire log). */
  transportFor(fromId: BrokerId): FederationTransport {
    return {
      deliver: async (target, envelope: AnyEnvelope): Promise<DeliveryResult> => {
        const handler = this.handlers.get(target.broker);
        if (!handler) {
          this.wire.push({ from: fromId, to: target.broker, envelope_id: envelope.id, type: envelope.type, result: "unreachable" });
          return { kind: "unreachable", message: `no broker answers at ${target.inbox}` };
        }
        const result = await handler.acceptInbound(JSON.parse(JSON.stringify(envelope)) as unknown, { remote: fromId });
        this.wire.push({
          from: fromId,
          to: target.broker,
          envelope_id: envelope.id,
          type: envelope.type,
          result: result.kind === "receipt" ? `receipt:${result.receipt.status}${result.receipt.code ? `:${result.receipt.code}` : ""}` : `refused:${result.code}`,
        });
        return JSON.parse(JSON.stringify(result)) as DeliveryResult;
      },
    };
  }
}
