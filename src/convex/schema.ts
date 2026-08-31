import { authTables } from "@convex-dev/auth/server";
import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

const schema = defineSchema(
  {
    ...authTables,

    users: defineTable({
      name: v.optional(v.string()),
      image: v.optional(v.string()),
      email: v.optional(v.string()),
      emailVerificationTime: v.optional(v.number()),
      isAnonymous: v.optional(v.boolean()),
      role: v.optional(
        v.union(
          v.literal("admin"),
          v.literal("user"),
          v.literal("member"),
        ),
      ),
    }).index("email", ["email"]),

    // ── Network Flows ──
    flows: defineTable({
      flowId: v.string(),
      timestamp: v.number(),
      sourceIp: v.string(),
      destinationIp: v.string(),
      protocol: v.string(),
      sourcePort: v.number(),
      destinationPort: v.number(),
      flowDuration: v.number(),
      totalPackets: v.number(),
      packetsPerSecond: v.number(),
      bytesPerSecond: v.number(),
      totalBytes: v.number(),
      classification: v.string(),
      confidence: v.number(),
      severity: v.string(),
      sourceEntropy: v.optional(v.number()),
      destinationConcentration: v.optional(v.number()),
      packetLengthMean: v.optional(v.number()),
      packetLengthStd: v.optional(v.number()),
      isSuspicious: v.boolean(),
      scenario: v.optional(v.string()),
    })
      .index("by_timestamp", ["timestamp"])
      .index("by_severity", ["severity"])
      .index("by_classification", ["classification"])
      .index("by_scenario", ["scenario"]),

    // ── Alerts ──
    alerts: defineTable({
      alertId: v.string(),
      timestamp: v.number(),
      flowId: v.string(),
      threatClass: v.string(),
      confidence: v.number(),
      severity: v.string(),
      sourceIp: v.string(),
      destinationIp: v.string(),
      protocol: v.string(),
      destinationPort: v.number(),
      detector: v.string(),
      detectionLatencyMs: v.number(),
      supportingEvidence: v.any(),
      description: v.string(),
      status: v.string(),
      scenario: v.optional(v.string()),
    })
      .index("by_timestamp", ["timestamp"])
      .index("by_severity", ["severity"])
      .index("by_threat_class", ["threatClass"])
      .index("by_status", ["status"]),

    // ── Incidents ──
    incidents: defineTable({
      incidentId: v.string(),
      timestamp: v.number(),
      title: v.string(),
      description: v.string(),
      threatClass: v.string(),
      severity: v.string(),
      confidence: v.number(),
      alertCount: v.number(),
      sourceIps: v.array(v.string()),
      destinationIps: v.array(v.string()),
      status: v.string(),
      evidence: v.any(),
      detector: v.string(),
      detectionLatencyMs: v.number(),
      scenario: v.optional(v.string()),
    })
      .index("by_timestamp", ["timestamp"])
      .index("by_severity", ["severity"])
      .index("by_status", ["status"]),

    // ── Replay State ──
    replayState: defineTable({
      sessionId: v.string(),
      status: v.string(),
      speed: v.number(),
      flowsPerSecond: v.number(),
      measuredFlowsPerSecond: v.number(),
      dataset: v.string(),
      scenario: v.string(),
      totalFlows: v.number(),
      processedFlows: v.number(),
      startedAt: v.optional(v.number()),
      mode: v.string(),
    }),

    // ── System Metrics ──
    systemMetrics: defineTable({
      timestamp: v.number(),
      totalFlows: v.number(),
      normalFlows: v.number(),
      suspiciousFlows: v.number(),
      threatsDetected: v.number(),
      criticalAlerts: v.number(),
      flowsPerSecond: v.number(),
      avgDetectionLatencyMs: v.number(),
      riskScore: v.number(),
      totalAlerts: v.number(),
      totalIncidents: v.number(),
    }).index("by_timestamp", ["timestamp"]),
  },
  {
    schemaValidation: false,
  },
);

export default schema;
