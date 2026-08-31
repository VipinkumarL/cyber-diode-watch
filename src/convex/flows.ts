import { v } from "convex/values";
import { query, mutation } from "./_generated/server";

export const list = query({
  args: {
    limit: v.optional(v.number()),
    severity: v.optional(v.string()),
    classification: v.optional(v.string()),
    scenario: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    let q = ctx.db.query("flows").order("desc");
    if (args.severity) {
      return await ctx.db
        .query("flows")
        .withIndex("by_severity", (i) => i.eq("severity", args.severity!))
        .order("desc")
        .take(args.limit ?? 100);
    }
    if (args.classification) {
      return await ctx.db
        .query("flows")
        .withIndex("by_classification", (i) => i.eq("classification", args.classification!))
        .order("desc")
        .take(args.limit ?? 100);
    }
    if (args.scenario) {
      return await ctx.db
        .query("flows")
        .withIndex("by_scenario", (i) => i.eq("scenario", args.scenario!))
        .order("desc")
        .take(args.limit ?? 100);
    }
    return await q.take(args.limit ?? 100);
  },
});

export const getRecent = query({
  args: { limit: v.optional(v.number()) },
  handler: async (ctx, args) => {
    return await ctx.db
      .query("flows")
      .order("desc")
      .take(args.limit ?? 50);
  },
});

export const stats = query({
  args: {},
  handler: async (ctx) => {
    const allFlows = await ctx.db.query("flows").collect();
    const total = allFlows.length;
    const normal = allFlows.filter((f) => f.classification === "Normal").length;
    const suspicious = allFlows.filter((f) => f.isSuspicious).length;
    const threats = allFlows.filter(
      (f) => f.severity === "CRITICAL" || f.severity === "HIGH",
    ).length;
    const critical = allFlows.filter((f) => f.severity === "CRITICAL").length;

    const now = Date.now();
    const recentFlows = allFlows.filter((f) => f.timestamp > now - 5000);
    const flowsPerSecond = recentFlows.length / 5;

    const suspiciousWithLatency = allFlows.filter((f) => f.isSuspicious);
    const avgLatency =
      suspiciousWithLatency.length > 0
        ? suspiciousWithLatency.reduce(
            (sum, f) => sum + (f.flowDuration || 0),
            0,
          ) / suspiciousWithLatency.length
        : 0;

    const riskScore =
      total > 0
        ? Math.min(
            100,
            Math.round(
              ((critical * 30 + threats * 15 + suspicious * 5) /
                Math.max(total, 1)) *
                10,
            ),
          )
        : 0;

    return {
      totalFlows: total,
      normalFlows: normal,
      suspiciousFlows: suspicious,
      threatsDetected: threats,
      criticalAlerts: critical,
      flowsPerSecond: Math.round(flowsPerSecond * 10) / 10,
      avgDetectionLatencyMs: Math.round(avgLatency),
      riskScore: Math.min(100, riskScore),
    };
  },
});

export const insertFlow = mutation({
  args: {
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
  },
  handler: async (ctx, args) => {
    return await ctx.db.insert("flows", args);
  },
});

export const insertMany = mutation({
  args: { flows: v.array(v.any()) },
  handler: async (ctx, args) => {
    const ids = [];
    for (const flow of args.flows) {
      const id = await ctx.db.insert("flows", flow);
      ids.push(id);
    }
    return ids;
  },
});

export const clear = mutation({
  args: {},
  handler: async (ctx) => {
    const flows = await ctx.db.query("flows").collect();
    for (const flow of flows) {
      await ctx.db.delete(flow._id);
    }
    return flows.length;
  },
});

export const getFlowTimeseries = query({
  args: { windowMs: v.optional(v.number()) },
  handler: async (ctx, args) => {
    const window = args.windowMs ?? 60000;
    const now = Date.now();
    const flows = await ctx.db
      .query("flows")
      .withIndex("by_timestamp", (i) => i.gte("timestamp", now - window))
      .collect();

    const buckets: Record<
      string,
      { total: number; threats: number; normal: number }
    > = {};
    for (const flow of flows) {
      const key = new Date(flow.timestamp).toISOString().slice(14, 19);
      if (!buckets[key]) buckets[key] = { total: 0, threats: 0, normal: 0 };
      buckets[key].total++;
      if (flow.classification !== "Normal") buckets[key].threats++;
      else buckets[key].normal++;
    }

    return Object.entries(buckets).map(([time, data]) => ({
      time,
      ...data,
    }));
  },
});
