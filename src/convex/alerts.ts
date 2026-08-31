import { v } from "convex/values";
import { query, mutation } from "./_generated/server";

export const list = query({
  args: {
    limit: v.optional(v.number()),
    severity: v.optional(v.string()),
    threatClass: v.optional(v.string()),
    status: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    if (args.severity) {
      return await ctx.db
        .query("alerts")
        .withIndex("by_severity", (i) => i.eq("severity", args.severity!))
        .order("desc")
        .take(args.limit ?? 100);
    }
    if (args.threatClass) {
      return await ctx.db
        .query("alerts")
        .withIndex("by_threat_class", (i) =>
          i.eq("threatClass", args.threatClass!),
        )
        .order("desc")
        .take(args.limit ?? 100);
    }
    if (args.status) {
      return await ctx.db
        .query("alerts")
        .withIndex("by_status", (i) => i.eq("status", args.status!))
        .order("desc")
        .take(args.limit ?? 100);
    }
    return await ctx.db
      .query("alerts")
      .order("desc")
      .take(args.limit ?? 100);
  },
});

export const get = query({
  args: { alertId: v.string() },
  handler: async (ctx, args) => {
    return await ctx.db
      .query("alerts")
      .filter((q) => q.eq(q.field("alertId"), args.alertId))
      .first();
  },
});

export const insert = mutation({
  args: {
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
    status: v.optional(v.string()),
    scenario: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    return await ctx.db.insert("alerts", {
      ...args,
      status: args.status ?? "new",
    });
  },
});

export const updateStatus = mutation({
  args: { alertId: v.string(), status: v.string() },
  handler: async (ctx, args) => {
    const alert = await ctx.db
      .query("alerts")
      .filter((q) => q.eq(q.field("alertId"), args.alertId))
      .first();
    if (alert) {
      await ctx.db.patch(alert._id, { status: args.status });
    }
    return alert?._id;
  },
});

export const clear = mutation({
  args: {},
  handler: async (ctx) => {
    const alerts = await ctx.db.query("alerts").collect();
    for (const alert of alerts) {
      await ctx.db.delete(alert._id);
    }
    return alerts.length;
  },
});

export const stats = query({
  args: {},
  handler: async (ctx) => {
    const all = await ctx.db.query("alerts").collect();
    const byThreatClass: Record<string, number> = {};
    const bySeverity: Record<string, number> = {};
    let totalConfidence = 0;
    let totalLatency = 0;

    for (const alert of all) {
      byThreatClass[alert.threatClass] =
        (byThreatClass[alert.threatClass] ?? 0) + 1;
      bySeverity[alert.severity] = (bySeverity[alert.severity] ?? 0) + 1;
      totalConfidence += alert.confidence;
      totalLatency += alert.detectionLatencyMs;
    }

    return {
      total: all.length,
      byThreatClass,
      bySeverity,
      avgConfidence: all.length > 0 ? totalConfidence / all.length : 0,
      avgLatency: all.length > 0 ? totalLatency / all.length : 0,
    };
  },
});

export const recentTimeline = query({
  args: { windowMs: v.optional(v.number()) },
  handler: async (ctx, args) => {
    const window = args.windowMs ?? 300000;
    const now = Date.now();
    const alerts = await ctx.db
      .query("alerts")
      .withIndex("by_timestamp", (i) => i.gte("timestamp", now - window))
      .collect();

    const buckets: Record<string, Record<string, number>> = {};
    for (const alert of alerts) {
      const bucketKey = Math.floor(alert.timestamp / 10000).toString();
      if (!buckets[bucketKey]) buckets[bucketKey] = {};
      buckets[bucketKey][alert.threatClass] =
        (buckets[bucketKey][alert.threatClass] ?? 0) + 1;
    }

    return Object.entries(buckets).map(([time, classes]) => ({
      time: Number(time) * 10000,
      ...classes,
    }));
  },
});
