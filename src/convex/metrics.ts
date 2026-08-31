import { v } from "convex/values";
import { query, mutation } from "./_generated/server";

export const getLatest = query({
  args: {},
  handler: async (ctx) => {
    return await ctx.db.query("systemMetrics").order("desc").first();
  },
});

export const record = mutation({
  args: {
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
  },
  handler: async (ctx, args) => {
    return await ctx.db.insert("systemMetrics", args);
  },
});

export const getTimeseries = query({
  args: { windowMs: v.optional(v.number()) },
  handler: async (ctx, args) => {
    const window = args.windowMs ?? 300000;
    const now = Date.now();
    return await ctx.db
      .query("systemMetrics")
      .withIndex("by_timestamp", (i) => i.gte("timestamp", now - window))
      .order("desc")
      .take(200);
  },
});

export const clear = mutation({
  args: {},
  handler: async (ctx) => {
    const metrics = await ctx.db.query("systemMetrics").collect();
    for (const m of metrics) {
      await ctx.db.delete(m._id);
    }
    return metrics.length;
  },
});
