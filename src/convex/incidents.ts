import { v } from "convex/values";
import { query, mutation } from "./_generated/server";

export const list = query({
  args: {
    limit: v.optional(v.number()),
    severity: v.optional(v.string()),
    status: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    if (args.severity) {
      return await ctx.db
        .query("incidents")
        .withIndex("by_severity", (i) => i.eq("severity", args.severity!))
        .order("desc")
        .take(args.limit ?? 50);
    }
    if (args.status) {
      return await ctx.db
        .query("incidents")
        .withIndex("by_status", (i) => i.eq("status", args.status!))
        .order("desc")
        .take(args.limit ?? 50);
    }
    return await ctx.db
      .query("incidents")
      .order("desc")
      .take(args.limit ?? 50);
  },
});

export const get = query({
  args: { incidentId: v.string() },
  handler: async (ctx, args) => {
    return await ctx.db
      .query("incidents")
      .filter((q) => q.eq(q.field("incidentId"), args.incidentId))
      .first();
  },
});

export const insert = mutation({
  args: {
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
    status: v.optional(v.string()),
    evidence: v.any(),
    detector: v.string(),
    detectionLatencyMs: v.number(),
    scenario: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    return await ctx.db.insert("incidents", {
      ...args,
      status: args.status ?? "open",
    });
  },
});

export const updateStatus = mutation({
  args: { incidentId: v.string(), status: v.string() },
  handler: async (ctx, args) => {
    const incident = await ctx.db
      .query("incidents")
      .filter((q) => q.eq(q.field("incidentId"), args.incidentId))
      .first();
    if (incident) {
      await ctx.db.patch(incident._id, { status: args.status });
    }
    return incident?._id;
  },
});

export const clear = mutation({
  args: {},
  handler: async (ctx) => {
    const incidents = await ctx.db.query("incidents").collect();
    for (const incident of incidents) {
      await ctx.db.delete(incident._id);
    }
    return incidents.length;
  },
});

export const stats = query({
  args: {},
  handler: async (ctx) => {
    const all = await ctx.db.query("incidents").collect();
    const byStatus: Record<string, number> = {};
    const bySeverity: Record<string, number> = {};
    for (const inc of all) {
      byStatus[inc.status] = (byStatus[inc.status] ?? 0) + 1;
      bySeverity[inc.severity] = (bySeverity[inc.severity] ?? 0) + 1;
    }
    return { total: all.length, byStatus, bySeverity };
  },
});
