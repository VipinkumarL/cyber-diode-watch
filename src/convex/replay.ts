import { v } from "convex/values";
import { query, mutation } from "./_generated/server";

export const getState = query({
  args: {},
  handler: async (ctx) => {
    const state = await ctx.db.query("replayState").first();
    return state ?? null;
  },
});

export const setState = mutation({
  args: {
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
  },
  handler: async (ctx, args) => {
    const existing = await ctx.db.query("replayState").first();
    if (existing) {
      await ctx.db.patch(existing._id, args);
      return existing._id;
    }
    return await ctx.db.insert("replayState", args);
  },
});

export const clearState = mutation({
  args: {},
  handler: async (ctx) => {
    const states = await ctx.db.query("replayState").collect();
    for (const s of states) {
      await ctx.db.delete(s._id);
    }
    return states.length;
  },
});
