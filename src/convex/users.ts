import { query } from "./_generated/server";

export const currentUser = query({
  args: {},
  handler: async (ctx) => {
    const userId = (await ctx.auth.getUserIdentity())?.subject;
    if (!userId) return null;
    const user = await ctx.db.get(userId as any);
    if (!user || !("email" in user)) return null;
    return user as {
      _id: any;
      _creationTime: number;
      name?: string;
      email?: string;
      image?: string;
    };
  },
});
