// Mock auth hook - no backend required
import { useState, useCallback } from "react";

interface MockUser {
  name: string;
  email: string;
}

export function useAuth() {
  const [user, setUser] = useState<MockUser | null>({
    name: "SOC Analyst",
    email: "analyst@sih26145.local",
  });

  const isAuthenticated = !!user;
  const isLoading = false;

  const signIn = useCallback(async (_method: string, _form?: FormData) => {
    setUser({ name: "SOC Analyst", email: "analyst@sih26145.local" });
  }, []);

  const signOut = useCallback(async () => {
    setUser(null);
  }, []);

  return {
    isLoading,
    isAuthenticated,
    user,
    signIn,
    signOut,
  };
}
