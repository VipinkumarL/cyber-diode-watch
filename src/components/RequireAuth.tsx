// RequireAuth - no-op for frontend-only mode, always allows access
import type { ReactNode } from "react";

export function RequireAuth({ children }: { children: ReactNode }) {
  return <>{children}</>;
}
