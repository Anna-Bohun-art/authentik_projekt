export interface DirectoryUser {
  username: string;
  displayName: string;
  email: string;
  isActive: boolean;
}

/**
 * The small business capability this SOAP service exposes. Backed by SQL in
 * production (directory/postgres.ts) and by an in-memory fake in tests
 * (directory/inMemory.ts) — the handlers depend only on this interface.
 */
export interface UserDirectory {
  getUser(username: string): Promise<DirectoryUser | undefined>;
  listGroups(username: string): Promise<string[]>;
  /** Returns false when no such user exists. */
  deactivateUser(username: string): Promise<boolean>;
}
