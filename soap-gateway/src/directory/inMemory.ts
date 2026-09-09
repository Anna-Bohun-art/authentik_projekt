import type { DirectoryUser, UserDirectory } from './types.js';

interface Seed {
  users: DirectoryUser[];
  memberships: Record<string, string[]>;
}

/** Mirrors the rows created by db/10-init-soapdemo.sh. */
export const DEFAULT_SEED: Seed = {
  users: [
    { username: 'alice', displayName: 'Alice Anderson', email: 'alice@example.com', isActive: true },
    { username: 'bob', displayName: 'Bob Baker', email: 'bob@example.com', isActive: true },
    { username: 'carol', displayName: 'Carol Chen', email: 'carol@example.com', isActive: true },
  ],
  memberships: {
    alice: ['admins', 'engineering'],
    bob: ['engineering'],
    carol: ['finance'],
  },
};

export function createInMemoryDirectory(seed: Seed = DEFAULT_SEED): UserDirectory {
  const users = new Map<string, DirectoryUser>(seed.users.map((u) => [u.username, { ...u }]));
  const memberships = new Map<string, string[]>(
    Object.entries(seed.memberships).map(([k, v]) => [k, [...v].sort()]),
  );

  return {
    async getUser(username) {
      const found = users.get(username);
      return found ? { ...found } : undefined;
    },
    async listGroups(username) {
      return [...(memberships.get(username) ?? [])];
    },
    async deactivateUser(username) {
      const user = users.get(username);
      if (!user) return false;
      user.isActive = false;
      return true;
    },
  };
}
