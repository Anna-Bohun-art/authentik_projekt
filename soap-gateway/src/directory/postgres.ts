import type { Pool } from 'pg';
import type { DirectoryUser, UserDirectory } from './types.js';

interface UserRow {
  username: string;
  display_name: string;
  email: string;
  is_active: boolean;
}

function toDomain(row: UserRow): DirectoryUser {
  return {
    username: row.username,
    displayName: row.display_name,
    email: row.email,
    isActive: row.is_active,
  };
}

/**
 * SQL-backed directory. Every query is parameterised — user input never gets
 * concatenated into a statement. Schema: db/10-init-soapdemo.sh.
 */
export function createPostgresDirectory(pool: Pool): UserDirectory {
  return {
    async getUser(username) {
      const { rows } = await pool.query<UserRow>(
        'SELECT username, display_name, email, is_active FROM app_user WHERE username = $1',
        [username],
      );
      return rows[0] ? toDomain(rows[0]) : undefined;
    },

    async listGroups(username) {
      const { rows } = await pool.query<{ name: string }>(
        `SELECT g.name
           FROM user_group ug
           JOIN app_group g ON g.name = ug.group_name
          WHERE ug.username = $1
          ORDER BY g.name`,
        [username],
      );
      return rows.map((r) => r.name);
    },

    async deactivateUser(username) {
      const { rowCount } = await pool.query(
        'UPDATE app_user SET is_active = false WHERE username = $1',
        [username],
      );
      return (rowCount ?? 0) > 0;
    },
  };
}
