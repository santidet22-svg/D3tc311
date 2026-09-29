import { pgTable, serial, text, timestamp, integer, bigint, primaryKey } from "drizzle-orm/pg-core";

// Cuenta en la nube: un taller = una cuenta compartida por todos sus dispositivos.
export const accounts = pgTable("accounts", {
  id: serial().primaryKey(),
  username: text().notNull().unique(),
  passwordHash: text("password_hash").notNull(),
  salt: text().notNull(),
  revision: bigint({ mode: "number" }).notNull().default(0),
  createdAt: timestamp("created_at").defaultNow(),
});

export const sessions = pgTable("sessions", {
  tokenHash: text("token_hash").primaryKey(),
  accountId: integer("account_id").notNull().references(() => accounts.id, { onDelete: "cascade" }),
  createdAt: timestamp("created_at").defaultNow(),
  lastUsedAt: timestamp("last_used_at").defaultNow(),
});

// Cada clave de datos de la app (órdenes, clientes, inventario...) como un registro.
export const appData = pgTable(
  "app_data",
  {
    accountId: integer("account_id").notNull().references(() => accounts.id, { onDelete: "cascade" }),
    key: text().notNull(),
    value: text().notNull(),
    revision: bigint({ mode: "number" }).notNull(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (t) => [primaryKey({ columns: [t.accountId, t.key] })],
);
