import type { Config } from "@netlify/functions";
import { createHash, randomBytes, scrypt, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
import { and, eq, gt, sql } from "drizzle-orm";
import { db } from "../../db/index.js";
import { accounts, appData, sessions } from "../../db/schema.js";

const scryptAsync = promisify(scrypt) as (pw: string, salt: string, len: number) => Promise<Buffer>;

// Solo se sincronizan claves de datos de la app. El bloqueo local (contraseña por
// dispositivo), el modo oscuro y los backups automáticos quedan en cada equipo.
const KEY_RE = /^detcell_[a-z0-9_]{1,60}$/;
const EXCLUDED = new Set(["detcell_auth_att", "detcell_auth_last", "detcell_autobackup", "detcell_modo_oscuro"]);
const MAX_VALUE = 5 * 1024 * 1024;

const json = (data: unknown, status = 200) => Response.json(data, { status, headers: { "cache-control": "no-store" } });
const err = (message: string, status: number) => json({ error: message }, status);
const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");
const normUser = (u: unknown) => String(u ?? "").trim().toLowerCase();

async function hashPassword(password: string, salt: string) {
  return (await scryptAsync(password, salt, 64)).toString("hex");
}

async function newSession(accountId: number) {
  const token = randomBytes(32).toString("base64url");
  await db.insert(sessions).values({ tokenHash: sha256(token), accountId });
  return token;
}

async function authenticate(req: Request) {
  const token = (req.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
  if (!token) return null;
  const [s] = await db.select().from(sessions).where(eq(sessions.tokenHash, sha256(token)));
  if (!s) return null;
  await db.update(sessions).set({ lastUsedAt: new Date() }).where(eq(sessions.tokenHash, s.tokenHash));
  return s;
}

async function register(body: any) {
  const username = normUser(body.user);
  const password = String(body.pass ?? "");
  if (!/^[a-z0-9._@-]{3,40}$/.test(username)) return err("El usuario debe tener entre 3 y 40 caracteres (letras, números, . _ - @).", 400);
  if (password.length < 8) return err("La contraseña debe tener al menos 8 caracteres.", 400);
  const [exists] = await db.select({ id: accounts.id }).from(accounts).where(eq(accounts.username, username));
  if (exists) return err("Ese usuario ya existe. Elegí otro o iniciá sesión.", 409);
  const salt = randomBytes(16).toString("hex");
  const [acc] = await db
    .insert(accounts)
    .values({ username, salt, passwordHash: await hashPassword(password, salt) })
    .onConflictDoNothing()
    .returning();
  if (!acc) return err("Ese usuario ya existe. Elegí otro o iniciá sesión.", 409);
  return json({ token: await newSession(acc.id), user: acc.username, rev: 0 }, 201);
}

async function login(body: any) {
  const username = normUser(body.user);
  const password = String(body.pass ?? "");
  const [acc] = await db.select().from(accounts).where(eq(accounts.username, username));
  const salt = acc?.salt ?? "0000000000000000";
  const hash = Buffer.from(await hashPassword(password, salt), "hex");
  const ok = !!acc && timingSafeEqual(hash, Buffer.from(acc.passwordHash, "hex"));
  if (!ok) {
    await new Promise((r) => setTimeout(r, 800));
    return err("Usuario o contraseña incorrectos.", 401);
  }
  return json({ token: await newSession(acc.id), user: acc.username, rev: acc.revision });
}

async function getData(accountId: number, since: number, only?: string) {
  const [acc] = await db.select({ rev: accounts.revision, user: accounts.username }).from(accounts).where(eq(accounts.id, accountId));
  if (!acc) return err("Cuenta no encontrada.", 401);
  const rows = await db
    .select({ key: appData.key, value: appData.value })
    .from(appData)
    .where(and(eq(appData.accountId, accountId), gt(appData.revision, since), only && KEY_RE.test(only) ? eq(appData.key, only) : undefined));
  const data: Record<string, string> = {};
  for (const r of rows) data[r.key] = r.value;
  return json({ rev: acc.rev, user: acc.user, data });
}

async function putData(accountId: number, body: any) {
  const changes = body?.changes;
  if (!changes || typeof changes !== "object" || Array.isArray(changes)) return err("Formato inválido.", 400);
  const entries = Object.entries(changes).filter(([k, v]) => KEY_RE.test(k) && !EXCLUDED.has(k) && typeof v === "string");
  if (entries.some(([, v]) => (v as string).length > MAX_VALUE)) return err("Uno de los datos es demasiado grande para sincronizar.", 413);
  if (!entries.length) return json({ rev: body.rev ?? 0 });

  const rev = await db.transaction(async (tx) => {
    const [acc] = await tx
      .update(accounts)
      .set({ revision: sql`${accounts.revision} + 1` })
      .where(eq(accounts.id, accountId))
      .returning({ rev: accounts.revision });
    for (const [key, value] of entries) {
      await tx
        .insert(appData)
        .values({ accountId, key, value: value as string, revision: acc.rev })
        .onConflictDoUpdate({
          target: [appData.accountId, appData.key],
          set: { value: value as string, revision: acc.rev, updatedAt: new Date() },
        });
    }
    return acc.rev;
  });
  return json({ rev });
}

export default async (req: Request) => {
  const action = new URL(req.url).pathname.split("/").pop();
  try {
    if (req.method === "POST" && action === "register") return await register(await req.json());
    if (req.method === "POST" && action === "login") return await login(await req.json());

    const session = await authenticate(req);
    if (!session) return err("Sesión vencida. Volvé a iniciar sesión en la nube.", 401);

    if (action === "data" && req.method === "GET") {
      const since = Math.max(0, parseInt(new URL(req.url).searchParams.get("since") || "0", 10) || 0);
      return await getData(session.accountId, since, new URL(req.url).searchParams.get("only") || undefined);
    }
    if (action === "data" && req.method === "PUT") return await putData(session.accountId, await req.json());
    if (action === "logout" && req.method === "POST") {
      await db.delete(sessions).where(eq(sessions.tokenHash, session.tokenHash));
      return json({ ok: true });
    }
    return err("No encontrado.", 404);
  } catch (e) {
    console.error("cloud api error", e);
    return err("Error del servidor. Intentá de nuevo.", 500);
  }
};

export const config: Config = {
  path: ["/api/cloud/register", "/api/cloud/login", "/api/cloud/logout", "/api/cloud/data"],
};
