// @vitest-environment node
import { describe, test, expect, vi, beforeEach } from "vitest";
import { SignJWT, jwtVerify } from "jose";

vi.mock("server-only", () => ({}));

const mockSet = vi.fn();
const mockGet = vi.fn();
const mockDelete = vi.fn();

vi.mock("next/headers", () => ({
  cookies: vi.fn(async () => ({
    set: mockSet,
    get: mockGet,
    delete: mockDelete,
  })),
}));

const { createSession, getSession, deleteSession, verifySession } = await import("@/lib/auth");

const JWT_SECRET = new TextEncoder().encode("development-secret-key");

describe("createSession", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  test("sets auth-token cookie", async () => {
    await createSession("user-123", "test@example.com");

    expect(mockSet).toHaveBeenCalledOnce();
    expect(mockSet.mock.calls[0][0]).toBe("auth-token");
  });

  test("token contains correct userId and email", async () => {
    await createSession("user-123", "test@example.com");

    const token = mockSet.mock.calls[0][1] as string;
    const { payload } = await jwtVerify(token, JWT_SECRET);

    expect(payload.userId).toBe("user-123");
    expect(payload.email).toBe("test@example.com");
  });

  test("cookie has correct security options", async () => {
    await createSession("user-123", "test@example.com");

    const options = mockSet.mock.calls[0][2];

    expect(options.httpOnly).toBe(true);
    expect(options.sameSite).toBe("lax");
    expect(options.path).toBe("/");
    expect(options.secure).toBe(false);
  });

  test("cookie expires in 7 days", async () => {
    const before = Date.now();
    await createSession("user-123", "test@example.com");
    const after = Date.now();

    const options = mockSet.mock.calls[0][2];
    const expires: number = (options.expires as Date).getTime();
    const sevenDays = 7 * 24 * 60 * 60 * 1000;

    expect(expires).toBeGreaterThanOrEqual(before + sevenDays);
    expect(expires).toBeLessThanOrEqual(after + sevenDays);
  });

  test("generates a distinct token per call", async () => {
    await createSession("user-1", "a@example.com");
    const token1 = mockSet.mock.calls[0][1];

    vi.clearAllMocks();
    await createSession("user-2", "b@example.com");
    const token2 = mockSet.mock.calls[0][1];

    expect(token1).not.toBe(token2);
  });
});

describe("getSession", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  test("returns null when no cookie is present", async () => {
    mockGet.mockReturnValue(undefined);

    const session = await getSession();

    expect(session).toBeNull();
  });

  test("returns session payload for a valid token", async () => {
    const token = await new SignJWT({ userId: "user-123", email: "test@example.com" })
      .setProtectedHeader({ alg: "HS256" })
      .setExpirationTime("7d")
      .sign(JWT_SECRET);

    mockGet.mockReturnValue({ value: token });

    const session = await getSession();

    expect(session?.userId).toBe("user-123");
    expect(session?.email).toBe("test@example.com");
  });

  test("returns null for a tampered token", async () => {
    mockGet.mockReturnValue({ value: "invalid.token.value" });

    const session = await getSession();

    expect(session).toBeNull();
  });

  test("returns null for an expired token", async () => {
    const token = await new SignJWT({ userId: "user-123", email: "test@example.com" })
      .setProtectedHeader({ alg: "HS256" })
      .setExpirationTime("-1s")
      .sign(JWT_SECRET);

    mockGet.mockReturnValue({ value: token });

    const session = await getSession();

    expect(session).toBeNull();
  });
});

describe("deleteSession", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  test("deletes the auth-token cookie", async () => {
    await deleteSession();

    expect(mockDelete).toHaveBeenCalledOnce();
    expect(mockDelete).toHaveBeenCalledWith("auth-token");
  });
});

describe("verifySession", () => {
  function makeRequest(token: string | undefined) {
    return {
      cookies: { get: (name: string) => (token ? { name, value: token } : undefined) },
    } as any;
  }

  test("returns null when no cookie is present", async () => {
    const session = await verifySession(makeRequest(undefined));

    expect(session).toBeNull();
  });

  test("returns session payload for a valid token", async () => {
    const token = await new SignJWT({ userId: "user-123", email: "test@example.com" })
      .setProtectedHeader({ alg: "HS256" })
      .setExpirationTime("7d")
      .sign(JWT_SECRET);

    const session = await verifySession(makeRequest(token));

    expect(session?.userId).toBe("user-123");
    expect(session?.email).toBe("test@example.com");
  });

  test("returns null for a tampered token", async () => {
    const session = await verifySession(makeRequest("invalid.token.value"));

    expect(session).toBeNull();
  });

  test("returns null for an expired token", async () => {
    const token = await new SignJWT({ userId: "user-123", email: "test@example.com" })
      .setProtectedHeader({ alg: "HS256" })
      .setExpirationTime("-1s")
      .sign(JWT_SECRET);

    const session = await verifySession(makeRequest(token));

    expect(session).toBeNull();
  });
});
