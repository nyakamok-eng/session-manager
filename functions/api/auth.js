export async function onRequestPost(context) {
  const { request, env } = context;
  const { password } = await request.json();

  const stored = await env.SESSION_KV.get("admin:password");

  if (!stored) {
    if (password === "admin1234") {
      const token = crypto.randomUUID();
      await env.SESSION_KV.put("admin:token:" + token, "valid", { expirationTtl: 86400 * 7 });
      return Response.json({ token, firstLogin: true });
    }
    return Response.json({ error: "invalid" }, { status: 401 });
  }

  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hash = [...new Uint8Array(hashBuffer)].map(b => b.toString(16).padStart(2, "0")).join("");

  if (hash !== stored) {
    return Response.json({ error: "invalid" }, { status: 401 });
  }

  const token = crypto.randomUUID();
  await env.SESSION_KV.put("admin:token:" + token, "valid", { expirationTtl: 86400 * 7 });
  return Response.json({ token });
}
