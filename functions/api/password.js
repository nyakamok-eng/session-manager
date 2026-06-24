export async function onRequestPost(context) {
  const { request, env } = context;
  const { token, newPassword } = await request.json();

  const valid = await env.SESSION_KV.get("admin:token:" + token);
  if (!valid) return Response.json({ error: "unauthorized" }, { status: 401 });

  const encoder = new TextEncoder();
  const data = encoder.encode(newPassword);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hash = [...new Uint8Array(hashBuffer)].map(b => b.toString(16).padStart(2, "0")).join("");

  await env.SESSION_KV.put("admin:password", hash);
  return Response.json({ ok: true });
}
