async function verifyAdmin(request, env) {
  const auth = request.headers.get("Authorization");
  if (!auth || !auth.startsWith("Bearer ")) return false;
  const token = auth.slice(7);
  const valid = await env.SESSION_KV.get("admin:token:" + token);
  return !!valid;
}

export async function onRequestGet(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const clientToken = url.searchParams.get("token");

  if (clientToken) {
    const clientId = await env.SESSION_KV.get("token:" + clientToken);
    if (!clientId) return Response.json({ error: "not_found" }, { status: 404 });
    const data = await env.SESSION_KV.get("client:" + clientId, "json");
    if (!data) return Response.json({ error: "not_found" }, { status: 404 });
    return Response.json(data);
  }

  if (!(await verifyAdmin(request, env))) {
    return Response.json({ error: "unauthorized" }, { status: 401 });
  }

  const list = await env.SESSION_KV.get("client:list", "json") || [];
  const clients = [];
  for (const item of list) {
    const data = await env.SESSION_KV.get("client:" + item.id, "json");
    if (data) clients.push(data);
  }
  return Response.json(clients);
}

export async function onRequestPost(context) {
  const { request, env } = context;
  if (!(await verifyAdmin(request, env))) {
    return Response.json({ error: "unauthorized" }, { status: 401 });
  }

  const body = await request.json();
  const id = crypto.randomUUID().slice(0, 8);
  const pageToken = crypto.randomUUID().slice(0, 12);

  const client = {
    id,
    pageToken,
    name: body.name,
    plan: body.plan,
    totalSessions: parseInt(body.totalSessions) || 0,
    price: parseInt(body.price) || 0,
    sessions: [],
    createdAt: new Date().toISOString()
  };

  await env.SESSION_KV.put("client:" + id, JSON.stringify(client));
  await env.SESSION_KV.put("token:" + pageToken, id);

  const list = await env.SESSION_KV.get("client:list", "json") || [];
  list.push({ id, name: client.name });
  await env.SESSION_KV.put("client:list", JSON.stringify(list));

  return Response.json(client);
}

export async function onRequestPut(context) {
  const { request, env } = context;
  if (!(await verifyAdmin(request, env))) {
    return Response.json({ error: "unauthorized" }, { status: 401 });
  }

  const body = await request.json();
  const data = await env.SESSION_KV.get("client:" + body.id, "json");
  if (!data) return Response.json({ error: "not_found" }, { status: 404 });

  if (body.name !== undefined) data.name = body.name;
  if (body.plan !== undefined) data.plan = body.plan;
  if (body.totalSessions !== undefined) data.totalSessions = parseInt(body.totalSessions);
  if (body.price !== undefined) data.price = parseInt(body.price);

  await env.SESSION_KV.put("client:" + body.id, JSON.stringify(data));

  const list = await env.SESSION_KV.get("client:list", "json") || [];
  const idx = list.findIndex(i => i.id === body.id);
  if (idx >= 0) list[idx].name = data.name;
  await env.SESSION_KV.put("client:list", JSON.stringify(list));

  return Response.json(data);
}

export async function onRequestDelete(context) {
  const { request, env } = context;
  if (!(await verifyAdmin(request, env))) {
    return Response.json({ error: "unauthorized" }, { status: 401 });
  }

  const url = new URL(request.url);
  const id = url.searchParams.get("id");
  const data = await env.SESSION_KV.get("client:" + id, "json");

  if (data) {
    await env.SESSION_KV.delete("client:" + id);
    await env.SESSION_KV.delete("token:" + data.pageToken);
    const list = await env.SESSION_KV.get("client:list", "json") || [];
    const filtered = list.filter(i => i.id !== id);
    await env.SESSION_KV.put("client:list", JSON.stringify(filtered));
  }

  return Response.json({ ok: true });
}
