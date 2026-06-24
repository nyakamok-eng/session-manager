async function verifyAdmin(request, env) {
  const auth = request.headers.get("Authorization");
  if (!auth || !auth.startsWith("Bearer ")) return false;
  const token = auth.slice(7);
  const valid = await env.SESSION_KV.get("admin:token:" + token);
  return !!valid;
}

export async function onRequestPost(context) {
  const { request, env } = context;
  if (!(await verifyAdmin(request, env))) {
    return Response.json({ error: "unauthorized" }, { status: 401 });
  }

  const { clientId, date } = await request.json();
  const data = await env.SESSION_KV.get("client:" + clientId, "json");
  if (!data) return Response.json({ error: "not_found" }, { status: 404 });

  const sessionNumber = data.sessions.length + 1;
  data.sessions.push({
    number: sessionNumber,
    date: date || new Date().toISOString().split("T")[0],
    fileUrl: null,
    fileName: null
  });

  await env.SESSION_KV.put("client:" + clientId, JSON.stringify(data));
  return Response.json(data);
}

export async function onRequestDelete(context) {
  const { request, env } = context;
  if (!(await verifyAdmin(request, env))) {
    return Response.json({ error: "unauthorized" }, { status: 401 });
  }

  const url = new URL(request.url);
  const clientId = url.searchParams.get("clientId");
  const sessionNum = parseInt(url.searchParams.get("number"));

  const data = await env.SESSION_KV.get("client:" + clientId, "json");
  if (!data) return Response.json({ error: "not_found" }, { status: 404 });

  data.sessions = data.sessions.filter(s => s.number !== sessionNum);
  data.sessions.forEach((s, i) => s.number = i + 1);

  await env.SESSION_KV.put("client:" + clientId, JSON.stringify(data));
  return Response.json(data);
}
