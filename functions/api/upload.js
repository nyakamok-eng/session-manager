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

  const formData = await request.formData();
  const file = formData.get("file");
  const clientId = formData.get("clientId");
  const sessionNumber = parseInt(formData.get("sessionNumber"));

  if (!file || !clientId || !sessionNumber) {
    return Response.json({ error: "missing_fields" }, { status: 400 });
  }

  const ext = file.name.split(".").pop();
  const key = `${clientId}/${sessionNumber}.${ext}`;

  await env.SESSION_R2.put(key, file.stream(), {
    httpMetadata: { contentType: file.type },
    customMetadata: { originalName: file.name }
  });

  const data = await env.SESSION_KV.get("client:" + clientId, "json");
  if (data) {
    const session = data.sessions.find(s => s.number === sessionNumber);
    if (session) {
      session.fileUrl = `/api/file?key=${encodeURIComponent(key)}`;
      session.fileName = file.name;
    }
    await env.SESSION_KV.put("client:" + clientId, JSON.stringify(data));
  }

  return Response.json({ ok: true, key });
}
