export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname.startsWith("/api/")) {
      return handleAPI(url, request, env);
    }

    return env.ASSETS.fetch(request);
  }
};

async function handleAPI(url, request, env) {
  const path = url.pathname;
  const method = request.method;

  const corsHeaders = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type,Authorization"
  };

  if (method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    let res;

    if (path === "/api/auth" && method === "POST") {
      res = await handleAuth(request, env);
    } else if (path === "/api/password" && method === "POST") {
      res = await handlePassword(request, env);
    } else if (path === "/api/clients") {
      res = await handleClients(url, request, method, env);
    } else if (path === "/api/sessions") {
      res = await handleSessions(url, request, method, env);
    } else if (path === "/api/upload" && method === "POST") {
      res = await handleUpload(request, env);
    } else if (path === "/api/file" && method === "GET") {
      res = await handleFile(url, env);
    } else if (path === "/api/settings") {
      res = await handleSettings(url, request, method, env);
    } else if (path === "/api/timelog") {
      res = await handleTimelog(url, request, method, env);
    } else if (path === "/api/archives") {
      res = await handleArchives(url, request, method, env);
    } else if (path === "/api/export" && method === "GET") {
      res = await handleExport(request, env);
    } else if (path === "/api/errors") {
      res = await handleErrors(url, request, method, env);
    } else if (path === "/api/cleanup") {
      res = await handleCleanup(url, request, method, env);
    } else {
      res = Response.json({ error: "not_found" }, { status: 404 });
    }

    const headers = new Headers(res.headers);
    for (const [k, v] of Object.entries(corsHeaders)) {
      headers.set(k, v);
    }
    return new Response(res.body, { status: res.status, headers });
  } catch (e) {
    await logError(env, path, method, e);
    return Response.json({ error: "server_error" }, { status: 500, headers: corsHeaders });
  }
}

async function verifyAdmin(request, env) {
  const auth = request.headers.get("Authorization");
  if (!auth || !auth.startsWith("Bearer ")) return false;
  const token = auth.slice(7);
  const valid = await env.SESSION_KV.get("admin:token:" + token);
  return !!valid;
}

async function handleAuth(request, env) {
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

async function handlePassword(request, env) {
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

async function handleClients(url, request, method, env) {
  if (method === "GET") {
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

  if (method === "POST") {
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

  if (method === "PUT") {
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
    if (body.sheetUrl !== undefined) data.sheetUrl = body.sheetUrl;
    if (body.expiryDate !== undefined) data.expiryDate = body.expiryDate;

    await env.SESSION_KV.put("client:" + body.id, JSON.stringify(data));

    const list = await env.SESSION_KV.get("client:list", "json") || [];
    const idx = list.findIndex(i => i.id === body.id);
    if (idx >= 0) list[idx].name = data.name;
    await env.SESSION_KV.put("client:list", JSON.stringify(list));

    return Response.json(data);
  }

  if (method === "DELETE") {
    if (!(await verifyAdmin(request, env))) {
      return Response.json({ error: "unauthorized" }, { status: 401 });
    }
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

  return Response.json({ error: "method_not_allowed" }, { status: 405 });
}

async function handleSessions(url, request, method, env) {
  if (method === "POST") {
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

  if (method === "PUT") {
    if (!(await verifyAdmin(request, env))) {
      return Response.json({ error: "unauthorized" }, { status: 401 });
    }
    const { clientId, sessionNumber, fileUrl, fileName } = await request.json();
    const data = await env.SESSION_KV.get("client:" + clientId, "json");
    if (!data) return Response.json({ error: "not_found" }, { status: 404 });

    const session = data.sessions.find(s => s.number === sessionNumber);
    if (!session) return Response.json({ error: "session_not_found" }, { status: 404 });

    session.fileUrl = fileUrl || null;
    session.fileName = fileName || null;

    await env.SESSION_KV.put("client:" + clientId, JSON.stringify(data));
    return Response.json(data);
  }

  if (method === "DELETE") {
    if (!(await verifyAdmin(request, env))) {
      return Response.json({ error: "unauthorized" }, { status: 401 });
    }
    const clientId = url.searchParams.get("clientId");
    const sessionNum = parseInt(url.searchParams.get("number"));

    const data = await env.SESSION_KV.get("client:" + clientId, "json");
    if (!data) return Response.json({ error: "not_found" }, { status: 404 });

    data.sessions = data.sessions.filter(s => s.number !== sessionNum);
    data.sessions.forEach((s, i) => s.number = i + 1);

    await env.SESSION_KV.put("client:" + clientId, JSON.stringify(data));
    return Response.json(data);
  }

  return Response.json({ error: "method_not_allowed" }, { status: 405 });
}

async function handleSettings(url, request, method, env) {
  if (method === "GET") {
    const key = url.searchParams.get("key");
    if (!key) return Response.json({ error: "key_required" }, { status: 400 });
    const data = await env.SESSION_KV.get("settings:" + key, "json");
    return Response.json(data || {});
  }

  if (method === "POST") {
    if (!(await verifyAdmin(request, env))) {
      return Response.json({ error: "unauthorized" }, { status: 401 });
    }
    const { key, value } = await request.json();
    if (!key) return Response.json({ error: "key_required" }, { status: 400 });
    await env.SESSION_KV.put("settings:" + key, JSON.stringify(value));
    return Response.json({ ok: true });
  }

  return Response.json({ error: "method_not_allowed" }, { status: 405 });
}

async function handleTimelog(url, request, method, env) {
  if (method === "GET") {
    const clientToken = url.searchParams.get("token");
    const clientId = url.searchParams.get("clientId");

    if (clientToken) {
      const id = await env.SESSION_KV.get("token:" + clientToken);
      if (!id) return Response.json({ error: "not_found" }, { status: 404 });
      const data = await env.SESSION_KV.get("timelog:" + id, "json");
      return Response.json(data || { status: "none" });
    }

    if (clientId) {
      if (!(await verifyAdmin(request, env))) {
        return Response.json({ error: "unauthorized" }, { status: 401 });
      }
      const data = await env.SESSION_KV.get("timelog:" + clientId, "json");
      return Response.json(data || { status: "none" });
    }

    return Response.json({ error: "missing_params" }, { status: 400 });
  }

  if (method === "POST") {
    const body = await request.json();
    const action = body.action;

    if (action === "start") {
      if (!(await verifyAdmin(request, env))) {
        return Response.json({ error: "unauthorized" }, { status: 401 });
      }
      const timelog = {
        status: "active",
        startedAt: new Date().toISOString(),
        entries: []
      };
      await env.SESSION_KV.put("timelog:" + body.clientId, JSON.stringify(timelog));
      return Response.json(timelog);
    }

    if (action === "save") {
      const clientToken = body.token;
      const clientId = body.clientId;
      let id;

      if (clientToken) {
        id = await env.SESSION_KV.get("token:" + clientToken);
        if (!id) return Response.json({ error: "not_found" }, { status: 404 });
      } else if (clientId) {
        if (!(await verifyAdmin(request, env))) {
          return Response.json({ error: "unauthorized" }, { status: 401 });
        }
        id = clientId;
      } else {
        return Response.json({ error: "missing_params" }, { status: 400 });
      }

      const data = await env.SESSION_KV.get("timelog:" + id, "json");
      if (!data || data.status !== "active") {
        return Response.json({ error: "timelog_not_active" }, { status: 400 });
      }

      const entry = {
        dayNumber: body.dayNumber,
        date: body.date,
        slots: body.slots || [],
        memo: body.memo || ""
      };

      const existingIdx = data.entries.findIndex(e => e.dayNumber === body.dayNumber);
      if (existingIdx >= 0) {
        data.entries[existingIdx] = entry;
      } else {
        data.entries.push(entry);
      }
      data.entries.sort((a, b) => a.dayNumber - b.dayNumber);

      await env.SESSION_KV.put("timelog:" + id, JSON.stringify(data));
      return Response.json(data);
    }

    if (action === "stop") {
      if (!(await verifyAdmin(request, env))) {
        return Response.json({ error: "unauthorized" }, { status: 401 });
      }
      const data = await env.SESSION_KV.get("timelog:" + body.clientId, "json");
      if (!data) return Response.json({ error: "not_found" }, { status: 404 });
      data.status = "completed";
      await env.SESSION_KV.put("timelog:" + body.clientId, JSON.stringify(data));
      return Response.json(data);
    }

    if (action === "adminMemo") {
      if (!(await verifyAdmin(request, env))) {
        return Response.json({ error: "unauthorized" }, { status: 401 });
      }
      const data = await env.SESSION_KV.get("timelog:" + body.clientId, "json");
      if (!data) return Response.json({ error: "not_found" }, { status: 404 });
      data.adminMemo = body.memo || "";
      await env.SESSION_KV.put("timelog:" + body.clientId, JSON.stringify(data));
      return Response.json(data);
    }

    if (action === "deleteEntry") {
      const clientToken = body.token;
      const clientId = body.clientId;
      let id;

      if (clientToken) {
        id = await env.SESSION_KV.get("token:" + clientToken);
        if (!id) return Response.json({ error: "not_found" }, { status: 404 });
      } else if (clientId) {
        if (!(await verifyAdmin(request, env))) {
          return Response.json({ error: "unauthorized" }, { status: 401 });
        }
        id = clientId;
      } else {
        return Response.json({ error: "missing_params" }, { status: 400 });
      }

      const data = await env.SESSION_KV.get("timelog:" + id, "json");
      if (!data || data.status !== "active") {
        return Response.json({ error: "timelog_not_active" }, { status: 400 });
      }

      data.entries = data.entries.filter(e => e.dayNumber !== body.dayNumber);
      data.entries.forEach((e, i) => e.dayNumber = i + 1);

      await env.SESSION_KV.put("timelog:" + id, JSON.stringify(data));
      return Response.json(data);
    }

    return Response.json({ error: "invalid_action" }, { status: 400 });
  }

  if (method === "DELETE") {
    if (!(await verifyAdmin(request, env))) {
      return Response.json({ error: "unauthorized" }, { status: 401 });
    }
    const clientId = url.searchParams.get("clientId");
    await env.SESSION_KV.delete("timelog:" + clientId);
    return Response.json({ ok: true });
  }

  return Response.json({ error: "method_not_allowed" }, { status: 405 });
}

async function handleArchives(url, request, method, env) {
  if (method === "GET") {
    const clientToken = url.searchParams.get("token");
    if (clientToken) {
      const clientId = await env.SESSION_KV.get("token:" + clientToken);
      if (!clientId) return Response.json({ error: "not_found" }, { status: 404 });
      const clientData = await env.SESSION_KV.get("client:" + clientId, "json");
      if (!clientData) return Response.json({ error: "not_found" }, { status: 404 });
      const archives = await env.SESSION_KV.get("settings:shareArchives", "json") || [];
      const access = clientData.archiveAccess || [];
      const permitted = archives.filter(a => access.includes(a.id));
      return Response.json(permitted);
    }

    if (!(await verifyAdmin(request, env))) {
      return Response.json({ error: "unauthorized" }, { status: 401 });
    }
    const archives = await env.SESSION_KV.get("settings:shareArchives", "json") || [];
    return Response.json(archives);
  }

  if (!(await verifyAdmin(request, env))) {
    return Response.json({ error: "unauthorized" }, { status: 401 });
  }

  if (method === "POST") {
    const body = await request.json();
    const action = body.action;

    if (action === "add") {
      const archives = await env.SESSION_KV.get("settings:shareArchives", "json") || [];
      const id = crypto.randomUUID().slice(0, 8);
      archives.unshift({ id, title: body.title, url: body.url, date: body.date });
      await env.SESSION_KV.put("settings:shareArchives", JSON.stringify(archives));
      return Response.json(archives);
    }

    if (action === "edit") {
      const archives = await env.SESSION_KV.get("settings:shareArchives", "json") || [];
      const item = archives.find(a => a.id === body.id);
      if (!item) return Response.json({ error: "not_found" }, { status: 404 });
      if (body.title !== undefined) item.title = body.title;
      if (body.url !== undefined) item.url = body.url;
      if (body.date !== undefined) item.date = body.date;
      await env.SESSION_KV.put("settings:shareArchives", JSON.stringify(archives));
      return Response.json(archives);
    }

    if (action === "delete") {
      let archives = await env.SESSION_KV.get("settings:shareArchives", "json") || [];
      archives = archives.filter(a => a.id !== body.id);
      await env.SESSION_KV.put("settings:shareArchives", JSON.stringify(archives));
      return Response.json(archives);
    }

    if (action === "setAccess") {
      const clientData = await env.SESSION_KV.get("client:" + body.clientId, "json");
      if (!clientData) return Response.json({ error: "not_found" }, { status: 404 });
      clientData.archiveAccess = body.archiveIds || [];
      await env.SESSION_KV.put("client:" + body.clientId, JSON.stringify(clientData));
      return Response.json({ ok: true });
    }

    return Response.json({ error: "invalid_action" }, { status: 400 });
  }

  return Response.json({ error: "method_not_allowed" }, { status: 405 });
}

async function handleUpload(request, env) {
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

  const arrayBuffer = await file.arrayBuffer();
  const fileKey = "file:" + clientId + ":" + sessionNumber;

  await env.SESSION_KV.put(fileKey, arrayBuffer, {
    metadata: { contentType: file.type, fileName: file.name }
  });

  const data = await env.SESSION_KV.get("client:" + clientId, "json");
  if (data) {
    const session = data.sessions.find(s => s.number === sessionNumber);
    if (session) {
      session.fileUrl = "/api/file?key=" + encodeURIComponent(fileKey);
      session.fileName = file.name;
      await env.SESSION_KV.put("client:" + clientId, JSON.stringify(data));
    }
  }

  return Response.json({ ok: true });
}

async function handleFile(url, env) {
  const key = url.searchParams.get("key");
  if (!key) return Response.json({ error: "key_required" }, { status: 400 });

  const { value, metadata } = await env.SESSION_KV.getWithMetadata(key, "arrayBuffer");
  if (!value) return Response.json({ error: "not_found" }, { status: 404 });

  const contentType = metadata && metadata.contentType ? metadata.contentType : "application/octet-stream";
  const fileName = metadata && metadata.fileName ? metadata.fileName : "file";

  return new Response(value, {
    headers: {
      "Content-Type": contentType,
      "Content-Disposition": "inline; filename=\"" + fileName + "\""
    }
  });
}

async function handleExport(request, env) {
  const auth = request.headers.get("Authorization");
  const exportKey = request.headers.get("X-Export-Key");

  if (exportKey) {
    const storedKey = await env.SESSION_KV.get("settings:exportKey", "json");
    if (!storedKey || exportKey !== storedKey) {
      return Response.json({ error: "unauthorized" }, { status: 401 });
    }
  } else {
    if (!(await verifyAdmin(request, env))) {
      return Response.json({ error: "unauthorized" }, { status: 401 });
    }
  }

  const clientList = await env.SESSION_KV.get("client:list", "json") || [];
  const clients = [];
  for (const item of clientList) {
    const data = await env.SESSION_KV.get("client:" + item.id, "json");
    if (data) {
      const timelog = await env.SESSION_KV.get("timelog:" + item.id, "json");
      clients.push({ ...data, timelog: timelog || null });
    }
  }

  const archives = await env.SESSION_KV.get("settings:shareArchives", "json") || [];
  const audioLink = await env.SESSION_KV.get("settings:audioLink", "json") || null;

  const errorLogs = await env.SESSION_KV.get("system:errorLogs", "json") || [];

  const exportData = {
    exportedAt: new Date().toISOString(),
    clients,
    archives,
    audioLink,
    errorLogs
  };

  return Response.json(exportData);
}

async function logError(env, endpoint, method, error) {
  try {
    const logs = await env.SESSION_KV.get("system:errorLogs", "json") || [];
    logs.unshift({
      id: crypto.randomUUID().slice(0, 8),
      timestamp: new Date().toISOString(),
      endpoint,
      method,
      message: error.message || String(error),
      stack: error.stack || null
    });
    if (logs.length > 100) logs.length = 100;
    await env.SESSION_KV.put("system:errorLogs", JSON.stringify(logs));
  } catch (e) {}
}

async function handleErrors(url, request, method, env) {
  if (!(await verifyAdmin(request, env))) {
    return Response.json({ error: "unauthorized" }, { status: 401 });
  }

  if (method === "GET") {
    const logs = await env.SESSION_KV.get("system:errorLogs", "json") || [];
    return Response.json(logs);
  }

  if (method === "POST") {
    const { action } = await request.json();
    if (action === "clear") {
      await env.SESSION_KV.put("system:errorLogs", JSON.stringify([]));
      return Response.json({ ok: true });
    }
  }

  return Response.json({ error: "method_not_allowed" }, { status: 405 });
}

async function handleCleanup(url, request, method, env) {
  if (method === "GET") {
    const clientToken = url.searchParams.get("token");
    const clientId = url.searchParams.get("clientId");

    if (clientToken) {
      const id = await env.SESSION_KV.get("token:" + clientToken);
      if (!id) return Response.json({ error: "not_found" }, { status: 404 });
      const client = await env.SESSION_KV.get("client:" + id, "json");
      if (!client || !client.cleanupSessionEnabled) {
        return Response.json({ error: "not_available" }, { status: 403 });
      }
      const data = await env.SESSION_KV.get("cleanup:" + id, "json");
      return Response.json(data || { total: 4, completed: [] });
    }

    if (clientId) {
      if (!(await verifyAdmin(request, env))) {
        return Response.json({ error: "unauthorized" }, { status: 401 });
      }
      const data = await env.SESSION_KV.get("cleanup:" + clientId, "json");
      return Response.json(data || { total: 4, completed: [] });
    }

    return Response.json({ error: "missing_params" }, { status: 400 });
  }

  if (method === "POST") {
    if (!(await verifyAdmin(request, env))) {
      return Response.json({ error: "unauthorized" }, { status: 401 });
    }
    const body = await request.json();
    const action = body.action;

    if (action === "toggle") {
      const client = await env.SESSION_KV.get("client:" + body.clientId, "json");
      if (!client) return Response.json({ error: "not_found" }, { status: 404 });
      client.cleanupSessionEnabled = !!body.enabled;
      await env.SESSION_KV.put("client:" + body.clientId, JSON.stringify(client));
      return Response.json({ ok: true });
    }

    if (action === "complete") {
      const data = await env.SESSION_KV.get("cleanup:" + body.clientId, "json") || { total: 4, completed: [] };
      if (data.completed.length >= data.total) {
        return Response.json({ error: "all_completed" }, { status: 400 });
      }
      data.completed.push({
        number: data.completed.length + 1,
        date: body.date || new Date().toISOString().split("T")[0].replace(/-/g, "."),
        videoUrl: body.videoUrl || ""
      });
      await env.SESSION_KV.put("cleanup:" + body.clientId, JSON.stringify(data));
      return Response.json(data);
    }

    if (action === "editSession") {
      const data = await env.SESSION_KV.get("cleanup:" + body.clientId, "json");
      if (!data) return Response.json({ error: "not_found" }, { status: 404 });
      const session = data.completed.find(s => s.number === body.number);
      if (!session) return Response.json({ error: "not_found" }, { status: 404 });
      if (body.date) session.date = body.date;
      if (body.videoUrl !== undefined) session.videoUrl = body.videoUrl;
      await env.SESSION_KV.put("cleanup:" + body.clientId, JSON.stringify(data));
      return Response.json(data);
    }

    if (action === "deleteSession") {
      const data = await env.SESSION_KV.get("cleanup:" + body.clientId, "json");
      if (!data) return Response.json({ error: "not_found" }, { status: 404 });
      data.completed = data.completed.filter(s => s.number !== body.number);
      data.completed.forEach((s, i) => s.number = i + 1);
      await env.SESSION_KV.put("cleanup:" + body.clientId, JSON.stringify(data));
      return Response.json(data);
    }

    return Response.json({ error: "invalid_action" }, { status: 400 });
  }

  return Response.json({ error: "method_not_allowed" }, { status: 405 });
}
