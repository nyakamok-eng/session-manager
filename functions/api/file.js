export async function onRequestGet(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const key = url.searchParams.get("key");

  if (!key) return new Response("Not found", { status: 404 });

  const object = await env.SESSION_R2.get(key);
  if (!object) return new Response("Not found", { status: 404 });

  const headers = new Headers();
  headers.set("Content-Type", object.httpMetadata?.contentType || "application/octet-stream");
  if (object.customMetadata?.originalName) {
    headers.set("Content-Disposition", `inline; filename="${object.customMetadata.originalName}"`);
  }

  return new Response(object.body, { headers });
}
