// 可选的通用媒体中转端点（默认关闭）。
//
// 用途：从同一个出口 IP 完成“取页 -> 解析媒体地址 -> 取流”全链路，
// 供上游媒体地址绑定请求 IP 的场景使用（解析与取流必须同 IP）。
// 全部配置走环境变量，代码里不含任何上游特征：
//   RELAY_KEY       调用密钥（请求头 X-Relay-Key）
//   RELAY_PATH      路径段（随机串，如 x7k2m9q4...，不含斜杠）
//   RELAY_UPSTREAM  上游站点 origin，如 https://example.com
//   RELAY_PAGE_TMPL 页面路径模板，{id} 会被替换，如 /view_video.php?viewkey={id}
//   RELAY_DEFS_KEY  页面内媒体定义数组的 JSON 键名，如 mediaDefinitions
// 五项缺任何一项，端点不注册（当它不存在）。
// 鉴权失败返回 404（不暴露端点存在）；鉴权通过后的上游失败返回 502 + 步骤码。
// 日志里不记录请求参数。

import type { Hono } from "hono";
import { config } from "./config.ts";

const UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
const PAGE_TIMEOUT_MS = 20_000;
const QUALITY_ORDER: Record<string, number> = { "720": 0, "480": 1, "1080": 2, "240": 3 };

type MediaDef = { format?: string; quality?: string | number; videoUrl?: string };

function enabled(): boolean {
  return Boolean(
    config.relayKey && config.relayPath && config.relayUpstream && config.relayPageTmpl && config.relayDefsKey,
  );
}

// 从 HTML 里按括号匹配取出 key 对应的 JSON 数组（只从针位起扫描，不扫整页）。
function extractDefsArray(html: string, key: string): MediaDef[] | null {
  const needle = `"${key}":`;
  const pos = html.indexOf(needle);
  if (pos < 0) return null;
  const start = html.indexOf("[", pos + needle.length);
  if (start < 0) return null;
  let depth = 0;
  let inStr = false;
  let esc = false;
  let end = -1;
  for (let i = start; i < html.length; i++) {
    const c = html[i];
    if (inStr) {
      if (esc) {
        esc = false;
        continue;
      }
      if (c === "\\") {
        esc = true;
        continue;
      }
      if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') {
      inStr = true;
      continue;
    }
    if (c === "[") depth++;
    else if (c === "]") {
      depth--;
      if (depth === 0) {
        end = i + 1;
        break;
      }
    }
  }
  if (end < 0) return null;
  try {
    const parsed = JSON.parse(html.slice(start, end)) as unknown;
    return Array.isArray(parsed) ? (parsed as MediaDef[]) : null;
  } catch {
    return null;
  }
}

export function registerRelay(app: Hono): void {
  if (!enabled()) return;
  const upstream = config.relayUpstream.replace(/\/$/, "");
  const path = "/" + config.relayPath.replace(/^\/+/, "");

  app.get(path, async (c) => {
    // 鉴权：密钥头不对直接 404，不暴露端点存在
    if (c.req.header("X-Relay-Key") !== config.relayKey) {
      return c.text("Not Found", 404);
    }
    const id = c.req.query("id");
    if (!id) return c.json({ error: "missing id" }, 400);
    const range = c.req.header("Range");
    const fail = (step: string) => {
      console.error(`[relay] ${step} failed`);
      return c.json({ error: step }, 502);
    };

    // 1. 取页（收 cookie，供第 3 步用）
    const pageUrl = upstream + config.relayPageTmpl.replaceAll("{id}", encodeURIComponent(id));
    let pageRes: Response;
    try {
      pageRes = await fetch(pageUrl, {
        headers: { "User-Agent": UA, Referer: upstream + "/" },
        signal: AbortSignal.timeout(PAGE_TIMEOUT_MS),
        redirect: "follow",
      });
    } catch {
      return fail("page");
    }
    if (!pageRes.ok) return fail("page");
    const setCookies: string[] =
      typeof pageRes.headers.getSetCookie === "function"
        ? pageRes.headers.getSetCookie()
        : (() => {
            const single = pageRes.headers.get("set-cookie");
            return single ? [single] : [];
          })();
    const cookie = setCookies.map((sc) => sc.split(";")[0]).join("; ");
    const html = await pageRes.text();

    // 2. 解析媒体定义，取 mp4 条目的二次地址
    const defs = extractDefsArray(html, config.relayDefsKey);
    if (!defs) return fail("defs");
    const mp4 = defs.find((d) => d.format === "mp4" && d.videoUrl);
    if (!mp4 || !mp4.videoUrl) return fail("mp4def");
    const gmUrl = mp4.videoUrl.replace(/\\\//g, "/");

    // 3. 二次地址（带页 cookie + Referer）
    const gmHeaders: Record<string, string> = {
      "User-Agent": UA,
      Referer: pageUrl,
      Accept: "application/json",
    };
    if (cookie) gmHeaders["Cookie"] = cookie;
    let gmRes: Response;
    try {
      gmRes = await fetch(gmUrl, {
        headers: gmHeaders,
        signal: AbortSignal.timeout(PAGE_TIMEOUT_MS),
        redirect: "follow",
      });
    } catch {
      return fail("media");
    }
    if (!gmRes.ok) return fail("media");
    let variants: unknown;
    try {
      variants = (await gmRes.json()) as unknown;
    } catch {
      return fail("media");
    }
    if (!Array.isArray(variants) || variants.length === 0) return fail("media");
    let best: string | null = null;
    let bestRank = 99;
    for (const v of variants as MediaDef[]) {
      if (!v.videoUrl) continue;
      const rank = QUALITY_ORDER[String(v.quality)] ?? 9;
      if (rank < bestRank) {
        bestRank = rank;
        best = v.videoUrl;
      }
    }
    if (!best) return fail("media");
    const mediaUrl = (best as string).replace(/\\\//g, "/");

    // 4. 取流（同进程同出口 IP，与第 3 步一致），流式透传
    const mediaHeaders: Record<string, string> = { "User-Agent": UA, Referer: upstream + "/" };
    if (range) mediaHeaders["Range"] = range;
    let up: Response;
    try {
      up = await fetch(mediaUrl, { headers: mediaHeaders, redirect: "follow" });
    } catch {
      return fail("stream");
    }
    const headers = new Headers();
    for (const name of ["content-type", "content-length", "content-range", "accept-ranges"]) {
      const v = up.headers.get(name);
      if (v) headers.set(name, v);
    }
    headers.set("Access-Control-Allow-Origin", "*");
    return new Response(up.body, { status: up.status, headers });
  });
}
