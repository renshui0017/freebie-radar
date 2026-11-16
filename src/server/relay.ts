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
// 安全加固（2026-11-16）：第 3、4 步的上游 URL 来自页面内容，须过域名白名单
// （pornhub.com / phncdn.com 后缀，拒裸 IP 与内网地址），重定向每跳都校验。

import type { Hono } from "hono";
import { config } from "./config.ts";

const UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
const PAGE_TIMEOUT_MS = 20_000;
const RANGE_STEP = 8 * 1024 * 1024; // Range 大起点探针步进（见第 4 步注释）
const QUALITY_ORDER: Record<string, number> = { "720": 0, "480": 1, "1080": 2, "240": 3 };

type MediaDef = { format?: string; quality?: string | number; videoUrl?: string };

function enabled(): boolean {
  return Boolean(
    config.relayKey && config.relayPath && config.relayUpstream && config.relayPageTmpl && config.relayDefsKey,
  );
}

// 上游 URL 校验（安全加固 2026-11-16）：gmUrl / mediaUrl 来自上游页面内容，
// 不是服务端构造的，必须落在上游自家域名上；裸 IP、内网地址、非 http(s) 一律拒绝。
// 第 1 步的 pageUrl 由环境变量 + 编码后的 id 构造（可信），不走这里。
const RELAY_ALLOWED_SUFFIXES = ["pornhub.com", "phncdn.com"];

function isRelayAllowedUrl(raw: string): boolean {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return false;
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") return false;
  if (u.username !== "" || u.password !== "") return false;
  const host = u.hostname.toLowerCase().replace(/\.$/, "");
  if (host === "" || host === "localhost" || host.endsWith(".localhost")) return false;
  // 裸 IP 一律拒绝（IPv4 字面量与含冒号的 IPv6 字面量）
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host) || host.includes(":")) return false;
  for (const s of RELAY_ALLOWED_SUFFIXES) {
    if (host === s || host.endsWith("." + s)) return true;
  }
  return false;
}

// 带校验的手动重定向跟随：初始 URL 与每一跳都必须过域名白名单，最多 3 跳。
// timeoutMs 为空时不设超时（取流是大文件流式传输，不能用固定超时掐断）。
async function fetchRelay(url: string, init: RequestInit, timeoutMs?: number): Promise<Response> {
  let current = url;
  for (let hop = 0; hop <= 3; hop++) {
    if (!isRelayAllowedUrl(current)) {
      throw new Error("relay: disallowed url");
    }
    const res = await fetch(current, {
      ...init,
      ...(timeoutMs ? { signal: AbortSignal.timeout(timeoutMs) } : {}),
      redirect: "manual",
    });
    if (
      res.status === 301 ||
      res.status === 302 ||
      res.status === 303 ||
      res.status === 307 ||
      res.status === 308
    ) {
      const loc = res.headers.get("location");
      await res.arrayBuffer().catch(() => undefined);
      if (!loc) throw new Error("relay: redirect without location");
      current = new URL(loc, current).toString();
      continue;
    }
    return res;
  }
  throw new Error("relay: too many redirects");
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
      gmRes = await fetchRelay(gmUrl, { headers: gmHeaders }, PAGE_TIMEOUT_MS);
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
    // phncdn 限制 Range 起点相对已送达位置的跳跃幅度（实测：60MB 跳跃返回 416，
    // 10MB 步进正常；同一文件+IP 下渐进请求 20M→100M 全部 206）：大起点先以
    // 小步 Range 探针“走”上去，每步只取 1 字节，探针失败即停（尽力而为）。
    // 416 是边缘节点状态依赖的偶发失败（同一视频同一偏移可连续 10 次成功也可偶发
    // 416）：最终取流 416 时重走一遍探针再取，最多 3 次；3 次都 416 则原样返回。
    const rangeStart = /^bytes=(\d+)-/.exec(range || "");
    const startPos = rangeStart ? parseInt(rangeStart[1] ?? "0", 10) : 0;
    const walk = async () => {
      if (startPos <= RANGE_STEP) return;
      for (let pos = RANGE_STEP; pos < startPos; pos += RANGE_STEP) {
        try {
          const probe = await fetchRelay(
            mediaUrl,
            { headers: { "User-Agent": UA, Referer: upstream + "/", Range: `bytes=${pos}-${pos}` } },
            PAGE_TIMEOUT_MS,
          );
          await probe.arrayBuffer().catch(() => undefined);
          if (probe.status !== 206) break;
        } catch {
          break;
        }
      }
    };
    let up: Response | null = null;
    for (let attempt = 0; attempt < 3; attempt++) {
      await walk();
      try {
        up = await fetchRelay(mediaUrl, { headers: mediaHeaders });
      } catch {
        up = null;
      }
      if (up && up.status !== 416) break;
      if (up) await up.arrayBuffer().catch(() => undefined);
      if (attempt < 2) await new Promise((r) => setTimeout(r, 1000));
    }
    if (!up) return fail("stream");
    const headers = new Headers();
    for (const name of ["content-type", "content-length", "content-range", "accept-ranges"]) {
      const v = up.headers.get(name);
      if (v) headers.set(name, v);
    }
    headers.set("Access-Control-Allow-Origin", "*");
    // 部署标记：验证新版是否上线时用（rev 2 = 含上游 URL 校验的版本）
    headers.set("X-Relay-Rev", "2");
    return new Response(up.body, { status: up.status, headers });
  });
}
