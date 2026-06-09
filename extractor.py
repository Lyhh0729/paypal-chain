"""PayPal BA 链提取核心引擎 —— 3阶段代理切换"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import random
import re
import secrets
import time
import uuid
from datetime import datetime
from typing import Any, Callable
from urllib.parse import urlparse, urlencode, parse_qs

from curl_cffi import requests as curl_requests

try:
    from curl_cffi.const import CurlHttpVersion
except Exception:
    CurlHttpVersion = None

CHATGPT_BASE = "https://chatgpt.com"
AUTH_BASE = "https://auth.openai.com"
OAUTH_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
OAUTH_REDIRECT_URI = "http://localhost:1455/auth/callback"
OAUTH_SCOPE = "openid profile email offline_access api.connectors.read api.connectors.invoke"

_SCREEN_SIZES = ["1440x900", "1920x1080", "1536x864", "1920x1200"]
_HW = [8, 12, 16]

_FINGERPRINTS = [
    {
        "impersonate": "chrome131",
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="99"',
        "accept_language": "en-US,en;q=0.9",
        "screen": "1440x900",
        "hw": 8,
    },
    {
        "impersonate": "chrome131",
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="99"',
        "accept_language": "en-GB,en;q=0.9",
        "screen": "1920x1080",
        "hw": 12,
    },
]


def load_config() -> dict[str, Any]:
    path = os.path.join(os.path.dirname(__file__), "config.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


class PayPalChainExtractor:
    """PayPal BA 链提取器 —— 三阶段代理切换"""

    def __init__(
        self,
        log_fn: Callable[[str, str], None],
        jp_proxy: str | None = None,
        us_proxy: str | None = None,
    ):
        self.log = log_fn
        cfg = load_config()
        self.jp_proxy = jp_proxy or cfg["jp_proxy"]
        self.us_proxy = us_proxy or cfg["us_proxy"]
        self.billing = cfg["billing_address"]
        self.poll_interval = cfg.get("poll_interval", 2)
        self.poll_max = cfg.get("poll_max_attempts", 30)

        self.device_id = str(uuid.uuid4())
        fp = random.choice(_FINGERPRINTS)
        self.impersonate = fp["impersonate"]
        self.ua = fp["ua"]
        self.sec_ch_ua = fp["sec_ch_ua"]
        self.accept_language = fp["accept_language"]
        self.screen = fp["screen"]
        self.hw = fp["hw"]

    def _make_session(self, proxy: str | None) -> curl_requests.Session:
        s = curl_requests.Session(impersonate=self.impersonate)
        if CurlHttpVersion is not None:
            try:
                s.http_version = CurlHttpVersion.V1_1
            except Exception:
                pass
        if proxy:
            s.proxies = {"http": proxy, "https": proxy}
        s.headers.update(
            {
                "User-Agent": self.ua,
                "Accept-Language": self.accept_language,
                "sec-ch-ua": self.sec_ch_ua,
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"Windows"',
            }
        )
        return s

    def _make_trace_headers(self) -> dict[str, str]:
        trace_id = random.randint(10**17, 10**18 - 1)
        parent_id = random.randint(10**17, 10**18 - 1)
        return {
            "traceparent": f"00-{uuid.uuid4().hex}-{format(parent_id, '016x')}-01",
            "tracestate": "dd=s:1;o:rum",
            "x-datadog-origin": "rum",
            "x-datadog-sampling-priority": "1",
            "x-datadog-trace-id": str(trace_id),
            "x-datadog-parent-id": str(parent_id),
        }

    def _build_sentinel(self, session: curl_requests.Session, flow: str = "authorize_continue") -> str | None:
        try:
            screen = self.screen
            ua = self.ua
            now_str = time.strftime("%a %b %d %Y %H:%M:%S GMT+0000 (Coordinated Universal Time)", time.gmtime())
            perf_now = random.uniform(1000, 50000)
            time_origin = time.time() * 1000 - perf_now
            config = [
                screen, now_str, 4294705152, 1.0, ua,
                "https://sentinel.openai.com/sentinel/20260124ceb8/sdk.js",
                None, None, "en-US", self.accept_language, random.random(),
                "vendorSub-undefined", "location", "Object",
                perf_now, str(uuid.uuid4()), "", self.hw, time_origin,
            ]
            raw = json.dumps(config, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            p_value = "gAAAAAC" + base64.b64encode(raw).decode("ascii")

            gen_body = {"p": p_value, "id": self.device_id, "flow": flow}
            gen_headers = {
                "Content-Type": "text/plain;charset=UTF-8",
                "Referer": "https://sentinel.openai.com/backend-api/sentinel/frame.html",
                "Origin": "https://sentinel.openai.com",
            }
            resp = session.post(
                "https://sentinel.openai.com/backend-api/sentinel/req",
                data=json.dumps(gen_body),
                headers=gen_headers,
                timeout=20,
            )
            if resp.status_code != 200:
                return None
            data = resp.json()
            if not isinstance(data, dict) or not data.get("token"):
                return None
            c_value = data["token"]
            return json.dumps(
                {"p": p_value, "t": "", "c": c_value, "id": self.device_id, "flow": flow},
                separators=(",", ":"),
            )
        except Exception:
            return None

    # ═══════════════════════════════════════════
    # 阶段1: 创建 Checkout (JP 代理)
    # ═══════════════════════════════════════════
    def step1_create_checkout(self, access_token: str) -> tuple[str, str, Any]:
        self.log("info", "══════ 阶段1: 创建 Checkout (JP 代理) ══════")
        self.log("info", f"代理: {self._mask(self.jp_proxy)}")
        session = self._make_session(self.jp_proxy)

        # 1a. 访问首页
        self.log("info", "访问 ChatGPT 首页...")
        resp = session.get(
            f"{CHATGPT_BASE}/",
            headers={"Accept": "text/html,application/xhtml+xml,*/*;q=0.8", "Upgrade-Insecure-Requests": "1"},
            allow_redirects=True,
            timeout=30,
        )
        self.log("info", f"首页: HTTP {resp.status_code}")

        # 1b. 获取 CSRF
        self.log("info", "获取 CSRF token...")
        csrf_resp = session.get(
            f"{CHATGPT_BASE}/api/auth/csrf",
            headers={"Accept": "application/json", "Referer": f"{CHATGPT_BASE}/"},
            timeout=30,
        )
        csrf_data = csrf_resp.json()
        csrf = str(csrf_data.get("csrfToken", ""))
        if not csrf:
            raise RuntimeError("缺少 csrfToken")
        self.log("info", f"CSRF: {csrf[:16]}...")

        # 1c. 使用 access_token 获取 session
        self.log("info", "验证 access token...")
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
            "Origin": CHATGPT_BASE,
            "Referer": f"{CHATGPT_BASE}/",
            "oai-device-id": self.device_id,
        }
        headers.update(self._make_trace_headers())

        me_resp = session.get(
            f"{CHATGPT_BASE}/backend-api/me",
            headers=headers,
            timeout=30,
        )
        if me_resp.status_code != 200:
            raise RuntimeError(f"access_token 无效: HTTP {me_resp.status_code}")
        me_data = me_resp.json()
        self.log("info", f"用户: {me_data.get('email', me_data.get('id', '?'))}")

        # 1d. accounts/check
        self.log("info", "检查账户状态...")
        chk_resp = session.get(
            f"{CHATGPT_BASE}/backend-api/accounts/check/v4-2023-04-27?timezone_offset_min=-480",
            headers=headers,
            timeout=30,
        )
        chk_data = chk_resp.json() if chk_resp.status_code == 200 else {}
        accounts = chk_data.get("accounts", {}) if isinstance(chk_data, dict) else {}
        account_id = next(iter(accounts.keys()), "")
        self.log("info", f"AccountID: {account_id[:16] if account_id else '?'}")

        # 1e. 创建 checkout
        self.log("info", "创建 promo checkout (country=US, currency=USD)...")
        checkout_headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Origin": CHATGPT_BASE,
            "Referer": f"{CHATGPT_BASE}/",
            "oai-device-id": self.device_id,
        }
        checkout_headers.update(self._make_trace_headers())

        checkout_resp = session.post(
            f"{CHATGPT_BASE}/backend-api/payments/checkout",
            json={"country": "US", "currency": "USD"},
            headers=checkout_headers,
            timeout=30,
        )
        self.log("info", f"Checkout API: HTTP {checkout_resp.status_code}")
        co_data = checkout_resp.json() if checkout_resp.status_code == 200 else {}

        # 提取 cs_live
        cs_live = ""
        if isinstance(co_data, dict):
            cs_live = str(co_data.get("checkout_session_id") or co_data.get("cs_live", ""))
            if not cs_live:
                url = str(co_data.get("url", ""))
                if url:
                    m = re.search(r"cs_live_[a-zA-Z0-9]+", url)
                    if m:
                        cs_live = m.group(0)

        if not cs_live:
            self.log("warn", f"Checkout 响应: {json.dumps(co_data, ensure_ascii=False)[:300]}")
            raise RuntimeError("未提取到 cs_live checkout session ID")

        self.log("ok", f"cs_live: {cs_live[:40]}...")
        return cs_live, access_token, session

    # ═══════════════════════════════════════════
    # 阶段2: Stripe/PayPal (US 代理)
    # ═══════════════════════════════════════════
    def step2_stripe_provider(self, cs_live: str, access_token: str) -> dict[str, Any]:
        self.log("info", "══════ 阶段2: Stripe/PayPal (US 代理) ══════")
        self.log("info", f"代理: {self._mask(self.us_proxy)}")
        self.log("info", f"Billing: US / {self.billing['city']} / {self.billing['state']}")
        session = self._make_session(self.us_proxy)

        # 2a. 访问 Stripe checkout 页面
        stripe_url = f"https://checkout.stripe.com/c/pay/{cs_live}"
        self.log("info", f"Stripe checkout: {stripe_url[:70]}...")

        resp = session.get(
            stripe_url,
            headers={"Accept": "text/html,application/xhtml+xml,*/*;q=0.8", "Upgrade-Insecure-Requests": "1"},
            allow_redirects=True,
            timeout=30,
        )
        final_url = str(resp.url)
        html = resp.text or ""
        self.log("info", f"Stripe 页面: HTTP {resp.status_code}")

        # 2b. 提取 Stripe 关键参数
        pub_key = ""
        m = re.search(r'pk_live_[a-zA-Z0-9]+', html)
        if m:
            pub_key = m.group(0)
        self.log("info", f"Stripe pk: {'FOUND' if pub_key else 'NOT FOUND'}")

        si_secret = ""
        m = re.search(r"setup_intent_client_secret['\"]?\s*[:=]\s*['\"]([^'\"]+)", html)
        if m:
            si_secret = m.group(1)
            self.log("info", f"SetupIntent secret: FOUND ({si_secret[:10]}...)")

        # 2c. 模拟 PayPal 支付方式创建
        self.log("info", "创建 PayPal payment_method (billing=US)...")
        self.log("info", f"  country={self.billing['country']} city={self.billing['city']} state={self.billing['state']}")

        # 尝试从页面提取更多信息
        checkout_session_match = re.search(r"checkout_session['\"]?\s*[:=]\s*['\"]([^'\"]+)", html)
        if checkout_session_match:
            self.log("info", f"CheckoutSession: {checkout_session_match.group(1)[:20]}...")

        return {
            "final_url": final_url,
            "pub_key": pub_key,
            "has_setup_intent": bool(si_secret),
            "status": "requires_approval",
        }

    # ═══════════════════════════════════════════
    # 阶段3: Approve (JP 代理)
    # ═══════════════════════════════════════════
    def step3_approve(self, cs_live: str, access_token: str) -> dict[str, Any]:
        self.log("info", "══════ 阶段3: ChatGPT Approve (JP 代理) ══════")
        session = self._make_session(self.jp_proxy)

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Origin": CHATGPT_BASE,
            "Referer": f"{CHATGPT_BASE}/",
            "oai-device-id": self.device_id,
        }
        headers.update(self._make_trace_headers())

        for attempt in range(1, 6):
            self.log("info", f"Approve 尝试 {attempt}/5...")
            resp = session.post(
                f"{CHATGPT_BASE}/backend-api/payments/checkout/approve",
                json={"checkout_session_id": cs_live},
                headers=headers,
                timeout=30,
            )
            self.log("info", f"Approve: HTTP {resp.status_code}")
            try:
                data = resp.json()
                result = str(data.get("result", "") if isinstance(data, dict) else "")
                self.log("info", f"  result: {result}")
                if result == "approved":
                    self.log("ok", "Approve 成功!")
                    return {"ok": True, "data": data}
            except Exception:
                pass
            time.sleep(2)

        self.log("warn", "Approve 未返回 approved")
        return {"ok": False, "data": {}}

    # ═══════════════════════════════════════════
    # 阶段4: 提取 PayPal BA 链
    # ═══════════════════════════════════════════
    def step4_extract_chain(self, cs_live: str, access_token: str) -> str | None:
        self.log("info", "══════ 阶段4: 提取 PayPal BA 链 ══════")
        session = self._make_session(self.jp_proxy)

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
            "Origin": CHATGPT_BASE,
            "Referer": f"{CHATGPT_BASE}/",
            "oai-device-id": self.device_id,
        }
        headers.update(self._make_trace_headers())

        for i in range(1, self.poll_max + 1):
            self.log("info", f"轮询 {i}/{self.poll_max}...")
            resp = session.get(
                f"{CHATGPT_BASE}/backend-api/payments/checkout/{cs_live}",
                headers=headers,
                timeout=30,
            )
            try:
                data = resp.json()
                if isinstance(data, dict):
                    status = data.get("status", "")
                    return_url = data.get("return_url", "")
                    self.log("info", f"  status: {status}")
                    if return_url:
                        self.log("ok", f"PayPal BA 链: {return_url[:120]}")
                        return return_url
                    # 也尝试从其他字段提取
                    for key in ("paypal_url", "redirect_url", "approval_url", "ba_link"):
                        val = data.get(key, "")
                        if val and "paypal" in str(val).lower():
                            self.log("ok", f"PayPal BA 链 ({key}): {str(val)[:120]}")
                            return str(val)
            except Exception:
                pass
            time.sleep(self.poll_interval)

        self.log("warn", "未能提取 PayPal BA 链")
        return None

    # ═══════════════════════════════════════════
    # 全流程执行
    # ═══════════════════════════════════════════
    def run(self, access_token: str) -> dict[str, Any]:
        results: dict[str, Any] = {"stages": {}, "success": False}
        try:
            cs_live, at, _ = self.step1_create_checkout(access_token)
            results["stages"]["checkout"] = {"cs_live": cs_live}

            provider = self.step2_stripe_provider(cs_live, at)
            results["stages"]["provider"] = provider

            approve = self.step3_approve(cs_live, at)
            results["stages"]["approve"] = approve

            chain = self.step4_extract_chain(cs_live, at)
            results["stages"]["chain"] = {"paypal_ba": chain}
            if chain:
                results["success"] = True
                results["paypal_ba_chain"] = chain
                self.log("ok", "========== 全流程完成: PayPal BA 链提取成功! ==========")
            else:
                results["error"] = "未能提取 PayPal BA 链"
                self.log("error", "全流程完成但未提取到链")
            return results
        except Exception as e:
            results["error"] = f"{type(e).__name__}: {e}"
            self.log("error", f"流程异常: {results['error']}")
            return results

    @staticmethod
    def _mask(url: str) -> str:
        if not url:
            return "DIRECT"
        try:
            p = urlparse(url if "://" in url else f"http://{url}")
            host = p.hostname or ""
            return f"{p.scheme}://***@{host}:{p.port or '?'}"
        except Exception:
            return url[:30] + "..."