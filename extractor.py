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
        self.log("info", f"Checkout 完整响应: {json.dumps(co_data, ensure_ascii=False)[:500]}")

        # 提取关键参数
        cs_live = str(co_data.get("checkout_session_id", ""))
        publishable_key = str(co_data.get("publishable_key", ""))  # 注意拼写是 publishable
        processor_entity = str(co_data.get("processor_entity", "openai_llc"))
        checkout_ui_mode = str(co_data.get("checkout_ui_mode", ""))

        if not cs_live:
            self.log("warn", f"未找到 checkout_session_id")
            raise RuntimeError("未提取到 cs_live checkout session ID")

        self.log("ok", f"cs_live: {cs_live[:40]}...")
        self.log("info", f"publishable_key: {publishable_key[:30] if publishable_key else 'NOT FOUND'}...")
        self.log("info", f"processor_entity: {processor_entity}")
        self.log("info", f"checkout_ui_mode: {checkout_ui_mode}")
        return cs_live, access_token, session, publishable_key, processor_entity

    # ═══════════════════════════════════════════
    # 阶段2: Stripe/PayPal (US 代理)
    # ═══════════════════════════════════════════
    def step2_stripe_provider(self, cs_live: str, access_token: str, publishable_key: str = "") -> dict[str, Any]:
        self.log("info", "══════ 阶段2: Stripe/PayPal (US 代理) ══════")
        self.log("info", f"代理: {self._mask(self.us_proxy)}")
        self.log("info", f"Billing: US / {self.billing['city']} / {self.billing['state']}")
        session = self._make_session(self.us_proxy)

        if not publishable_key:
            self.log("error", "缺少 publishable_key，无法调用 Stripe API")
            return {"status": "no_pk"}

        stripe_headers = {
            "Authorization": f"Bearer {publishable_key}",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://checkout.stripe.com",
            "Referer": "https://checkout.stripe.com/",
        }

        # 2a. 尝试用 Stripe API 获取 checkout session 里的 setup_intent
        self.log("info", "获取 Stripe checkout session 信息...")
        setup_intent_id = ""
        client_secret = ""

        # 尝试 Stripe 公开 API
        for endpoint in [
            f"https://api.stripe.com/v1/checkout/sessions/{cs_live}/elements",
            f"https://api.stripe.com/v1/checkout/sessions/{cs_live}",
        ]:
            try:
                r = session.get(endpoint, headers={
                    "Authorization": f"Bearer {publishable_key}",
                    "Accept": "application/json",
                    "Origin": "https://checkout.stripe.com",
                }, timeout=20)
                self.log("info", f"Stripe API {endpoint.split('/')[-1]}: HTTP {r.status_code}")
                if r.status_code == 200:
                    try:
                        d = r.json()
                        # 提取 setup_intent 信息
                        si = d.get("setup_intent", d.get("setup_intent_id", ""))
                        if isinstance(si, dict):
                            setup_intent_id = si.get("id", "")
                            client_secret = si.get("client_secret", "")
                        elif isinstance(si, str) and si:
                            setup_intent_id = si
                        self.log("info", f"  setup_intent: {setup_intent_id[:30] if setup_intent_id else 'NOT FOUND'}")
                        if client_secret:
                            self.log("info", f"  client_secret: FOUND")
                            break
                    except Exception:
                        pass
            except Exception as e:
                self.log("info", f"  FAIL: {str(e)[:80]}")

        # 2b. 如果还不行，尝试从 Stripe checkout 页面提取
        if not client_secret:
            self.log("info", "从 Stripe 页面提取 setup_intent...")
            try:
                r = session.get(
                    f"https://checkout.stripe.com/c/pay/{cs_live}",
                    headers={"Accept": "text/html,application/xhtml+xml,*/*;q=0.8"},
                    allow_redirects=True,
                    timeout=30,
                )
                html = r.text or ""

                # 搜索各种可能的模式
                for pattern in [
                    r'"client_secret"\s*:\s*"([^"]+)"',
                    r'setup_intent_client_secret["\']?\s*[:=]\s*["\']([^"\']+)',
                    r'clientSecret["\']?\s*[:=]\s*["\'](seti_[^"\']+)',
                    r'"secret"\s*:\s*"(seti_[^"]+)"',
                ]:
                    m = re.search(pattern, html)
                    if m:
                        client_secret = m.group(1) if m.lastindex else m.group(0)
                        setup_intent_id = client_secret.split("_secret_")[0]
                        self.log("info", f"  从HTML提取: si={setup_intent_id[:30]}")
                        break

                # 尝试从 JS bundle 中提取 (更宽松的模式)
                if not client_secret:
                    for m in re.finditer(r'"seti_[^"]+_secret_[^"]+"', html):
                        val = m.group(0).strip('"')
                        if "_secret_" in val:
                            client_secret = val
                            setup_intent_id = val.split("_secret_")[0]
                            self.log("info", f"  从JS提取: si={setup_intent_id[:30]}")
                            break
            except Exception as e:
                self.log("warn", f"Stripe 页面提取失败: {e}")

        # 2c. 创建 PayPal payment_method
        payment_method_id = ""
        if publishable_key and (client_secret or setup_intent_id):
            self.log("info", "创建 PayPal payment_method...")
            pm_data = {
                "type": "paypal",
                "billing_details[address][country]": self.billing["country"],
                "billing_details[address][line1]": self.billing["line1"],
                "billing_details[address][city]": self.billing["city"],
                "billing_details[address][state]": self.billing["state"],
                "billing_details[address][postal_code]": self.billing["postal_code"],
            }
            pm_resp = session.post(
                "https://api.stripe.com/v1/payment_methods",
                data=pm_data,
                headers=stripe_headers,
                timeout=30,
            )
            self.log("info", f"PaymentMethod: HTTP {pm_resp.status_code}")
            if pm_resp.status_code == 200:
                pm = pm_resp.json()
                payment_method_id = pm.get("id", "")
                self.log("ok", f"PM ID: {payment_method_id}")

            # 2d. Confirm SetupIntent with payment method
            if payment_method_id and client_secret:
                self.log("info", f"Confirm SetupIntent {setup_intent_id[:30]}...")
                si_id = client_secret.split("_secret_")[0]
                confirm_resp = session.post(
                    f"https://api.stripe.com/v1/setup_intents/{si_id}/confirm",
                    data={
                        "payment_method": payment_method_id,
                        "client_secret": client_secret,
                    },
                    headers=stripe_headers,
                    timeout=30,
                )
                self.log("info", f"SetupIntent confirm: HTTP {confirm_resp.status_code}")
                try:
                    si_data = confirm_resp.json()
                    si_status = si_data.get("status", "")
                    self.log("info", f"SI status: {si_status}")
                    self.log("info", f"SI response: {json.dumps(si_data, ensure_ascii=False)[:400]}")

                    if si_status == "requires_action":
                        next_action = si_data.get("next_action", {})
                        redirect = next_action.get("redirect_to_url", {}).get("url", "")
                        if redirect:
                            self.log("ok", f"PayPal redirect: {redirect[:150]}")
                            return {"status": "requires_action", "paypal_url": redirect}
                    elif si_status == "succeeded":
                        self.log("ok", "SetupIntent succeeded!")
                        return {"status": "requires_approval", "setup_intent_id": si_id}
                    elif si_status == "processing":
                        self.log("info", "SetupIntent processing...")
                        return {"status": "processing", "setup_intent_id": si_id}
                except Exception as e:
                    self.log("warn", f"Confirm parse error: {e}")
        else:
            missing = []
            if not publishable_key: missing.append("pk")
            if not client_secret: missing.append("si_secret")
            self.log("warn", f"缺少参数: {missing}")

        return {"status": "provider_not_set", "payment_method_id": payment_method_id}

        # 2d. 提取 JSON 数据块 (Stripe 经常把配置放在 script 标签里)
        json_data = {}
        for m in re.finditer(r'\{[^}]+"publishableKey"[^}]+\}', html):
            try:
                json_data = json.loads(m.group(0))
                break
            except Exception:
                pass
        if not json_data:
            for m in re.finditer(r'window\.__stripeAppData\s*=\s*(\{[^<]+\})', html):
                try:
                    json_data = json.loads(m.group(1))
                    break
                except Exception:
                    pass
        if json_data:
            if not pub_key:
                pub_key = json_data.get("publishableKey", "")
            if not si_secret:
                si_secret = json_data.get("clientSecret", json_data.get("client_secret", ""))
            self.log("info", f"JSON data extracted: keys={list(json_data.keys())[:5]}")

        # 2e. 如果有 pub_key 和 si_secret，调用 Stripe API 创建 PayPal payment_method
        payment_method_id = ""
        if pub_key and si_secret:
            self.log("info", "调用 Stripe API: 创建 PayPal payment_method...")
            stripe_headers = {
                "Authorization": f"Bearer {pub_key}",
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": "https://checkout.stripe.com",
                "Referer": final_url,
            }
            pm_data = {
                "type": "paypal",
                "billing_details[address][country]": self.billing["country"],
                "billing_details[address][line1]": self.billing["line1"],
                "billing_details[address][city]": self.billing["city"],
                "billing_details[address][state]": self.billing["state"],
                "billing_details[address][postal_code]": self.billing["postal_code"],
            }
            pm_resp = session.post(
                "https://api.stripe.com/v1/payment_methods",
                data=pm_data,
                headers=stripe_headers,
                timeout=30,
            )
            self.log("info", f"PaymentMethod: HTTP {pm_resp.status_code}")
            if pm_resp.status_code == 200:
                pm_json = pm_resp.json()
                payment_method_id = pm_json.get("id", "")
                self.log("ok", f"PaymentMethod ID: {payment_method_id}")

            # 2f. 确认 SetupIntent
            if payment_method_id:
                self.log("info", "调用 Stripe API: confirm SetupIntent...")
                si_id = si_secret.split("_secret_")[0]
                confirm_resp = session.post(
                    f"https://api.stripe.com/v1/setup_intents/{si_id}/confirm",
                    data={
                        "payment_method": payment_method_id,
                        "client_secret": si_secret,
                    },
                    headers=stripe_headers,
                    timeout=30,
                )
                self.log("info", f"SetupIntent confirm: HTTP {confirm_resp.status_code}")
                try:
                    si_data = confirm_resp.json()
                    si_status = si_data.get("status", "")
                    self.log("info", f"SetupIntent status: {si_status}")
                    if si_status == "requires_action":
                        # PayPal redirect needed
                        next_action = si_data.get("next_action", {})
                        redirect_url = next_action.get("redirect_to_url", {}).get("url", "")
                        if redirect_url:
                            self.log("ok", f"PayPal redirect: {redirect_url[:120]}")
                            return {"status": "requires_action", "paypal_url": redirect_url, "pub_key": pub_key, "payment_method_id": payment_method_id}
                except Exception as e:
                    self.log("warn", f"SetupIntent parse: {e}")
        else:
            self.log("warn", f"缺少 Stripe 参数 pk={bool(pub_key)} si={bool(si_secret)}")
            # Dump relevant HTML parts for debugging
            snippets = re.findall(r'(?:pk_|publishableKey|setup_intent|client_secret|stripe)[^"]*["\']([^"\']+)["\']', html, re.I)
            if snippets:
                self.log("info", f"HTML hints: {snippets[:5]}")

        return {
            "final_url": final_url,
            "pub_key": pub_key,
            "payment_method_id": payment_method_id,
            "status": "requires_approval" if payment_method_id else "incomplete",
        }

    # ═══════════════════════════════════════════
    # 阶段3: Approve (JP 代理)
    # ═══════════════════════════════════════════
    def step3_approve(self, cs_live: str, access_token: str, processor_entity: str = "openai_llc") -> dict[str, Any]:
        self.log("info", "══════ 阶段3: ChatGPT Approve (JP 代理) ══════")
        self.log("info", f"processor_entity: {processor_entity}")
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

        # 尝试 approve — processor_entity 必须是 'openai_llc' 或 'openai_ie'
        payloads = [
            {"checkout_session_id": cs_live, "processor_entity": processor_entity},
            {"checkout_session_id": cs_live, "processor_entity": "openai_llc"},
            {"checkout_session_id": cs_live, "processor_entity": "openai_ie"},
        ]

        for payload in payloads:
            for attempt in range(1, 4):
                pe = payload.get("processor_entity", "?")
                self.log("info", f"Approve processor_entity={pe} 尝试 {attempt}/3...")
                resp = session.post(
                    f"{CHATGPT_BASE}/backend-api/payments/checkout/approve",
                    json=payload,
                    headers=headers,
                    timeout=30,
                )
                resp_text = resp.text[:500]
                self.log("info", f"Approve: HTTP {resp.status_code}")
                self.log("info", f"  body: {resp_text}")
                try:
                    data = resp.json()
                    result = str(data.get("result", "") if isinstance(data, dict) else "")
                    if result == "approved":
                        self.log("ok", f"Approve 成功!")
                        return {"ok": True, "data": data}
                    for key in ("return_url", "url", "redirect_url", "paypal_url", "next_url"):
                        val = data.get(key, "") if isinstance(data, dict) else ""
                        if val:
                            self.log("ok", f"获取到 URL: {val[:120]}")
                            return {"ok": True, "data": data, "return_url": val}
                    # 如果是 422 enum 错误，跳过这个 payload
                    if resp.status_code == 422 and "enum" in resp_text:
                        self.log("info", f"  processor_entity={pe} 不支持，跳过")
                        break
                except Exception:
                    pass
                time.sleep(1)

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
            cs_live, at, _, pub_key, processor_entity = self.step1_create_checkout(access_token)
            results["stages"]["checkout"] = {"cs_live": cs_live, "pub_key": pub_key[:30]+"...", "processor_entity": processor_entity}

            provider = self.step2_stripe_provider(cs_live, at, publishable_key=pub_key)
            results["stages"]["provider"] = provider

            # 如果阶段2直接返回了 PayPal redirect URL，优先提取
            paypal_url = provider.get("paypal_url", "")

            approve = self.step3_approve(cs_live, at, processor_entity=processor_entity)
            results["stages"]["approve"] = approve
            # 检查 approve 是否直接返回了 URL
            if not paypal_url and approve.get("return_url"):
                paypal_url = approve.get("return_url", "")

            chain = self.step4_extract_chain(cs_live, at)
            results["stages"]["chain"] = {"paypal_ba": chain}

            # 合并结果
            final_chain = chain or paypal_url
            if final_chain:
                results["success"] = True
                results["paypal_ba_chain"] = final_chain
                self.log("ok", "========== 全流程完成: PayPal BA 链提取成功! ==========")
            elif approve.get("ok"):
                results["success"] = True
                results["message"] = "Approve 成功，请手动提取链"
                self.log("ok", "========== 全流程完成: Approve OK ==========")
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