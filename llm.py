"""Minimal provider-agnostic LLM client (stdlib only, no agent frameworks).

Providers (LLM_PROVIDER):
  anthropic  - Anthropic Messages API           (ANTHROPIC_API_KEY)
  openai     - any OpenAI-compatible chat API   (OPENAI_API_KEY, optional OPENAI_BASE_URL)
               e.g. OpenAI, Groq, OpenRouter, Gemini's OpenAI endpoint, Ollama.
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request

DEFAULT_MODELS = {"anthropic": "claude-sonnet-5-5", "openai": "gpt-4o-mini"}
RETRYABLE = {408, 409, 429, 500, 502, 503, 504, 529}


class LLMError(RuntimeError):
    pass


class LLMClient:
    def __init__(self, provider: str | None = None, model: str | None = None,
                 api_key: str | None = None, base_url: str | None = None,
                 timeout: int = 120, max_retries: int = 6):
        self.provider = (provider or os.getenv("LLM_PROVIDER") or self._guess_provider()).lower()
        if self.provider not in DEFAULT_MODELS:
            raise LLMError(f"unsupported LLM_PROVIDER '{self.provider}' (use anthropic or openai)")
        self.model = model or os.getenv("LLM_MODEL") or DEFAULT_MODELS[self.provider]
        key_var = "ANTHROPIC_API_KEY" if self.provider == "anthropic" else "OPENAI_API_KEY"
        self.api_key = api_key or os.getenv(key_var)
        if not self.api_key:
            raise LLMError(f"missing {key_var}; copy .env.example to .env and set it")
        default_base = ("https://api.anthropic.com" if self.provider == "anthropic"
                        else "https://api.openai.com/v1")
        env_base = os.getenv("ANTHROPIC_BASE_URL" if self.provider == "anthropic" else "OPENAI_BASE_URL")
        self.base_url = (base_url or env_base or default_base).rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries

    @staticmethod
    def _guess_provider() -> str:
        if os.getenv("ANTHROPIC_API_KEY") and not os.getenv("OPENAI_API_KEY"):
            return "anthropic"
        return "openai" if os.getenv("OPENAI_API_KEY") else "anthropic"

    def chat(self, system: str, messages: list[dict], max_tokens: int = 4096) -> str:
        """messages: [{'role': 'user'|'assistant', 'content': str}, ...]. Returns reply text."""
        if self.provider == "anthropic":
            url = f"{self.base_url}/v1/messages"
            headers = {"x-api-key": self.api_key, "anthropic-version": "2023-06-01",
                       "content-type": "application/json"}
            body = {"model": self.model, "max_tokens": max_tokens, "system": system,
                    "messages": messages}
        else:
            url = f"{self.base_url}/chat/completions"
            headers = {"authorization": f"Bearer {self.api_key}", "content-type": "application/json"}
            body = {"model": self.model, "max_tokens": max_tokens, "temperature": 0,
                    "messages": [{"role": "system", "content": system}, *messages]}
        data = self._post(url, headers, body)
        try:
            if self.provider == "anthropic":
                return "".join(b.get("text", "") for b in data["content"] if b.get("type") == "text")
            return data["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError):
            raise LLMError(f"unexpected LLM response shape: {str(data)[:200]}")

    @staticmethod
    def _rate_limit_wait(retry_after: str | None, detail: str) -> float:
        """Seconds to wait after a 429: honour Retry-After or 'try again in 1.5s / 75ms / 2m3s'."""
        try:
            if retry_after:
                return min(float(retry_after) + 1, 70)
        except ValueError:
            pass
        m = re.search(r"try again in (?:(\d+)m(?!s))?(?:([\d.]+)s(?!\w))?(?:([\d.]+)ms)?", detail)
        if m and any(m.groups()):
            secs = int(m.group(1) or 0) * 60 + float(m.group(2) or 0) + float(m.group(3) or 0) / 1000
            return min(secs + 2, 70)
        return 20  # unknown 429: per-minute windows reset within ~a minute

    def _post(self, url: str, headers: dict, body: dict) -> dict:
        payload = json.dumps(body).encode()
        # Some providers' CDNs (e.g. Cloudflare in front of Groq) reject urllib's default User-Agent.
        headers = {"user-agent": "devops-audit-agent/1.0", "accept": "application/json", **headers}
        last = ""
        for attempt in range(self.max_retries + 1):
            req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    return json.loads(r.read().decode())
            except urllib.error.HTTPError as e:
                detail = e.read().decode(errors="replace")[:300]
                last = f"HTTP {e.code}: {detail}"
                if e.code not in RETRYABLE:
                    raise LLMError(last)
                wait = self._rate_limit_wait(e.headers.get("retry-after"), detail) if e.code == 429 else 0
            except (urllib.error.URLError, TimeoutError, ConnectionError, json.JSONDecodeError) as e:
                last = f"{type(e).__name__}: {e}"
                wait = 0
            if attempt < self.max_retries:
                time.sleep(max(wait, min(2 ** attempt * 2, 30)))
        raise LLMError(f"LLM request failed after retries: {last}")
