#!/usr/bin/env python3
"""
Control iD Monitor – cache de token + de-dup por ID (HWM) + VERBOSE/DEBUG
------------------------------------------------------------------------
- Login com usuário/senha em /api/login/ (ou usa token do cache).
- Salva token (TTL) em ~/.cache/controlid/token.json.
- 401 => limpa cache, reloga e continua.
- Monitora /api/access/monitor com os mesmos parâmetros do Bash.
- Evita duplicados com high-water mark (HWM) do maior ID visto.
- ID do evento configurável: --event-id-field (default: idLog)
- Flags de debug:
  * -v / --verbose        : logs de alto nível (params, cursors, contagens, ids)
  * --debug-http          : liga logging do httpx (requests/responses)
  * --log-body            : loga um trecho do corpo da resposta (aprox. 2 KB)
Exemplo:
python monitor.py \
  --base-url https://seu-software-controlid.seudominio.com \
  --events-endpoint /api/access/monitor \
  --auth-kind password --auth-endpoint /api/login/ --auth-ttl 8h \
  --since-param time --id-param modevalue --limit-param limite --limit 15 \
  -P mode=loop -P areas= -P events= -P parkings= \
  --initial-since "$(date -u +'%Y-%m-%dT00:00:00.000Z')" \
  --initial-after-id 0 \
  --event-id-field idLog \
  --print-format human \
  -v --debug-http --log-body
"""

import argparse
import asyncio
import json
import os
import re
import signal
import sqlite3
import time
import pathlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from getpass import getpass
from typing import Any, Dict, List, Optional, Tuple

import httpx

# ---------------- Logging helpers ----------------

LOGGER = logging.getLogger("controlid.monitor")

def setup_logging(verbose: bool, debug_http: bool):
    level = logging.DEBUG if (verbose or debug_http) else logging.INFO
    # Evite duplicação de handlers em re-runs
    if not logging.getLogger().handlers:
        logging.basicConfig(
            level=level,
            format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    else:
        logging.getLogger().setLevel(level)
    # httpx logs (detalhes de requests/responses)
    if debug_http:
        logging.getLogger("httpx").setLevel(logging.DEBUG)
        logging.getLogger("httpcore").setLevel(logging.DEBUG)
        logging.getLogger("hpack").setLevel(logging.DEBUG)
    else:
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("httpcore").setLevel(logging.WARNING)
        logging.getLogger("hpack").setLevel(logging.WARNING)

def redact(s: str) -> str:
    if not s:
        return s
    s = re.sub(r"(Authorization:\s*Bearer\s+)([A-Za-z0-9\-\._]+)", r"\1***REDACTED***", s, flags=re.I)
    s = re.sub(r"(accessToken\"\s*:\s*\")([^\"]+)", r"\1***REDACTED***", s, flags=re.I)
    return s

# ---------------- Utilities ----------------

def parse_duration(s: str) -> float:
    """
    Aceita: '500ms', '2s', '5m', '8h' ou apenas números (em segundos).
    """
    if s is None:
        raise ValueError("Duração não informada")
    s = str(s).strip().lower()
    if s.isdigit():
        return float(int(s))
    m = re.fullmatch(r"(\d+(?:\.\d+)?)(ms|s|m|h)", s)
    if not m:
        raise ValueError(f"Duração inválida: {s}")
    val, unit = m.groups()
    val = float(val)
    if unit == "ms":
        return val / 1000.0
    if unit == "s":
        return val
    if unit == "m":
        return val * 60.0
    if unit == "h":
        return val * 3600.0
    raise ValueError(f"Unidade inválida: {unit}")

def dotnet_to_iso_utc(dotnet: str) -> str:
    """
    Converte '/Date(1724123456789-0300)/' -> 'YYYY-MM-DDTHH:MM:SS.000Z' (UTC).
    """
    m = re.search(r"/Date\((\d+)([+-]\d{4})?\)/", dotnet)
    if not m:
        return dotnet
    ms = int(m.group(1))
    dt = datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")

def parse_dotnet_date(s: str):
    """Converte '/Date(1724123456789-0300)/' ou '/Date(1724123456789)/' em datetime (UTC)."""
    try:
        m = re.search(r"/Date\((\d+)([+-]\d{4})?\)/", s)
        if not m:
            return None
        ms = int(m.group(1))
        # O valor é epoch ms; tratamos como UTC.
        return datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
    except Exception:
        return None

def ensure_cache_dir() -> pathlib.Path:
    home = pathlib.Path(os.path.expanduser("~"))
    cache_dir = home / ".cache" / "controlid"
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir

# ---------------- Config ----------------

@dataclass
class AuthConfig:
    kind: str = "none"  # none | bearer | password
    token: Optional[str] = None
    endpoint: str = "/api/login/"
    user: Optional[str] = None
    password: Optional[str] = None
    payload_format: str = "json"  # json | form
    extra_payload: Dict[str, Any] = field(default_factory=dict)
    token_path: str = "accessToken"
    cache_path: Optional[str] = None  # default ~/.cache/controlid/token.json
    ttl_sec: float = 8 * 3600  # 8h default

@dataclass
class PollConfig:
    base_url: str = ""
    events_endpoint: str = "/api/access/monitor"
    interval_sec: float = 2.0
    verify_ssl: bool = True
    extra_params: Dict[str, str] = field(default_factory=dict)
    since_param: str = "time"
    id_param: str = "modevalue"
    limit_param: str = "limite"
    limit_value: Optional[int] = 15
    initial_since: Optional[str] = None
    initial_after_id: Optional[str] = None
    event_id_field: str = "idLog"  # <— NOVO

@dataclass
class OutputConfig:
    jsonl_path: Optional[str] = None
    print_format: str = "human"  # human | json
    timezone: str = "local"      # local | utc
    verbose: bool = False
    debug_http: bool = False
    log_body: bool = False

@dataclass
class StateConfig:
    state_db_path: str = "monitor_state.sqlite"
    namespace: str = "default"

# ---------------- State ----------------

class StateStore:
    def __init__(self, cfg: StateConfig):
        self.path = cfg.state_db_path
        self.ns = cfg.namespace
        self._ensure_schema()

    def _ensure_schema(self):
        con = sqlite3.connect(self.path)
        try:
            cur = con.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS cursors (
                  namespace TEXT PRIMARY KEY,
                  last_id TEXT,
                  last_since TEXT
                )
            """)
            con.commit()
        finally:
            con.close()

    def get(self) -> Tuple[Optional[str], Optional[str]]:
        con = sqlite3.connect(self.path)
        try:
            cur = con.cursor()
            cur.execute("SELECT last_id, last_since FROM cursors WHERE namespace=?", (self.ns,))
            row = cur.fetchone()
            if row:
                return row[0], row[1]
            return None, None
        finally:
            con.close()

    def set(self, last_id: Optional[str], last_since: Optional[str]):
        con = sqlite3.connect(self.path)
        try:
            cur = con.cursor()
            cur.execute("""
                INSERT INTO cursors (namespace, last_id, last_since)
                VALUES (?, ?, ?)
                ON CONFLICT(namespace) DO UPDATE
                SET last_id=excluded.last_id, last_since=excluded.last_since
            """, (self.ns, last_id, last_since))
            con.commit()
        finally:
            con.close()

# ---------------- Monitor ----------------

class Monitor:
    def __init__(self, auth: AuthConfig, poll: PollConfig, output: OutputConfig, state_cfg: StateConfig):
        self.auth = auth
        self.poll = poll
        self.output = output
        self.state = StateStore(state_cfg)
        self.stop_event = asyncio.Event()
        self.client: Optional[httpx.AsyncClient] = None
        self.last_id: Optional[str] = None
        self.last_since: Optional[str] = None
        self.jsonl_fd = None
        # High-water mark para evitar duplicados
        self.hwm_id: int = -1

    async def __aenter__(self):
        self.client = httpx.AsyncClient(http2=True, verify=self.poll.verify_ssl, timeout=30.0)
        self.last_id, self.last_since = self.state.get()
        try:
            if self.last_id is not None:
                self.hwm_id = int(str(self.last_id))
        except ValueError:
            self.hwm_id = -1

        if self.output.jsonl_path:
            self.jsonl_fd = open(self.output.jsonl_path, "a", encoding="utf-8")

        if self.output.verbose:
            LOGGER.info("Iniciando monitor | base=%s | endpoint=%s", self.poll.base_url, self.poll.events_endpoint)
            LOGGER.info("Estado inicial | last_id=%s (HWM=%s) | last_since=%s",
                        self.last_id, self.hwm_id, self.last_since)

        await self._maybe_login()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self.client:
            await self.client.aclose()
        if self.jsonl_fd:
            self.jsonl_fd.close()

    # ---------- Auth & Cache ----------
    def _cache_file(self) -> pathlib.Path:
        if self.auth.cache_path:
            return pathlib.Path(self.auth.cache_path)
        return ensure_cache_dir() / "token.json"

    def _read_cache(self) -> Optional[Dict[str, Any]]:
        fp = self._cache_file()
        if not fp.exists():
            return None
        try:
            data = json.loads(fp.read_text(encoding="utf-8"))
            return data
        except Exception:
            return None

    def _write_cache(self, data: Dict[str, Any]):
        fp = self._cache_file()
        fp.parent.mkdir(parents=True, exist_ok=True)
        tmp = fp.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, fp)

    def _cache_key(self) -> str:
        return self.poll.base_url.rstrip("/")

    def _get_cached_token(self) -> Optional[str]:
        data = self._read_cache()
        if not data:
            return None
        key = self._cache_key()
        item = data.get(key)
        if not item:
            return None
        token = item.get("token")
        exp = item.get("expires_at")
        if not token or not exp:
            return None
        try:
            exp_dt = datetime.fromisoformat(exp.replace("Z", "+00:00"))
            if datetime.now(timezone.utc) < exp_dt:
                return token
            return None
        except Exception:
            return None

    def _save_cached_token(self, token: str):
        exp_dt = datetime.now(timezone.utc) + timedelta(seconds=self.auth.ttl_sec)
        data = self._read_cache() or {}
        data[self._cache_key()] = {
            "token": token,
            "expires_at": exp_dt.isoformat(),
        }
        self._write_cache(data)

    async def _maybe_login(self):
        if self.auth.kind == "bearer" and self.auth.token:
            if self.output.verbose:
                LOGGER.info("Autenticação: usando token fornecido (bearer)")
            return

        if self.auth.kind == "password":
            cached = self._get_cached_token()
            if cached:
                self.auth.token = cached
                if self.output.verbose:
                    LOGGER.info("Autenticação: usando token do cache")
                return
            if self.output.verbose:
                LOGGER.info("Autenticação: cache vazio, realizando login (password)")
            await self._login_password()
            return

    async def _login_password(self):
        assert self.client is not None
        url = self.poll.base_url.rstrip("/") + self.auth.endpoint
        headers = {"Accept": "application/json"}
        user = self.auth.user or input("Username: ")
        pw = self.auth.password or getpass("Password: ")
        payload = {"username": user, "password": pw, "passwordCustom": None, **self.auth.extra_payload}

        if self.output.verbose:
            LOGGER.info("POST %s (login) | headers=%s | payload=%s",
                        url, "{Accept: application/json}", redact(json.dumps(payload)))

        t0 = time.time()
        if self.auth.payload_format == "json":
            r = await self.client.post(url, json=payload, headers=headers)
        else:
            r = await self.client.post(url, data=payload, headers=headers)
        dt = (time.time() - t0) * 1000
        if self.output.verbose:
            LOGGER.info("Login resposta | status=%s | tempo=%.1fms", r.status_code, dt)

        r.raise_for_status()
        body = r.text or ""
        if self.output.log_body:
            LOGGER.debug("Login body (redacted): %s", redact(body[:2048]))

        data = r.json()
        token = data
        for key in self.auth.token_path.split("."):
            token = token.get(key) if isinstance(token, dict) else None
        if not token:
            raise RuntimeError(f"Não foi possível extrair token em '{self.auth.token_path}'")
        self.auth.token = str(token)
        self._save_cached_token(self.auth.token)
        if self.output.verbose:
            LOGGER.info("Login OK | token armazenado no cache (TTL=%ss)", self.auth.ttl_sec)

    def _auth_headers(self) -> Dict[str, str]:
        if (self.auth.kind in ("bearer", "password")) and self.auth.token:
            return {"Authorization": f"Bearer {self.auth.token}"}
        return {}

    # ---------- Printing ----------
    def _fmt_ts(self, ts: Optional[str]) -> str:
        if not ts:
            return ""
        try:
            if isinstance(ts, str) and ts.startswith("/Date("):
                dt = parse_dotnet_date(ts)
            else:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if self.output.timezone == "utc":
                return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
        except Exception:
            return str(ts)

    def _print_event(self, ev: Dict[str, Any]):
        if self.output.print_format == "json":
            print(json.dumps(ev, ensure_ascii=False))
        else:
            etype = ev.get("eventName", "event")
            ts = self._fmt_ts(ev.get("time"))
            who = ev.get("name") or ev.get("user_id") or "?"
            door = ev.get("device") or "?"
            detail = ev.get("info") or ""
            print(f"[{ts}] {etype} | user={who} | door={door} | {detail}".strip())

        if self.jsonl_fd:
            self.jsonl_fd.write(json.dumps(ev, ensure_ascii=False) + "\n")
            self.jsonl_fd.flush()

    def _update_cursors(self, events: List[Dict[str, Any]]):
        max_id = self.hwm_id
        last_since_norm = self.last_since
        eid_key = self.poll.event_id_field or "idLog"

        for ev in events:
            try:
                ev_id = int(str(ev.get(eid_key)))
                if ev_id > max_id:
                    max_id = ev_id
            except (TypeError, ValueError):
                pass

            raw = str(ev.get("time", "")) if ev.get("time") is not None else None
            if raw:
                if raw.startswith("/Date("):
                    last_since_norm = dotnet_to_iso_utc(raw)
                else:
                    try:
                        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
                        last_since_norm = dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
                    except Exception:
                        last_since_norm = raw

        self.hwm_id = max_id
        self.last_id = str(self.hwm_id if self.hwm_id >= 0 else 0)
        self.last_since = last_since_norm
        self.state.set(self.last_id, self.last_since)

        if self.output.verbose:
            LOGGER.info("Atualizado cursor | HWM=%s | last_since=%s", self.hwm_id, self.last_since)

    async def run_poll(self):
        assert self.client is not None
        url = self.poll.base_url.rstrip("/") + self.poll.events_endpoint

        if not self.last_since and self.poll.initial_since:
            self.last_since = self.poll.initial_since
        if (self.last_id is None) and (self.poll.initial_after_id is not None):
            self.last_id = str(self.poll.initial_after_id)
            try:
                self.hwm_id = int(self.last_id)
            except ValueError:
                self.hwm_id = -1
        if self.hwm_id < 0:
            self.hwm_id = 0
            self.last_id = "0"

        if self.output.verbose:
            LOGGER.info("Loop iniciado | intervalo=%.3fs", self.poll.interval_sec)

        while not self.stop_event.is_set():
            params = dict(self.poll.extra_params)

            since_val = self.last_since
            if since_val and isinstance(since_val, str) and since_val.startswith("/Date("):
                since_val = dotnet_to_iso_utc(since_val)
            if since_val:
                params[self.poll.since_param] = since_val

            params[self.poll.id_param] = str(self.hwm_id if self.hwm_id >= 0 else 0)
            if self.poll.limit_value is not None:
                params[self.poll.limit_param] = str(self.poll.limit_value)

            # Logs de envio
            if self.output.verbose:
                LOGGER.info("GET %s", url)
                LOGGER.info("Params: %s", params)
                hdrs_dbg = dict(self._auth_headers())
                if "Authorization" in hdrs_dbg:
                    hdrs_dbg["Authorization"] = "Bearer ***REDACTED***"
                LOGGER.info("Headers: %s", hdrs_dbg)

            t0 = time.time()
            try:
                r = await self.client.get(url, params=params, headers=self._auth_headers())
                dt_ms = (time.time() - t0) * 1000
                if self.output.verbose:
                    LOGGER.info("Resp status=%s | %.1fms | url=%s", r.status_code, dt_ms, r.request.url)

                if r.status_code == 401 and self.auth.kind == "password":
                    if self.output.verbose:
                        LOGGER.warning("401 recebido. Tentando relogin e repetir chamada.")
                    # invalida cache e reloga
                    self._save_cached_token("")  # sobrescreve
                    await self._login_password()
                    r = await self.client.get(url, params=params, headers=self._auth_headers())
                    if self.output.verbose:
                        LOGGER.info("Retry após login | status=%s", r.status_code)

                if self.output.log_body:
                    body_preview = r.text[:2048] if r.text else ""
                    LOGGER.debug("Body preview: %s", redact(body_preview))

                r.raise_for_status()

                # Parse seguro
                try:
                    data = r.json()
                except Exception as je:
                    LOGGER.error("Falha ao parsear JSON: %s", je)
                    await asyncio.sleep(self.poll.interval_sec)
                    continue

                events = data.get("data", [])
                if not isinstance(events, list):
                    if self.output.verbose:
                        LOGGER.warning("Campo 'data' não é lista. Tipo=%s", type(events).__name__)
                    events = []

                # De-dup: mantém só eventos com id > HWM e ordena crescente
                eid_key = self.poll.event_id_field or "idLog"
                new_events: List[Dict[str, Any]] = []
                min_id, max_id = None, None
                for ev in events:
                    raw_id = ev.get(eid_key)
                    try:
                        ev_id = int(str(raw_id))
                    except (TypeError, ValueError):
                        continue
                    if min_id is None or ev_id < min_id:
                        min_id = ev_id
                    if max_id is None or ev_id > max_id:
                        max_id = ev_id
                    if ev_id > self.hwm_id:
                        new_events.append(ev)

                new_events.sort(key=lambda e: int(str(e.get(eid_key, -1))))

                if self.output.verbose:
                    LOGGER.info("Recebidos %d eventos | faixa id=%s..%s | novos=%d (HWM atual=%s)",
                                len(events), min_id, max_id, len(new_events), self.hwm_id)

                if new_events:
                    for ev in new_events:
                        self._print_event(ev)
                    self._update_cursors(new_events)

            except httpx.HTTPStatusError as e:
                LOGGER.error("[HTTP %s] %s", e.response.status_code, e)
            except Exception as e:
                LOGGER.exception("[ERRO] %s", e)

            await asyncio.sleep(self.poll.interval_sec)

    def request_stop(self):
        self.stop_event.set()

# ---------------- CLI ----------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Control iD Monitor (token cache, de-dup e verbose)")
    p.add_argument("--base-url", required=True)
    p.add_argument("--events-endpoint", default="/api/access/monitor")
    p.add_argument("--interval", default="2s")
    p.add_argument("--verify-ssl", action="store_true", default=False)

    # Auth
    p.add_argument("--auth-kind", choices=["none", "bearer", "password"], default="password")
    p.add_argument("--token", default=None)
    p.add_argument("--auth-endpoint", default="/api/login/")
    p.add_argument("--auth-user", default=None)
    p.add_argument("--auth-pass", default=None)
    p.add_argument("--auth-payload-format", choices=["json", "form"], default="json")
    p.add_argument("--auth-extra", action="append", default=[], help="Campos extras para o login (k=v)")
    p.add_argument("--auth-token-path", default="accessToken")
    p.add_argument("--auth-cache", default=None, help="Caminho do cache de token (default: ~/.cache/controlid/token.json)")
    p.add_argument("--auth-ttl", default="8h", help="Tempo de vida do token no cache (default: 8h)")

    # Params
    p.add_argument("--since-param", default="time")
    p.add_argument("--id-param", default="modevalue")
    p.add_argument("--limit-param", default="limite")
    p.add_argument("--limit", type=int, default=15)
    p.add_argument("-P", "--param", action="append", default=[])

    # Event ID field (NOVO)
    p.add_argument("--event-id-field", default="idLog",
                   help="Nome do campo que identifica o evento (ex.: idLog, id). Default: idLog")

    # Output
    p.add_argument("--jsonl", default=None)
    p.add_argument("--print-format", choices=["human", "json"], default="human")
    p.add_argument("--tz", choices=["local", "utc"], default="local")
    p.add_argument("-v", "--verbose", action="store_true", help="Logs detalhados de alto nível")
    p.add_argument("--debug-http", action="store_true", help="Liga logging do httpx (requests/responses)")
    p.add_argument("--log-body", action="store_true", help="Mostra trecho do corpo das respostas (redigido)")

    # State
    p.add_argument("--state-db", default="monitor_state.sqlite")
    p.add_argument("--namespace", default="default")

    # Initial cursors
    p.add_argument("--initial-since", default=None)
    p.add_argument("--initial-after-id", default=None)  # passe 0 para reproduzir o Bash

    return p

def parse_kv_list(items: List[str]) -> Dict[str, str]:
    out = {}
    for it in items:
        if "=" not in it:
            raise ValueError(f"Parâmetro inválido: {it}. Use 'k=v'")
        k, v = it.split("=", 1)
        out[k.strip()] = v.strip()
    return out

async def main_async():
    args = build_parser().parse_args()

    setup_logging(verbose=args.verbose, debug_http=args.debug_http)

    auth = AuthConfig(
        kind=args.auth_kind,
        token=args.token,
        endpoint=args.auth_endpoint,
        user=args.auth_user,
        password=args.auth_pass,
        payload_format=args.auth_payload_format,
        extra_payload=parse_kv_list(args.auth_extra) if args.auth_extra else {},
        token_path=args.auth_token_path,
        cache_path=args.auth_cache,
        ttl_sec=parse_duration(args.auth_ttl)
    )

    poll = PollConfig(
        base_url=args.base_url,
        events_endpoint=args.events_endpoint,
        interval_sec=parse_duration(args.interval),
        verify_ssl=args.verify_ssl,
        since_param=args.since_param,
        id_param=args.id_param,
        limit_param=args.limit_param,
        limit_value=args.limit,
        extra_params=parse_kv_list(args.param) if args.param else {},
        initial_since=args.initial_since,
        initial_after_id=args.initial_after_id,
        event_id_field=args.event_id_field,
    )
    output = OutputConfig(
        jsonl_path=args.jsonl,
        print_format=args.print_format,
        timezone=args.tz,
        verbose=args.verbose,
        debug_http=args.debug_http,
        log_body=args.log_body,
    )
    state = StateConfig(state_db_path=args.state_db, namespace=args.namespace)

    monitor = Monitor(auth, poll, output, state)
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, monitor.request_stop)
        except NotImplementedError:
            pass

    async with monitor:
        await monitor.run_poll()

def main():
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
