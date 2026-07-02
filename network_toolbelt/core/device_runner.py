"""Device connection management, platform detection, execution engines, and connection registry."""

import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, FIRST_COMPLETED, wait
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

from network_toolbelt.core.command_policy import CommandPolicyMode
from network_toolbelt.core.credentials import (
    CredentialStore,
    TargetCredentialMapping,
    TargetCredentialMapStore,
)
from network_toolbelt.core.redaction import (
    LineBufferedRedactor,
    SecureTempSessionLogManager,
    redactor,
)
from network_toolbelt.core.settings import (
    CommandStatus,
    ConnectionStatus,
    FilenameSafety,
    LogicalPlatform,
    settings,
)


def format_concurrent_status(completed: int, total: int, active: int, stopped: bool) -> str:
    """Return a human-readable status string for concurrent execution progress."""
    if stopped:
        return f"STOPPED — {completed}/{total} hosts completed, {active} still winding down"
    return f"Running — {completed}/{total} hosts completed, {active} active"


@dataclass
class ConnectionResult:
    host: str
    status: ConnectionStatus
    connection: Optional[Any] = None
    netmiko_device_type: str = ""
    logical_platform: Optional[LogicalPlatform] = None
    error_message: str = ""
    attempt_history: List[Dict] = field(default_factory=list)
    _reconnect_credential: Optional[Dict[str, str]] = field(
        default=None, repr=False, compare=False
    )
    platform_probe_output: str = ""
    session_prepped: bool = False


@dataclass
class DeviceSessionContext:
    host: str
    platform_choice: str
    logical_platform: LogicalPlatform
    device_type: str
    temp_session_log: str
    conn: Any
    run_platform_probe: bool
    platform_probe_output: str = ""
    _reconnect_credential: Optional[Dict[str, str]] = field(
        default=None, repr=False, compare=False
    )


@dataclass
class CommandExecutionResult:
    command: str
    status: CommandStatus
    output: str
    error_message: str = ""
    attempts: int = 1
    method_used: str = ""
    reconnect_performed: bool = False
    unsupported_reason: str = ""
    abort_host: bool = False
    elapsed_seconds: float = 0.0
    first_attempt_elapsed_seconds: float = 0.0
    retry_elapsed_seconds: float = 0.0
    output_bytes: int = 0
    output_lines: int = 0
    timeout_seconds: int = 0
    last_read_seconds: float = 0.0
    slow_command: bool = False
    diagnostic_reason: str = ""
    retry_reason: str = ""


class ActiveConnectionRegistry:
    def __init__(self):
        self.connections = {}
        self.lock = threading.Lock()

    def register(self, key, conn):
        with self.lock:
            self.connections[key] = conn

    def unregister(self, key):
        with self.lock:
            if key in self.connections:
                del self.connections[key]

    def disconnect_all(self):
        with self.lock:
            for conn in list(self.connections.values()):
                try:
                    conn.disconnect()
                except Exception:
                    pass
            self.connections.clear()


class DeviceDetector:
    @staticmethod
    def classify(version_output: str) -> LogicalPlatform:
        ver = version_output.lower()
        if "adaptive security appliance" in ver or "asa software" in ver:
            return LogicalPlatform.ASA
        if "nx-os" in ver or "nexus" in ver:
            return LogicalPlatform.NXOS
        if (
            "c800" in ver
            or "c1800" in ver
            or "c1900" in ver
            or "c2900" in ver
            or "c3900" in ver
        ):
            if "ios-xe" not in ver and "ios xe" not in ver:
                return LogicalPlatform.IOS_LEGACY_ROUTER
        if "ios-xe" in ver or "ios xe" in ver:
            if (
                "catalyst" in ver
                or "switch" in ver
                or "c9300" in ver
                or "c9200" in ver
                or "c9500" in ver
                or "c3850" in ver
            ):
                return LogicalPlatform.IOS_XE_SWITCH
            if (
                "router" in ver
                or "asr" in ver
                or "isr" in ver
                or "c8300" in ver
                or "c8200" in ver
                or "c8000" in ver
                or "csr" in ver
            ):
                return LogicalPlatform.IOS_XE_ROUTER
            return LogicalPlatform.IOS_XE_SWITCH
        if (
            "cisco ios software" in ver
            or "cisco internetwork operating system software" in ver
        ):
            return LogicalPlatform.IOS
        return LogicalPlatform.UNKNOWN_CISCO


class CommandOutputAnalyzer:
    @staticmethod
    def analyze(output: str) -> Tuple[CommandStatus, str]:
        lower_out = output.lower()
        if (
            "% invalid input" in lower_out
            or "% incomplete command" in lower_out
            or "% ambiguous command" in lower_out
            or "% unrecognized command" in lower_out
        ):
            return (
                CommandStatus.COMMAND_UNSUPPORTED,
                "Command syntax invalid or unsupported on this platform.",
            )
        if any(
            phrase in lower_out
            for phrase in [
                "authorization failed",
                "% authorization failed",
                "command authorization failed",
                "permission denied",
                "insufficient privileges",
                "insufficient privilege",
                "not authorized",
                "requires privilege",
                "privilege denied",
                "access denied",
            ]
        ):
            return (
                CommandStatus.PRIVILEGE_DENIED,
                "Account lacks privilege for this command.",
            )
        if (
            "% error" in lower_out
            or "%error" in lower_out
            or "% failed" in lower_out
            or "%failed" in lower_out
        ):
            return CommandStatus.DEVICE_ERROR, "Device returned an error."
        return CommandStatus.SUCCESS, ""


class FeatureDetector:
    @staticmethod
    def detect_features(running_config: str) -> List[str]:
        features = []
        if re.search(r"^router bgp \d+", running_config, re.MULTILINE):
            features.append("bgp")
        if re.search(
            r"^router ospf \d+", running_config, re.MULTILINE
        ) or re.search(r"^ip ospf ", running_config, re.MULTILINE):
            features.append("ospf")
        if re.search(
            r"^router eigrp \d+", running_config, re.MULTILINE
        ) or re.search(r"^ip router eigrp", running_config, re.MULTILINE):
            features.append("eigrp")
        if "standby " in running_config:
            features.append("hsrp")
        if "vrrp " in running_config:
            features.append("vrrp")
        if re.search(
            r"interface Port-channel|channel-group|lacp",
            running_config,
            re.IGNORECASE,
        ):
            features.append("portchannel")
        if re.search(
            r"crypto map|tunnel-group|crypto ikev|ipsec",
            running_config,
            re.IGNORECASE,
        ):
            features.append("crypto_vpn")
        if "failover" in running_config:
            features.append("asa_failover")
        return features


class ConnectionManager:
    @staticmethod
    def safe_send_command(conn, cmd, read_timeout=None, platform_hint=""):
        timeout_val = read_timeout or settings.command_timeout
        try:
            return conn.send_command(cmd, read_timeout=timeout_val, cmd_verify=False)
        except Exception as e:
            err_str = str(e).lower()
            if (
                "pattern not detected" in err_str
                or "search pattern" in err_str
                or "command echo" in err_str
                or "prompt" in err_str
                or "read_channel_timing" in err_str
            ):
                try:
                    return conn.send_command_timing(cmd, read_timeout=timeout_val)
                except Exception as inner_e:
                    raise inner_e
            raise e

    @staticmethod
    def prepare_session(
        conn,
        logical_platform: LogicalPlatform,
        device_type: str,
        log_callback=None,
    ):
        commands = []
        if logical_platform == LogicalPlatform.ASA or device_type == "cisco_asa":
            commands.append("terminal pager 0")
        elif logical_platform == LogicalPlatform.NXOS or device_type == "cisco_nxos":
            commands.append("terminal length 0")
        else:
            commands.append("terminal length 0")
            commands.append("terminal width 511")

        for cmd in commands:
            try:
                t0 = time.perf_counter()
                conn.send_command_timing(
                    cmd,
                    read_timeout=settings.prep_command_timeout,
                    last_read=settings.prep_last_read,
                    strip_prompt=False,
                    strip_command=False,
                )
                elapsed = time.perf_counter() - t0
                if settings.diagnostics_enabled and log_callback:
                    log_callback(
                        f"  Debug: Session prep '{cmd}' completed in {elapsed:.2f}s"
                    )
            except Exception as e:
                if log_callback:
                    log_callback(f"Debug: Session prep command '{cmd}' error: {e}")

    @staticmethod
    def is_transport_error(error_msg: str, output: str) -> bool:
        err = (error_msg + output).lower()
        if (
            "socket is closed" in err
            or "session is not active" in err
            or "connection reset" in err
            or "broken pipe" in err
            or "channel closed" in err
            or "eof" in err
        ):
            return True
        return False

    @staticmethod
    def is_malformed_echo(cmd: str, output: str) -> bool:
        if not output.strip():
            return False
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        if not lines:
            return False
        first_line = lines[0].lower()
        cmd_lower = cmd.strip().lower()
        if first_line == cmd_lower:
            return False
        if cmd_lower.startswith(first_line) and len(first_line) < len(cmd_lower):
            return True
        cmd_tokens = cmd_lower.split()
        out_tokens = first_line.split()
        if not out_tokens or len(out_tokens) > len(cmd_tokens):
            return False
        for i, token in enumerate(out_tokens):
            if not cmd_tokens[i].startswith(token):
                return False
        if len(out_tokens) < len(cmd_tokens):
            return True
        if any(
            len(out_tokens[i]) < len(cmd_tokens[i]) for i in range(len(out_tokens))
        ):
            return True
        return False

    @staticmethod
    def summarize_command_diagnostics(result: CommandExecutionResult) -> str:
        s = f"method={result.method_used}, attempts={result.attempts}, bytes={result.output_bytes}, lines={result.output_lines}, timeout={result.timeout_seconds}s, last_read={result.last_read_seconds}s"
        if result.status == CommandStatus.SUCCESS:
            if result.slow_command:
                return f"! Slow command: {result.command.strip()} took {result.elapsed_seconds:.1f}s [{s}]. Possible causes: large output, device delay, timing wait, or prompt/read behavior."
            return f"✓ {result.command.strip()} completed in {result.elapsed_seconds:.1f}s [{s}]"
        elif result.status == CommandStatus.COMMAND_TIMEOUT:
            return f"✗ Timeout after {result.elapsed_seconds:.1f}s: {result.command.strip()} [{s}]"
        else:
            return f"✗ Failed in {result.elapsed_seconds:.1f}s: {result.command.strip()} [status={result.status.name}, {s}, reason={result.retry_reason or result.diagnostic_reason or 'unknown'}]"

    @staticmethod
    def format_diagnostic_header(result: CommandExecutionResult) -> str:
        return f"# status={result.status.name} elapsed={result.elapsed_seconds:.1f}s method={result.method_used} attempts={result.attempts} bytes={result.output_bytes} lines={result.output_lines} timeout={result.timeout_seconds}s last_read={result.last_read_seconds}s retry={result.retry_reason or 'none'}"

    @staticmethod
    def execute_command_with_recovery(
        context: DeviceSessionContext,
        cmd: str,
        read_timeout: int = None,
        log_callback=None,
    ) -> CommandExecutionResult:
        total_t0 = time.perf_counter()
        timeout_val = read_timeout or settings.command_timeout
        last_read_val = settings.timing_last_read

        use_timing = False
        if settings.execution_strategy == "safe_timing":
            use_timing = True
        elif "|" in cmd or context.logical_platform in (
            LogicalPlatform.ASA,
            LogicalPlatform.NXOS,
            LogicalPlatform.IOS_XE_SWITCH,
            LogicalPlatform.IOS_XE_ROUTER,
        ):
            use_timing = True

        def run_once(conn, method_timing):
            out = ""
            err = ""
            status = CommandStatus.SUCCESS
            t0 = time.perf_counter()
            try:
                if method_timing:
                    out = conn.send_command_timing(
                        cmd,
                        read_timeout=timeout_val,
                        last_read=last_read_val,
                        strip_prompt=False,
                        strip_command=False,
                    )
                else:
                    out = conn.send_command(
                        cmd,
                        read_timeout=timeout_val,
                        cmd_verify=False,
                        strip_prompt=False,
                        strip_command=False,
                    )
            except NetmikoTimeoutException as e:
                err = str(e)
                status = CommandStatus.COMMAND_TIMEOUT
            except Exception as e:
                err = str(e)
                status = CommandStatus.UNKNOWN_ERROR
            elapsed = time.perf_counter() - t0
            return out, err, status, elapsed

        out, err, status, elapsed_1 = run_once(context.conn, use_timing)
        method_used = "send_command_timing" if use_timing else "send_command"

        needs_retry = False
        is_transport = False
        retry_reason = ""
        fallback_last_read = False
        if status != CommandStatus.SUCCESS and ConnectionManager.is_transport_error(
            err, out
        ):
            needs_retry = True
            is_transport = True
            retry_reason = "transport_error"
        elif status == CommandStatus.SUCCESS:
            if ConnectionManager.is_transport_error("", out):
                needs_retry = True
                is_transport = True
                retry_reason = "transport_error"
            elif ConnectionManager.is_malformed_echo(cmd, out):
                needs_retry = True
                retry_reason = "malformed_echo"
                fallback_last_read = True
        elif status == CommandStatus.COMMAND_TIMEOUT:
            if settings.retry_on_command_timeout:
                needs_retry = True
                retry_reason = "command_timeout"
                fallback_last_read = True
            else:
                needs_retry = False
        else:
            if status != CommandStatus.SUCCESS:
                needs_retry = True
                retry_reason = "unknown_error"

        if not needs_retry and status == CommandStatus.SUCCESS:
            status, analyze_err = CommandOutputAnalyzer.analyze(out)
            if status != CommandStatus.SUCCESS:
                err = analyze_err or "Device error"

        def finalize_result(
            out_f,
            err_f,
            status_f,
            attempts_f,
            method_f,
            recon_perf,
            abort_h,
            elaps_1,
            elaps_retry,
            r_reason,
            d_reason,
        ):
            elaps = time.perf_counter() - total_t0
            ob = len(out_f.encode("utf-8")) if out_f else 0
            ol = len(out_f.splitlines()) if out_f else 0
            slow = elaps >= settings.slow_command_threshold
            res = CommandExecutionResult(
                command=cmd,
                status=status_f,
                output=out_f,
                error_message=err_f,
                attempts=attempts_f,
                method_used=method_f,
                reconnect_performed=recon_perf,
                unsupported_reason="Unsupported"
                if status_f == CommandStatus.COMMAND_UNSUPPORTED
                else "",
                abort_host=abort_h,
                elapsed_seconds=elaps,
                first_attempt_elapsed_seconds=elaps_1,
                retry_elapsed_seconds=elaps_retry,
                output_bytes=ob,
                output_lines=ol,
                timeout_seconds=timeout_val,
                last_read_seconds=last_read_val if "timing" in method_f else 0.0,
                slow_command=slow,
                diagnostic_reason=d_reason,
                retry_reason=r_reason,
            )
            if settings.diagnostics_enabled and log_callback:
                log_callback(ConnectionManager.summarize_command_diagnostics(res))
            return res

        if not needs_retry:
            return finalize_result(
                out, err, status, 1, method_used, False, False, elapsed_1, 0.0, "", ""
            )

        if fallback_last_read:
            last_read_val = 2.0
            if log_callback:
                log_callback(
                    f"  Debug: Retrying with conservative timing last_read=2.0s ({retry_reason})"
                )
        elif log_callback:
            log_callback(f"  Debug: Command error detected ({retry_reason}). Retrying...")

        recon_elapsed = 0.0
        if is_transport and context._reconnect_credential:
            if log_callback:
                log_callback("  Debug: Transport error detected. Reconnecting...")
            t_rec = time.perf_counter()
            try:
                context.conn.disconnect()
            except Exception:
                pass

            recon_res = ConnectionManager.connect(
                context.host,
                context._reconnect_credential,
                context.platform_choice,
                context.temp_session_log,
                context.run_platform_probe,
            )
            if recon_res.status == ConnectionStatus.SUCCESS:
                context.conn = recon_res.connection
                if not recon_res.session_prepped:
                    ConnectionManager.prepare_session(
                        context.conn,
                        context.logical_platform,
                        context.device_type,
                        log_callback,
                    )
            else:
                recon_elapsed = time.perf_counter() - t_rec
                return finalize_result(
                    out,
                    f"Reconnect failed: {recon_res.error_message}",
                    CommandStatus.UNKNOWN_ERROR,
                    1,
                    method_used,
                    False,
                    True,
                    elapsed_1,
                    0.0,
                    retry_reason,
                    "Reconnect failed",
                )
            recon_elapsed = time.perf_counter() - t_rec

            out, err, status, elapsed_2 = run_once(context.conn, True)
            method_used = "reconnect + send_command_timing"
            reconnect_performed = True
        else:
            out, err, status, elapsed_2 = run_once(context.conn, True)
            method_used = "retry + send_command_timing"
            reconnect_performed = False

        if status == CommandStatus.SUCCESS:
            status, analyze_err = CommandOutputAnalyzer.analyze(out)
            if status != CommandStatus.SUCCESS:
                err = analyze_err or "Device error"

        if (
            status != CommandStatus.SUCCESS
            and ConnectionManager.is_transport_error(err, out)
        ) or (
            status == CommandStatus.SUCCESS
            and ConnectionManager.is_transport_error("", out)
        ):
            return finalize_result(
                out,
                err or "Transport error during retry",
                status
                if status != CommandStatus.SUCCESS
                else CommandStatus.UNKNOWN_ERROR,
                2,
                method_used,
                reconnect_performed,
                True,
                elapsed_1,
                elapsed_2,
                retry_reason,
                "Transport error persisted",
            )

        if status == CommandStatus.SUCCESS and ConnectionManager.is_malformed_echo(
            cmd, out
        ):
            return finalize_result(
                out,
                "Malformed command echo persisted after retry",
                CommandStatus.UNKNOWN_ERROR,
                2,
                method_used,
                reconnect_performed,
                True,
                elapsed_1,
                elapsed_2,
                retry_reason,
                "Malformed echo persisted",
            )

        return finalize_result(
            out,
            err,
            status,
            2,
            method_used,
            reconnect_performed,
            False,
            elapsed_1,
            elapsed_2,
            retry_reason,
            "",
        )

    @staticmethod
    def connect(
        ip: str,
        creds: dict,
        platform_choice: str,
        temp_session_log: str,
        run_platform_probe: bool = True,
        log_callback=None,
    ) -> ConnectionResult:
        try:
            t_connect_total = time.perf_counter()
            device_type = "cisco_ios"

            if platform_choice == "Cisco NX-OS":
                device_type = "cisco_nxos"
            elif platform_choice == "Cisco ASA":
                device_type = "cisco_asa"
            elif platform_choice in ("Auto Detect", "Auto Detect Platform"):
                device_type = "cisco_ios"
                if log_callback and settings.diagnostics_enabled:
                    log_callback(
                        "  ℹ Auto Detect selected — connecting as cisco_ios (platform probe will classify device)"
                    )

            if log_callback and settings.diagnostics_enabled:
                log_callback(
                    f"  ⏳ Opening SSH session (device_type={device_type}, timeout=15s)..."
                )
            t_ssh = time.perf_counter()
            try:
                try:
                    conn = ConnectHandler(
                        device_type=device_type,
                        host=ip,
                        username=creds["username"],
                        password=creds["password"],
                        secret=creds.get("secret", ""),
                        session_log=temp_session_log,
                        auth_timeout=15,
                        timeout=15,
                        fast_cli=False,
                        global_cmd_verify=False,
                    )
                except TypeError:
                    conn = ConnectHandler(
                        device_type=device_type,
                        host=ip,
                        username=creds["username"],
                        password=creds["password"],
                        secret=creds.get("secret", ""),
                        session_log=temp_session_log,
                        auth_timeout=15,
                        timeout=15,
                        fast_cli=False,
                    )
            except NetmikoAuthenticationException as e:
                if log_callback and settings.diagnostics_enabled:
                    log_callback(
                        f"  ✗ SSH authentication failed after {time.perf_counter() - t_ssh:.2f}s"
                    )
                return ConnectionResult(
                    host=ip,
                    status=ConnectionStatus.AUTH_FAILED,
                    error_message=str(e),
                    _reconnect_credential=creds,
                )
            except NetmikoTimeoutException as e:
                if log_callback and settings.diagnostics_enabled:
                    log_callback(
                        f"  ✗ SSH connection timed out after {time.perf_counter() - t_ssh:.2f}s"
                    )
                return ConnectionResult(
                    host=ip,
                    status=ConnectionStatus.TIMEOUT,
                    error_message=str(e),
                    _reconnect_credential=creds,
                )
            except Exception as e:
                if log_callback and settings.diagnostics_enabled:
                    log_callback(
                        f"  ✗ SSH connection error after {time.perf_counter() - t_ssh:.2f}s: {type(e).__name__}"
                    )
                err = str(e).lower()
                if "connection refused" in err:
                    status = ConnectionStatus.CONNECTION_REFUSED
                elif "dns" in err or "name or service not known" in err:
                    status = ConnectionStatus.DNS_FAILED
                elif "negotiation" in err or "kex" in err:
                    status = ConnectionStatus.SSH_NEGOTIATION_FAILED
                else:
                    status = ConnectionStatus.UNKNOWN_ERROR
                return ConnectionResult(
                    host=ip,
                    status=status,
                    error_message=str(e),
                    _reconnect_credential=creds,
                )
            if log_callback and settings.diagnostics_enabled:
                log_callback(
                    f"  ✓ SSH session established in {time.perf_counter() - t_ssh:.2f}s"
                )

            if log_callback and settings.diagnostics_enabled:
                log_callback("  ⏳ Attempting privilege escalation (enable)...")
            t_enable = time.perf_counter()
            try:
                conn.enable()
                if log_callback and settings.diagnostics_enabled:
                    log_callback(
                        f"  ✓ Enable mode succeeded in {time.perf_counter() - t_enable:.2f}s"
                    )
            except Exception:
                if log_callback:
                    log_callback(
                        f"  ⚠ Enable mode failed in {time.perf_counter() - t_enable:.2f}s (session will continue without privilege escalation)"
                    )

            logical = LogicalPlatform.UNKNOWN_CISCO
            ver_out_saved = ""
            session_prepped = False
            if platform_choice == "Cisco ASA" or device_type == "cisco_asa":
                logical = LogicalPlatform.ASA
            elif platform_choice == "Cisco NX-OS" or device_type == "cisco_nxos":
                logical = LogicalPlatform.NXOS
            elif platform_choice == "Cisco IOS / IOS-XE":
                logical = LogicalPlatform.IOS

            if run_platform_probe:
                if log_callback and settings.diagnostics_enabled:
                    log_callback("  ⏳ Preparing session (terminal length/width)...")
                ConnectionManager.prepare_session(
                    conn, logical, device_type, log_callback
                )
                session_prepped = True
                if log_callback and settings.diagnostics_enabled:
                    log_callback(
                        f"  ⏳ Running platform probe (show version, timeout={settings.platform_probe_timeout}s, last_read={settings.platform_probe_last_read}s)..."
                    )
                try:
                    t0 = time.perf_counter()
                    ver_out = conn.send_command_timing(
                        "show version",
                        read_timeout=settings.platform_probe_timeout,
                        last_read=settings.platform_probe_last_read,
                        strip_prompt=False,
                        strip_command=False,
                    )
                    logical = DeviceDetector.classify(ver_out)
                    ver_out_saved = ver_out
                    elapsed = time.perf_counter() - t0
                    if log_callback and settings.diagnostics_enabled:
                        log_callback(
                            f"  ✓ Platform probe completed in {elapsed:.2f}s — classified as {logical.name} [bytes={len(ver_out.encode('utf-8'))}, lines={len(ver_out.splitlines())}]"
                        )
                except Exception as e:
                    if log_callback and settings.diagnostics_enabled:
                        log_callback(
                            f"  ⚠ Platform probe failed after {time.perf_counter() - t0:.2f}s: {type(e).__name__}"
                        )

            if log_callback and settings.diagnostics_enabled:
                log_callback(
                    f"  ✓ Connection setup complete in {time.perf_counter() - t_connect_total:.2f}s [platform={logical.name}, device_type={device_type}]"
                )

            return ConnectionResult(
                host=ip,
                status=ConnectionStatus.SUCCESS,
                connection=conn,
                netmiko_device_type=device_type,
                logical_platform=logical,
                _reconnect_credential=creds,
                platform_probe_output=ver_out_saved,
                session_prepped=session_prepped,
            )

        except Exception as e:
            return ConnectionResult(
                host=ip,
                status=ConnectionStatus.UNKNOWN_ERROR,
                error_message=str(e),
            )


class CredentialMappingRunner:
    @staticmethod
    def map_targets(
        targets: List[str],
        credential_store: CredentialStore,
        mapping_store: TargetCredentialMapStore,
        platform_choice: str,
        ui_callbacks: dict,
        stop_event: threading.Event,
        retest_mapped: bool = False,
        only_unmapped_or_stale: bool = True,
        capture_mode: str = "redacted",
        run_platform_probe: bool = True,
    ):
        log_cb = ui_callbacks.get("log_cb", lambda m: None)
        status_cb = ui_callbacks.get(
            "status_cb",
            lambda host, status, m_cred, user, plat, last, err: None,
        )
        progress_cb = ui_callbacks.get(
            "progress_cb", lambda idx, total, host=None: None
        )

        total = len(targets)
        concurrency = settings.concurrency_mapper

        def worker_task(host: str, idx: int):
            if stop_event.is_set():
                return

            mapping = mapping_store.get_mapping(host)
            if not mapping:
                mapping = TargetCredentialMapping(
                    host=host, safe_host=FilenameSafety.safe_host_label(host)
                )

            mapping.status = "MAPPING"
            mapping.last_tested = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            status_cb(
                mapping.host,
                mapping.status,
                mapping.credential_label,
                mapping.username,
                mapping.detected_platform,
                mapping.last_tested,
                mapping.error_message,
            )

            settings.base_output_dir.mkdir(parents=True, exist_ok=True)
            temp_dir = SecureTempSessionLogManager.ensure_secure_temp_session_dir(
                settings.base_output_dir, "mapping"
            )
            temp_session_log_path = (
                SecureTempSessionLogManager.create_secure_session_log_path(
                    temp_dir, f"{mapping.safe_host}_{idx}"
                )
            )
            temp_session_log = str(temp_session_log_path)

            log_cb(f"  [{host}] Starting credential mapping probe...")
            sess_log_cb = ui_callbacks.get("sess_log_cb", lambda m: None)
            tail_stop_event = threading.Event()

            def tail_file(filepath, stop_evt):
                try:
                    buf_redactor = LineBufferedRedactor(redactor.redact_text)
                    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                        while not stop_evt.is_set():
                            chunk = f.read(1024)
                            if chunk:
                                out = (
                                    buf_redactor.feed(chunk)
                                    if capture_mode == "redacted"
                                    else chunk
                                )
                                if out:
                                    sess_log_cb(out)
                            else:
                                time.sleep(0.1)
                        chunk = f.read()
                        if chunk:
                            out = (
                                buf_redactor.feed(chunk) + buf_redactor.flush()
                                if capture_mode == "redacted"
                                else chunk
                            )
                            if out:
                                sess_log_cb(out)
                except Exception:
                    pass

            tail_t = threading.Thread(
                target=tail_file,
                args=(temp_session_log, tail_stop_event),
                daemon=True,
            )
            tail_t.start()

            creds_to_try = credential_store.records
            if not creds_to_try:
                log_cb(f"  [{host}] Error: No credentials loaded.")
                mapping.status = "FAILED"
                mapping.error_message = "No credentials loaded"
                mapping_store.upsert_mapping(host, mapping)
                status_cb(
                    mapping.host,
                    mapping.status,
                    mapping.credential_label,
                    mapping.username,
                    mapping.detected_platform,
                    mapping.last_tested,
                    mapping.error_message,
                )
                tail_stop_event.set()
                tail_t.join(1.0)
                SecureTempSessionLogManager.cleanup_secure_session_log(
                    Path(temp_session_log)
                )
                return

            success = False
            for i, cred_record in enumerate(creds_to_try, 1):
                if stop_event.is_set():
                    break

                log_cb(
                    f"  [{host}] Trying credential set {i}/{len(creds_to_try)}: user={cred_record.username} ..."
                )
                cred_dict = {
                    "username": cred_record.username,
                    "password": cred_record.password,
                    "secret": cred_record.secret,
                }
                res = ConnectionManager.connect(
                    host,
                    cred_dict,
                    platform_choice,
                    temp_session_log,
                    run_platform_probe,
                )

                history_record = {
                    "set_number": i,
                    "username": cred_record.username,
                    "status": res.status.name,
                    "error_category": res.error_message,
                    "success": res.status == ConnectionStatus.SUCCESS,
                }
                mapping.attempt_history.append(history_record)

                if res.status == ConnectionStatus.SUCCESS:
                    log_cb(
                        f"  [{host}] ✓ Credential set {i} succeeded for user {cred_record.username}"
                    )
                    log_cb(
                        f"  [{host}] Mapped -> {cred_record.label} / {cred_record.username}"
                    )

                    mapping.credential_id = cred_record.id
                    mapping.credential_label = cred_record.label
                    mapping.username = cred_record.username
                    mapping.status = "MAPPED"
                    mapping.connection_status = "SUCCESS"
                    mapping.detected_platform = (
                        res.logical_platform.name
                        if res.logical_platform
                        else "UNKNOWN"
                    )
                    mapping.netmiko_device_type = res.netmiko_device_type
                    mapping.error_message = ""
                    success = True

                    try:
                        res.connection.disconnect()
                    except Exception:
                        pass
                    break
                else:
                    log_cb(
                        f"  [{host}] → Credential set {i} failed for user {cred_record.username}: {res.status.name}"
                    )

            if stop_event.is_set() and not success:
                mapping.status = "STOPPED"
                mapping.error_message = "Mapping stopped by user"
            elif not success:
                mapping.status = "FAILED"
                mapping.error_message = "All credentials failed"
                log_cb(f"  [{host}] ✗ mapping failed.")

            mapping_store.upsert_mapping(host, mapping)
            status_cb(
                mapping.host,
                mapping.status,
                mapping.credential_label,
                mapping.username,
                mapping.detected_platform,
                mapping.last_tested,
                mapping.error_message,
            )

            tail_stop_event.set()
            tail_t.join(1.0)
            SecureTempSessionLogManager.cleanup_secure_session_log(
                Path(temp_session_log)
            )

        if concurrency == 1:
            for idx, host in enumerate(targets):
                if stop_event.is_set():
                    for remaining_host in targets[idx:]:
                        m = mapping_store.get_mapping(remaining_host)
                        if m and m.status == "MAPPED":
                            continue
                        if not m:
                            m = TargetCredentialMapping(
                                host=remaining_host,
                                safe_host=FilenameSafety.safe_host_label(
                                    remaining_host
                                ),
                            )
                        m.status = "STOPPED"
                        mapping_store.upsert_mapping(remaining_host, m)
                        status_cb(
                            m.host,
                            m.status,
                            m.credential_label,
                            m.username,
                            m.detected_platform,
                            m.last_tested,
                            m.error_message,
                        )
                    log_cb("\n[Mapping Stopped by User]")
                    break

                progress_cb(idx, total, host)
                log_cb(f"\nMapping {host} ...")

                mapping = mapping_store.get_mapping(host)
                if not mapping:
                    mapping = TargetCredentialMapping(
                        host=host,
                        safe_host=FilenameSafety.safe_host_label(host),
                    )

                if mapping.status == "MAPPED" and not retest_mapped:
                    if only_unmapped_or_stale:
                        log_cb(f"  Skipping {host} (Already mapped)")
                        status_cb(
                            mapping.host,
                            mapping.status,
                            mapping.credential_label,
                            mapping.username,
                            mapping.detected_platform,
                            mapping.last_tested,
                            mapping.error_message,
                        )
                        continue

                worker_task(host, idx + 1)

            if not stop_event.is_set():
                progress_cb(total, total, None)
                log_cb("\n[Mapping Session Complete]")
            return

        completed_count = 0
        active_count = 0
        targets_to_submit = list(enumerate(targets, 1))
        active_futures = set()
        completed_hosts = set()

        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            while len(active_futures) < concurrency and targets_to_submit:
                idx, host = targets_to_submit.pop(0)
                mapping = mapping_store.get_mapping(host)
                if (
                    mapping
                    and mapping.status == "MAPPED"
                    and not retest_mapped
                    and only_unmapped_or_stale
                ):
                    log_cb(f"  Skipping {host} (Already mapped)")
                    status_cb(
                        mapping.host,
                        mapping.status,
                        mapping.credential_label,
                        mapping.username,
                        mapping.detected_platform,
                        mapping.last_tested,
                        mapping.error_message,
                    )
                    completed_hosts.add(host)
                    completed_count += 1
                    progress_cb(completed_count, total, host)
                    continue

                active_count += 1
                progress_cb(completed_count, total, host)
                f = executor.submit(worker_task, host, idx)
                active_futures.add(f)

            while active_futures:
                done, not_done = wait(active_futures, return_when=FIRST_COMPLETED)
                for f in done:
                    active_futures.remove(f)
                    active_count -= 1
                    completed_count += 1

                    try:
                        f.result()
                    except Exception as fut_err:
                        log_cb(f"Mapping task error: {fut_err}")

                    progress_cb(completed_count, total, None)

                if not stop_event.is_set():
                    while len(active_futures) < concurrency and targets_to_submit:
                        idx, host = targets_to_submit.pop(0)
                        mapping = mapping_store.get_mapping(host)
                        if (
                            mapping
                            and mapping.status == "MAPPED"
                            and not retest_mapped
                            and only_unmapped_or_stale
                        ):
                            log_cb(f"  Skipping {host} (Already mapped)")
                            status_cb(
                                mapping.host,
                                mapping.status,
                                mapping.credential_label,
                                mapping.username,
                                mapping.detected_platform,
                                mapping.last_tested,
                                mapping.error_message,
                            )
                            completed_hosts.add(host)
                            completed_count += 1
                            progress_cb(completed_count, total, host)
                            continue

                        active_count += 1
                        progress_cb(completed_count, total, host)
                        f = executor.submit(worker_task, host, idx)
                        active_futures.add(f)

        if stop_event.is_set():
            for idx, host in enumerate(targets):
                m = mapping_store.get_mapping(host)
                if m and m.status in ("MAPPED", "MAPPING"):
                    continue
                if not m:
                    m = TargetCredentialMapping(
                        host=host,
                        safe_host=FilenameSafety.safe_host_label(host),
                    )
                m.status = "STOPPED"
                mapping_store.upsert_mapping(host, m)
                status_cb(
                    m.host,
                    m.status,
                    m.credential_label,
                    m.username,
                    m.detected_platform,
                    m.last_tested,
                    m.error_message,
                )
            log_cb("\n[Mapping Stopped by User]")
        else:
            progress_cb(total, total, None)
            log_cb("\n[Mapping Session Complete]")
