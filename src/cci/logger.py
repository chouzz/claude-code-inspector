"""
Logging configuration for Claude-Code-Inspector.

Implements a tiered logging system with INFO, DEBUG, and ERROR levels.
Provides a shared Rich Console instance for consistent terminal output.
"""

import logging
import sys
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler

# =============================================================================
# SHARED CONSOLE INSTANCE
# =============================================================================
# This is the SINGLE console instance that should be used throughout the entire
# application. Using a single instance ensures that Rich can properly manage
# terminal output, especially when using features like `console.status()` that
# need to pin content at the bottom of the terminal.
#
# The console is configured with:
# - force_terminal=True: Ensures Rich features work even in non-TTY environments
# - stderr=False: Output to stdout for consistency with status spinners
console = Console(force_terminal=True)

# Custom logger name
LOGGER_NAME = "cci"

# Flag to track if root logger has been configured
_root_logger_configured = False


def setup_logger(
    level: str = "INFO",
    log_file: str | Path | None = None,
    log_format: str | None = None,
) -> logging.Logger:
    """
    Set up the CCI logger with the specified configuration.

    This function also configures the root logger to use RichHandler,
    ensuring that ALL logging output (including from third-party libraries)
    goes through Rich and doesn't break the terminal layout.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR)
        log_file: Optional file path for log output
        log_format: Custom log format string

    Returns:
        Configured logger instance
    """
    global _root_logger_configured

    log_level = getattr(logging, level.upper(), logging.INFO)

    # Configure root logger ONCE to capture all third-party library logs
    if not _root_logger_configured:
        _configure_root_logger(log_level)
        _root_logger_configured = True

    # Configure CCI logger
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(log_level)

    # Clear existing handlers (avoid duplicates on re-init)
    logger.handlers.clear()

    # Rich console handler for pretty terminal output
    rich_handler = RichHandler(
        console=console,
        show_time=True,
        show_path=False,
        rich_tracebacks=True,
        tracebacks_show_locals=level.upper() == "DEBUG",
        markup=True,  # Enable Rich markup in log messages
    )
    rich_handler.setLevel(log_level)
    logger.addHandler(rich_handler)

    # File handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)  # Always log everything to file
        formatter = logging.Formatter(
            log_format or "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    # Don't propagate to root logger (we handle our own output)
    logger.propagate = False

    return logger


def _configure_root_logger(level: int) -> None:
    """
    Configure the root logger to use RichHandler.

    This ensures that ALL logging output from any library goes through Rich,
    preventing raw log output from breaking the terminal layout when using
    features like `console.status()`.
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Remove any existing handlers
    root_logger.handlers.clear()

    # Add RichHandler to root logger
    root_handler = RichHandler(
        console=console,
        show_time=True,
        show_path=False,
        rich_tracebacks=True,
        markup=True,
    )
    root_handler.setLevel(level)
    root_logger.addHandler(root_handler)


def silence_noisy_loggers() -> None:
    """
    Silence verbose third-party library loggers.

    Call this function after setup_logger() to suppress noisy logs from
    libraries like uvicorn, mitmproxy, urllib3, etc. that would otherwise
    clutter the terminal output.
    """
    noisy_loggers = [
        # Web servers
        "uvicorn",
        "uvicorn.access",
        "uvicorn.error",
        "werkzeug",
        "fastapi",
        # HTTP libraries
        "urllib3",
        "urllib3.connectionpool",
        "httpx",
        "httpcore",
        "requests",
        # Proxy / MITM
        "mitmproxy",
        "mitmproxy.proxy",
        "mitmproxy.proxy.server",
        # Async
        "asyncio",
        "concurrent.futures",
        # Watchdog
        "watchdog",
        "watchdog.observers",
    ]

    for logger_name in noisy_loggers:
        logging.getLogger(logger_name).setLevel(logging.WARNING)


def redirect_stdout_to_rich() -> None:
    """
    Redirect stdout to go through Rich console.

    This captures raw print() calls from third-party libraries and routes them
    through the Rich console, preventing them from breaking the terminal layout.

    Note: This is a more aggressive approach and may have side effects.
    Use only if silence_noisy_loggers() is not sufficient.
    """

    class RichStdoutWriter:
        """A file-like object that redirects writes to Rich console."""

        def write(self, text: str) -> int:
            if text and text.strip():
                console.print(text, end="", highlight=False)
            return len(text)

        def flush(self) -> None:
            pass

        def isatty(self) -> bool:
            return True

    sys.stdout = RichStdoutWriter()  # type: ignore[assignment]


def get_logger() -> logging.Logger:
    """Get the CCI logger instance."""
    return logging.getLogger(LOGGER_NAME)


class LogContext:
    """Context manager for temporary log level changes."""

    def __init__(self, level: str):
        self.level = level
        self.original_level: int | None = None

    def __enter__(self) -> "LogContext":
        logger = get_logger()
        self.original_level = logger.level
        logger.setLevel(getattr(logging, self.level.upper(), logging.INFO))
        return self

    def __exit__(self, *args: object) -> None:
        if self.original_level is not None:
            get_logger().setLevel(self.original_level)


def log_request_summary(
    method: str,
    url: str,
    status: int | None = None,
    latency_ms: float | None = None,
) -> None:
    """Log a formatted request summary."""
    logger = get_logger()

    # Color coding based on status
    if status is None:
        status_str = "→"
    elif 200 <= status < 300:
        status_str = f"[green]{status}[/green]"
    elif 300 <= status < 400:
        status_str = f"[yellow]{status}[/yellow]"
    else:
        status_str = f"[red]{status}[/red]"

    latency_str = f" ({latency_ms:.0f}ms)" if latency_ms else ""

    logger.info("%s %s %s%s", method, url, status_str, latency_str, extra={"markup": True})


def log_streaming_progress(request_id: str, chunk_count: int) -> None:
    """Log streaming response progress."""
    logger = get_logger()
    logger.debug("Request %s... received chunk #%d", request_id[:8], chunk_count)


def log_error(message: str, exc: Exception | None = None) -> None:
    """Log an error with optional exception details."""
    logger = get_logger()
    if exc:
        logger.error("%s: %s", message, exc, exc_info=logger.level <= logging.DEBUG)
    else:
        logger.error("%s", message)


def log_startup_banner(host: str, port: int) -> None:
    """Log the startup banner."""
    console.print()
    # fmt: off
    console.print("[bold cyan]╔══════════════════════════════════════════════════════════╗[/]")  # noqa: E501
    console.print("[bold cyan]║[/]  [bold white]Claude-Code-Inspector (CCI)[/]                            [bold cyan]║[/]")  # noqa: E501
    console.print("[bold cyan]║[/]  [dim]MITM Proxy for LLM API Traffic Analysis[/]               [bold cyan]║[/]")  # noqa: E501
    console.print("[bold cyan]╠══════════════════════════════════════════════════════════╣[/]")  # noqa: E501
    console.print(f"[bold cyan]║[/]  Proxy listening on: [bold green]{host}:{port}[/]                 [bold cyan]║[/]")  # noqa: E501
    console.print("[bold cyan]║[/]                                                          [bold cyan]║[/]")  # noqa: E501
    console.print("[bold cyan]║[/]  [dim]Configure your HTTP/HTTPS proxy to point here[/]         [bold cyan]║[/]")  # noqa: E501
    console.print("[bold cyan]║[/]  [dim]Press Ctrl+C to stop capturing[/]                        [bold cyan]║[/]")  # noqa: E501
    console.print("[bold cyan]╚══════════════════════════════════════════════════════════╝[/]")  # noqa: E501
    # fmt: on
    console.print()

