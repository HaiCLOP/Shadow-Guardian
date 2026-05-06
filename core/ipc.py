"""
Shadow Guardian — Named Pipe IPC

Windows Named Pipe server (agent side) and client (API side).
Uses length-prefixed JSON protocol for structured communication.

Protocol: [4-byte big-endian length][JSON payload]
"""

import threading
import time
import base64
import os
from typing import Optional, Callable
from multiprocessing.connection import Listener, Client, AuthenticationError

from utils.logger import get_logger

logger = get_logger("core.ipc")

PIPE_NAME = r"\\.\pipe\ShadowGuardianIPC"
IPC_KEY_FILE = "ipc_auth.key"


def _get_ipc_authkey() -> bytes:
    """Load or create the local IPC auth key shared by agent and API."""
    from utils.paths import get_app_data_dir

    key_path = get_app_data_dir() / IPC_KEY_FILE
    try:
        if key_path.exists():
            raw = base64.urlsafe_b64decode(key_path.read_text(encoding="ascii").strip())
            if len(raw) >= 32:
                return raw
    except Exception as e:
        logger.warning(f"Failed to read IPC auth key; rotating key: {e}")

    raw = os.urandom(32)
    key_path.write_text(base64.urlsafe_b64encode(raw).decode("ascii"), encoding="ascii")
    return raw

class IPCServer:
    """
    Named Pipe server that runs in the agent process.
    Handles incoming commands from the API server.
    Uses multiprocessing.connection for robust IPC.
    """

    def __init__(self, handler: Callable[[dict], dict]):
        self._handler = handler
        self._running = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._listener: Optional[Listener] = None

    def start(self) -> None:
        """Start the IPC server in a background thread."""
        self._running.set()
        
        try:
            self._listener = Listener(PIPE_NAME, authkey=_get_ipc_authkey())
        except Exception as e:
            logger.critical(f"Failed to start IPC Listener: {e}")
            raise
            
        self._thread = threading.Thread(
            target=self._serve_loop,
            name="IPCServer",
            daemon=True,
        )
        self._thread.start()
        logger.info("IPC server started", extra={"data": {"pipe": PIPE_NAME}})

    def stop(self) -> None:
        """Stop the IPC server."""
        self._running.clear()
        if self._listener:
            try:
                self._listener.close()
            except Exception:
                pass
                
        if self._thread:
            self._thread.join(timeout=2.0)
        logger.info("IPC server stopped")

    def _serve_loop(self) -> None:
        """Main server loop — accepts clients."""
        while self._running.is_set():
            try:
                # accept() blocks until a client connects or listener is closed
                conn = self._listener.accept()
                
                # We handle requests sequentially. For higher concurrency,
                # we could spawn a thread here, but sequential is safe for DB.
                self._handle_client(conn)
                
            except OSError:
                # Listener closed
                break
            except AuthenticationError as e:
                logger.warning(f"IPC authentication failed: {e}")
            except Exception as e:
                if self._running.is_set():
                    logger.error(f"IPC server accept error: {e}")
                    time.sleep(0.1)

    def _handle_client(self, conn) -> None:
        """Handle a single client connection."""
        try:
            try:
                request = conn.recv()
            except EOFError:
                return

            if not isinstance(request, dict):
                response = {"error": "Invalid request format", "status": "error"}
            else:
                try:
                    response = self._handler(request)
                except Exception as e:
                    response = {"error": str(e), "status": "error"}

            conn.send(response)
        except Exception as e:
            logger.error(f"IPC client handler error: {e}")
        finally:
            try:
                conn.close()
            except Exception:
                pass


class IPCClient:
    """
    Named Pipe client for the API server to communicate with the agent.
    """

    def __init__(self, timeout_ms: int = 5000):
        self._timeout_sec = timeout_ms / 1000.0

    def send_command(self, command: dict) -> dict:
        """
        Send a command to the agent and return the response.
        """
        start_time = time.time()
        conn = None
        
        while True:
            try:
                conn = Client(PIPE_NAME, authkey=_get_ipc_authkey())
                break
            except AuthenticationError:
                return {"error": "IPC authentication failed", "status": "error"}
            except FileNotFoundError:
                # Pipe doesn't exist yet / Agent not ready
                if time.time() - start_time > self._timeout_sec:
                    return {"error": "Pipe not available (Agent offline)", "status": "error"}
                time.sleep(0.1)
            except OSError as e:
                # Pipe busy or other OS error
                if time.time() - start_time > self._timeout_sec:
                    return {"error": f"Pipe busy timeout: {e}", "status": "error"}
                time.sleep(0.1)
            except Exception as e:
                return {"error": str(e), "status": "error"}

        try:
            conn.send(command)
            
            # Use poll to implement timeout on recv
            if conn.poll(self._timeout_sec):
                response = conn.recv()
                return response if response else {"error": "Empty response", "status": "error"}
            else:
                return {"error": "Response timeout", "status": "error"}
                
        except EOFError:
            return {"error": "Connection closed by server", "status": "error"}
        except Exception as e:
            return {"error": str(e), "status": "error"}
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass
