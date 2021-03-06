"""
*Deprecation Notice:* Mitmproxy's WebSocket API is going to change soon,
see <https://github.com/mitmproxy/mitmproxy/issues/4425>.
"""
import queue
import time
import warnings
from typing import List
from typing import Optional
from typing import Union

from mitmproxy import flow
from mitmproxy.coretypes import serializable
from mitmproxy.net import websocket
from mitmproxy.utils import human
from mitmproxy.utils import strutils

from wsproto.frame_protocol import CloseReason
from wsproto.frame_protocol import Opcode


class WebSocketMessage(serializable.Serializable):
    """
    A WebSocket message sent from one endpoint to the other.
    """

    type: Opcode
    """indicates either TEXT or BINARY (from wsproto.frame_protocol.Opcode)."""
    from_client: bool
    """True if this messages was sent by the client."""
    content: Union[bytes, str]
    """A byte-string representing the content of this message."""
    timestamp: float
    """Timestamp of when this message was received or created."""

    killed: bool
    """True if this messages was killed and should not be sent to the other endpoint."""

    def __init__(
        self,
        type: int,
        from_client: bool,
        content: Union[bytes, str],
        timestamp: Optional[float] = None,
        killed: bool = False
    ) -> None:
        self.type = Opcode(type)  # type: ignore
        self.from_client = from_client
        self.content = content
        self.timestamp: float = timestamp or time.time()
        self.killed = killed

    @classmethod
    def from_state(cls, state):
        return cls(*state)

    def get_state(self):
        return int(self.type), self.from_client, self.content, self.timestamp, self.killed

    def set_state(self, state):
        self.type, self.from_client, self.content, self.timestamp, self.killed = state
        self.type = Opcode(self.type)  # replace enum with bare int

    def __repr__(self):
        if self.type == Opcode.TEXT:
            return "text message: {}".format(repr(self.content))
        else:
            return "binary message: {}".format(strutils.bytes_to_escaped_str(self.content))

    def kill(self):  # pragma: no cover
        """
        Kill this message.

        It will not be sent to the other endpoint. This has no effect in streaming mode.
        """
        warnings.warn(
            "WebSocketMessage.kill is deprecated, set an empty content instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        # empty str or empty bytes.
        self.content = type(self.content)()


class WebSocketFlow(flow.Flow):
    """
    A WebSocketFlow is a simplified representation of a WebSocket connection.
    """

    def __init__(self, client_conn, server_conn, handshake_flow, live=None):
        super().__init__("websocket", client_conn, server_conn, live)

        self.messages: List[WebSocketMessage] = []
        """A list containing all WebSocketMessage's."""
        self.close_sender = 'client'
        """'client' if the client initiated connection closing."""
        self.close_code = CloseReason.NORMAL_CLOSURE
        """WebSocket close code."""
        self.close_message = '(message missing)'
        """WebSocket close message."""
        self.close_reason = 'unknown status code'
        """WebSocket close reason."""
        self.stream = False
        """True of this connection is streaming directly to the other endpoint."""
        self.handshake_flow = handshake_flow
        """The HTTP flow containing the initial WebSocket handshake."""
        self.ended = False
        """True when the WebSocket connection has been closed."""

        self._inject_messages_client = queue.Queue(maxsize=1)
        self._inject_messages_server = queue.Queue(maxsize=1)

        if handshake_flow:
            self.client_key = websocket.get_client_key(handshake_flow.request.headers)
            self.client_protocol = websocket.get_protocol(handshake_flow.request.headers)
            self.client_extensions = websocket.get_extensions(handshake_flow.request.headers)
            self.server_accept = websocket.get_server_accept(handshake_flow.response.headers)
            self.server_protocol = websocket.get_protocol(handshake_flow.response.headers)
            self.server_extensions = websocket.get_extensions(handshake_flow.response.headers)
        else:
            self.client_key = ''
            self.client_protocol = ''
            self.client_extensions = ''
            self.server_accept = ''
            self.server_protocol = ''
            self.server_extensions = ''

    _stateobject_attributes = flow.Flow._stateobject_attributes.copy()
    # mypy doesn't support update with kwargs
    _stateobject_attributes.update(dict(
        messages=List[WebSocketMessage],
        close_sender=str,
        close_code=int,
        close_message=str,
        close_reason=str,
        client_key=str,
        client_protocol=str,
        client_extensions=str,
        server_accept=str,
        server_protocol=str,
        server_extensions=str,
        # Do not include handshake_flow, to prevent recursive serialization!
        # Since mitmproxy-console currently only displays HTTPFlows,
        # dumping the handshake_flow will include the WebSocketFlow too.
    ))

    def get_state(self):
        d = super().get_state()
        d['close_code'] = int(d['close_code'])  # replace enum with bare int
        return d

    @classmethod
    def from_state(cls, state):
        f = cls(None, None, None)
        f.set_state(state)
        return f

    def __repr__(self):
        return "<WebSocketFlow ({} messages)>".format(len(self.messages))

    def message_info(self, message: WebSocketMessage) -> str:
        return "{client} {direction} WebSocket {type} message {direction} {server}{endpoint}".format(
            type=message.type,
            client=human.format_address(self.client_conn.peername),
            server=human.format_address(self.server_conn.address),
            direction="->" if message.from_client else "<-",
            endpoint=self.handshake_flow.request.path,
        )
