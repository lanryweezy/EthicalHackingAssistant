
"""
Manages real-time command streaming using asyncio and WebSockets.
"""
import asyncio
from typing import Dict, Any

class StreamManager:
    """Handles running shell commands and streaming their output in real-time."""

    def __init__(self, socketio):
        self.socketio = socketio

    async def stream_command(self, command: str, event_name: str, sid: str):
        """
        Executes a command and streams its stdout and stderr to a client
        via SocketIO.

        Args:
            command (str): The shell command to execute.
            event_name (str): The SocketIO event name to emit to.
            sid (str): The session ID of the client to send the stream to.
        """
        try:
            # Create a subprocess to run the command
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            # Announce that the stream has started
            self.socketio.emit(event_name, {'type': 'status', 'data': 'streaming_started'}, room=sid)

            # Create two concurrent tasks to read stdout and stderr
            stdout_task = asyncio.create_task(
                self._stream_reader(process.stdout, event_name, 'stdout', sid)
            )
            stderr_task = asyncio.create_task(
                self._stream_reader(process.stderr, event_name, 'stderr', sid)
            )

            # Wait for both streams to complete
            await asyncio.gather(stdout_task, stderr_task)

            # Wait for the process to terminate and get the exit code
            await process.wait()
            exit_code = process.returncode

            # Announce the stream has finished
            self.socketio.emit(event_name, {
                'type': 'status',
                'data': 'streaming_finished',
                'exit_code': exit_code
            }, room=sid)

        except Exception as e:
            self.socketio.emit(event_name, {
                'type': 'error',
                'data': f"Failed to start command: {str(e)}"
            }, room=sid)

    async def _stream_reader(self, stream_reader, event_name: str, stream_type: str, sid: str):
        """Reads from a stream and emits lines to the client."""
        while not stream_reader.at_eof():
            try:
                line_bytes = await stream_reader.readline()
                if line_bytes:
                    # Decode the line and strip trailing newline characters
                    line = line_bytes.decode('utf-8', errors='replace').rstrip()
                    self.socketio.emit(event_name, {
                        'type': stream_type,
                        'data': line
                    }, room=sid)
                else:
                    # End of stream
                    break
            except Exception as e:
                self.socketio.emit(event_name, {
                    'type': 'error',
                    'data': f"Error reading stream: {str(e)}"
                }, room=sid)
                break

