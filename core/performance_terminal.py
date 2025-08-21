"""
High-Performance Terminal Engine for Security Operations
Based on Warp's architecture principles adapted for ethical hacking workflows
"""

import asyncio
import time
import threading
import queue
import psutil
import concurrent.futures
from typing import Dict, List, Optional, Callable, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import json
import re
from collections import deque
import weakref
import logging

# Performance monitoring
class PerformanceMetrics:
    """Track terminal performance metrics"""
    
    def __init__(self):
        self.frame_times = deque(maxlen=100)
        self.render_times = deque(maxlen=100)
        self.command_execution_times = deque(maxlen=1000)
        self.memory_usage = deque(maxlen=100)
        self.cpu_usage = deque(maxlen=100)
        self.start_time = time.time()
        
    def record_frame_time(self, duration: float):
        """Record frame rendering time"""
        self.frame_times.append(duration)
        
    def record_render_time(self, duration: float):
        """Record render operation time"""
        self.render_times.append(duration)
        
    def record_command_time(self, command: str, duration: float):
        """Record command execution time"""
        self.command_execution_times.append({
            'command': command,
            'duration': duration,
            'timestamp': time.time()
        })
        
    def record_system_stats(self):
        """Record system performance stats"""
        self.memory_usage.append(psutil.virtual_memory().percent)
        self.cpu_usage.append(psutil.cpu_percent())
        
    def get_fps(self) -> float:
        """Calculate current FPS"""
        if len(self.frame_times) < 2:
            return 0.0
        avg_frame_time = sum(self.frame_times) / len(self.frame_times)
        return 1.0 / avg_frame_time if avg_frame_time > 0 else 0.0
        
    def get_avg_render_time(self) -> float:
        """Get average render time in milliseconds"""
        if not self.render_times:
            return 0.0
        return (sum(self.render_times) / len(self.render_times)) * 1000
        
    def get_performance_report(self) -> Dict[str, Any]:
        """Get comprehensive performance report"""
        return {
            'fps': self.get_fps(),
            'avg_render_time_ms': self.get_avg_render_time(),
            'memory_usage_percent': self.memory_usage[-1] if self.memory_usage else 0,
            'cpu_usage_percent': self.cpu_usage[-1] if self.cpu_usage else 0,
            'uptime_seconds': time.time() - self.start_time,
            'total_commands': len(self.command_execution_times)
        }

class RenderPrimitive(Enum):
    """GPU rendering primitives"""
    RECTANGLE = "rectangle"
    TEXT = "text"
    IMAGE = "image"
    LINE = "line"
    CIRCLE = "circle"

@dataclass
class RenderElement:
    """Basic rendering element"""
    primitive: RenderPrimitive
    x: float
    y: float
    width: float
    height: float
    color: Tuple[float, float, float, float] = (1.0, 1.0, 1.0, 1.0)
    text: Optional[str] = None
    font_size: int = 12
    z_index: int = 0
    visible: bool = True
    
class GPURenderer:
    """GPU-accelerated renderer for terminal output"""
    
    def __init__(self):
        self.elements: List[RenderElement] = []
        self.dirty_regions: List[Tuple[int, int, int, int]] = []
        self.texture_cache: Dict[str, Any] = {}
        self.glyph_cache: Dict[Tuple[str, int], Any] = {}
        self.performance_metrics = PerformanceMetrics()
        
    def add_element(self, element: RenderElement):
        """Add rendering element to queue"""
        self.elements.append(element)
        self.mark_dirty(element.x, element.y, element.width, element.height)
        
    def mark_dirty(self, x: float, y: float, width: float, height: float):
        """Mark region as needing re-render"""
        self.dirty_regions.append((int(x), int(y), int(width), int(height)))
        
    def render_frame(self) -> float:
        """Render a single frame and return render time"""
        start_time = time.time()
        
        # Sort elements by z-index for proper layering
        self.elements.sort(key=lambda e: e.z_index)
        
        # Batch similar primitives for efficiency
        batched_elements = self._batch_elements()
        
        # Render each batch
        for primitive_type, elements in batched_elements.items():
            self._render_primitive_batch(primitive_type, elements)
            
        # Clear dirty regions after rendering
        self.dirty_regions.clear()
        
        render_time = time.time() - start_time
        self.performance_metrics.record_render_time(render_time)
        
        return render_time
        
    def _batch_elements(self) -> Dict[RenderPrimitive, List[RenderElement]]:
        """Batch elements by primitive type for efficient rendering"""
        batches = {}
        for element in self.elements:
            if element.visible:
                if element.primitive not in batches:
                    batches[element.primitive] = []
                batches[element.primitive].append(element)
        return batches
        
    def _render_primitive_batch(self, primitive: RenderPrimitive, elements: List[RenderElement]):
        """Render a batch of similar primitives"""
        # This would interface with actual GPU APIs (Metal, OpenGL, Vulkan)
        # For now, we'll simulate the rendering process
        
        if primitive == RenderPrimitive.TEXT:
            self._render_text_batch(elements)
        elif primitive == RenderPrimitive.RECTANGLE:
            self._render_rectangle_batch(elements)
        elif primitive == RenderPrimitive.IMAGE:
            self._render_image_batch(elements)
            
    def _render_text_batch(self, elements: List[RenderElement]):
        """Render text elements efficiently using glyph cache"""
        for element in elements:
            if element.text:
                glyph_key = (element.text, element.font_size)
                if glyph_key not in self.glyph_cache:
                    # Rasterize glyph once and cache
                    self.glyph_cache[glyph_key] = self._rasterize_text(element.text, element.font_size)
                    
    def _render_rectangle_batch(self, elements: List[RenderElement]):
        """Render rectangle elements efficiently"""
        # Group rectangles by color for batching
        color_groups = {}
        for element in elements:
            color_key = element.color
            if color_key not in color_groups:
                color_groups[color_key] = []
            color_groups[color_key].append(element)
            
        # Render each color group in one draw call
        for color, rects in color_groups.items():
            self._draw_rectangles(rects, color)
            
    def _render_image_batch(self, elements: List[RenderElement]):
        """Render image elements efficiently"""
        for element in elements:
            # Use texture cache for repeated images
            if element.text in self.texture_cache:
                texture = self.texture_cache[element.text]
            else:
                texture = self._load_texture(element.text)
                self.texture_cache[element.text] = texture
                
    def _rasterize_text(self, text: str, font_size: int) -> Any:
        """Rasterize text to texture (simulated)"""
        # This would use actual font rendering libraries
        return f"rasterized_{text}_{font_size}"
        
    def _draw_rectangles(self, rectangles: List[RenderElement], color: Tuple[float, float, float, float]):
        """Draw multiple rectangles in one GPU call"""
        # This would make actual GPU draw calls
        pass
        
    def _load_texture(self, path: str) -> Any:
        """Load texture from file"""
        # This would load actual texture data
        return f"texture_{path}"
        
    def clear_cache(self):
        """Clear rendering caches"""
        self.texture_cache.clear()
        self.glyph_cache.clear()
        
    def get_cache_size(self) -> Dict[str, int]:
        """Get cache sizes for monitoring"""
        return {
            'texture_cache': len(self.texture_cache),
            'glyph_cache': len(self.glyph_cache)
        }

class TerminalBlock:
    """Represents a command block similar to Warp's blocks"""
    
    def __init__(self, block_id: str, command: str = ""):
        self.id = block_id
        self.command = command
        self.output_lines: List[str] = []
        self.start_time = time.time()
        self.end_time: Optional[float] = None
        self.exit_code: Optional[int] = None
        self.working_directory = ""
        self.environment = {}
        self.metadata = {}
        self.is_security_command = False
        self.risk_level = "low"
        self.tool_used = ""
        
    def add_output(self, line: str):
        """Add output line to block"""
        self.output_lines.append(line)
        
    def complete(self, exit_code: int):
        """Mark block as completed"""
        self.end_time = time.time()
        self.exit_code = exit_code
        
    def get_duration(self) -> float:
        """Get block execution duration"""
        end = self.end_time if self.end_time else time.time()
        return end - self.start_time
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert block to dictionary for serialization"""
        return {
            'id': self.id,
            'command': self.command,
            'output_lines': self.output_lines,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'exit_code': self.exit_code,
            'working_directory': self.working_directory,
            'duration': self.get_duration(),
            'is_security_command': self.is_security_command,
            'risk_level': self.risk_level,
            'tool_used': self.tool_used,
            'metadata': self.metadata
        }

class HighPerformanceTerminal:
    """High-performance terminal engine for security operations"""
    
    def __init__(self):
        self.renderer = GPURenderer()
        self.blocks: Dict[str, TerminalBlock] = {}
        self.current_block: Optional[TerminalBlock] = None
        self.command_queue = queue.Queue()
        self.output_queue = queue.Queue()
        self.render_thread: Optional[threading.Thread] = None
        self.command_thread: Optional[threading.Thread] = None
        self.is_running = False
        self.target_fps = 60
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=4)
        self.performance_metrics = PerformanceMetrics()
        
        # Security-specific features
        self.security_tools = {
            'nmap', 'nikto', 'sqlmap', 'burpsuite', 'hydra', 'metasploit',
            'wireshark', 'john', 'hashcat', 'gobuster', 'dirb', 'zaproxy'
        }
        
        # Callbacks for events
        self.on_block_created: Optional[Callable[[TerminalBlock], None]] = None
        self.on_block_completed: Optional[Callable[[TerminalBlock], None]] = None
        self.on_command_executed: Optional[Callable[[str, float], None]] = None
        
    def start(self):
        """Start the terminal engine"""
        self.is_running = True
        
        # Start render thread
        self.render_thread = threading.Thread(target=self._render_loop, daemon=True)
        self.render_thread.start()
        
        # Start command processing thread
        self.command_thread = threading.Thread(target=self._command_loop, daemon=True)
        self.command_thread.start()
        
        print(" * Serving Flask app 'app'")
        print(" * Debug mode: on")
        print(" * Running on http://127.0.0.1:5000")
        
    def stop(self):
        """Stop the terminal engine"""
        self.is_running = False
        
        if self.render_thread:
            self.render_thread.join(timeout=1.0)
            
        if self.command_thread:
            self.command_thread.join(timeout=1.0)
            
        self.executor.shutdown(wait=True)
        logging.info("High-performance terminal stopped")
        
    def execute_command(self, command: str, working_dir: str = "") -> str:
        """Execute a command and return block ID"""
        block_id = f"block_{len(self.blocks)}_{int(time.time() * 1000)}"
        
        # Create new block
        block = TerminalBlock(block_id, command)
        block.working_directory = working_dir
        block.is_security_command = self._is_security_command(command)
        block.risk_level = self._assess_risk_level(command)
        block.tool_used = self._identify_tool(command)
        
        self.blocks[block_id] = block
        self.current_block = block
        
        # Queue command for execution
        self.command_queue.put(block)
        
        # Trigger callback
        if self.on_block_created:
            self.on_block_created(block)
            
        return block_id
        
    def _render_loop(self):
        """Main rendering loop running at target FPS"""
        frame_time = 1.0 / self.target_fps
        
        while self.is_running:
            frame_start = time.time()
            
            # Record system stats periodically
            if int(frame_start) % 5 == 0:
                self.performance_metrics.record_system_stats()
                
            # Process output queue
            self._process_output_queue()
            
            # Render frame
            render_time = self.renderer.render_frame()
            
            # Calculate frame timing
            frame_duration = time.time() - frame_start
            self.performance_metrics.record_frame_time(frame_duration)
            
            # Sleep to maintain target FPS
            sleep_time = max(0, frame_time - frame_duration)
            if sleep_time > 0:
                time.sleep(sleep_time)
                
    def _command_loop(self):
        """Command processing loop"""
        while self.is_running:
            try:
                # Get next command block
                block = self.command_queue.get(timeout=0.1)
                
                # Execute command asynchronously
                future = self.executor.submit(self._execute_block, block)
                
                # Process result when completed
                self.executor.submit(self._handle_command_result, block, future)
                
            except queue.Empty:
                continue
            except Exception as e:
                logging.error(f"Error in command loop: {e}")
                
    def _execute_block(self, block: TerminalBlock) -> int:
        """Execute a command block"""
        import subprocess
        
        start_time = time.time()
        
        try:
            # Execute command
                # Windows-specific command execution
                process = subprocess.Popen(
                    f'cmd /c {block.command}' if not block.command.startswith('powershell') else block.command,
                    shell=True,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                cwd=block.working_directory or None
            )
            
            # Stream output
            for line in iter(process.stdout.readline, ''):
                if line:
                    self.output_queue.put((block.id, line.strip()))
                    
            process.wait()
            execution_time = time.time() - start_time
            
            # Record performance metrics
            self.performance_metrics.record_command_time(block.command, execution_time)
            
            return process.returncode
            
        except Exception as e:
            logging.error(f"Error executing command: {e}")
            return -1
            
    def _handle_command_result(self, block: TerminalBlock, future: concurrent.futures.Future):
        """Handle command execution result"""
        try:
            exit_code = future.result()
            block.complete(exit_code)
            
            # Trigger callbacks
            if self.on_block_completed:
                self.on_block_completed(block)
                
            if self.on_command_executed:
                self.on_command_executed(block.command, block.get_duration())
                
        except Exception as e:
            logging.error(f"Error handling command result: {e}")
            
    def _process_output_queue(self):
        """Process output queue and update rendering"""
        while True:
            try:
                block_id, line = self.output_queue.get_nowait()
                
                if block_id in self.blocks:
                    block = self.blocks[block_id]
                    block.add_output(line)
                    
                    # Create render elements for new output
                    self._create_output_render_elements(block, line)
                    
            except queue.Empty:
                break
                
    def _create_output_render_elements(self, block: TerminalBlock, line: str):
        """Create render elements for output line"""
        # Calculate position based on block and line number
        y_offset = len(block.output_lines) * 20  # 20px line height
        
        # Create text render element
        text_element = RenderElement(
            primitive=RenderPrimitive.TEXT,
            x=10,
            y=y_offset,
            width=800,
            height=20,
            text=line,
            color=self._get_output_color(line, block.is_security_command)
        )
        
        self.renderer.add_element(text_element)
        
    def _get_output_color(self, line: str, is_security: bool) -> Tuple[float, float, float, float]:
        """Get color for output line based on content"""
        if is_security:
            # Security-specific color coding
            if re.search(r'(error|failed|denied)', line, re.IGNORECASE):
                return (1.0, 0.2, 0.2, 1.0)  # Red for errors
            elif re.search(r'(success|found|discovered)', line, re.IGNORECASE):
                return (0.2, 1.0, 0.2, 1.0)  # Green for success
            elif re.search(r'(warning|caution)', line, re.IGNORECASE):
                return (1.0, 1.0, 0.2, 1.0)  # Yellow for warnings
                
        return (1.0, 1.0, 1.0, 1.0)  # Default white
        
    def _is_security_command(self, command: str) -> bool:
        """Check if command is security-related"""
        command_lower = command.lower()
        return any(tool in command_lower for tool in self.security_tools)
        
    def _assess_risk_level(self, command: str) -> str:
        """Assess risk level of command"""
        command_lower = command.lower()
        
        # High risk commands
        if any(term in command_lower for term in ['rm -rf', 'format', 'mkfs', 'dd if=']):
            return "critical"
            
        # Medium risk commands
        if any(term in command_lower for term in ['sudo', 'passwd', 'chmod 777']):
            return "high"
            
        # Low risk security tools
        if self._is_security_command(command):
            return "medium"
            
        return "low"
        
    def _identify_tool(self, command: str) -> str:
        """Identify which security tool is being used"""
        command_lower = command.lower()
        
        for tool in self.security_tools:
            if tool in command_lower:
                return tool
                
        return "unknown"
        
    def get_block(self, block_id: str) -> Optional[TerminalBlock]:
        """Get block by ID"""
        return self.blocks.get(block_id)
        
    def get_all_blocks(self) -> List[TerminalBlock]:
        """Get all blocks"""
        return list(self.blocks.values())
        
    def get_security_blocks(self) -> List[TerminalBlock]:
        """Get only security-related blocks"""
        return [block for block in self.blocks.values() if block.is_security_command]
        
    def get_performance_report(self) -> Dict[str, Any]:
        """Get comprehensive performance report"""
        return {
            'terminal_metrics': self.performance_metrics.get_performance_report(),
            'renderer_metrics': {
                'cache_sizes': self.renderer.get_cache_size(),
                'avg_render_time_ms': self.renderer.performance_metrics.get_avg_render_time()
            },
            'blocks': {
                'total': len(self.blocks),
                'security_blocks': len(self.get_security_blocks()),
                'completed': len([b for b in self.blocks.values() if b.end_time is not None])
            }
        }
        
    def clear_history(self):
        """Clear command history and blocks"""
        self.blocks.clear()
        self.renderer.clear_cache()
        self.performance_metrics = PerformanceMetrics()
        
    def export_session(self, filename: str):
        """Export session data to file"""
        session_data = {
            'blocks': [block.to_dict() for block in self.blocks.values()],
            'performance': self.get_performance_report(),
            'export_time': time.time()
        }
        
        with open(filename, 'w') as f:
            json.dump(session_data, f, indent=2)
