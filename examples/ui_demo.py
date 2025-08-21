#!/usr/bin/env python3
"""
Demonstration of Advanced UI System for Ethical Hacking Terminal
Shows blocks, segments, notifications, progress bars, and security visualizations
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from ui.advanced_ui_system import (
    AdvancedUISystem, UITheme, BlockType, AlertLevel, 
    UIElementType, AnimationType
)
import time
import json

class UIDemo:
    """Demonstration of the advanced UI system"""
    
    def __init__(self):
        # Create custom theme
        self.theme = UITheme(
            primary_color=(0.0, 0.8, 1.0, 1.0),
            secondary_color=(0.3, 0.3, 0.3, 1.0),
            background_color=(0.05, 0.05, 0.05, 1.0),
            success_color=(0.0, 1.0, 0.4, 1.0),
            warning_color=(1.0, 0.7, 0.0, 1.0),
            error_color=(1.0, 0.3, 0.3, 1.0),
            security_color=(1.0, 0.5, 0.0, 1.0),
            font_family="Fira Code",
            font_size=14,
            border_radius=12.0
        )
        
        # Initialize UI system
        self.ui = AdvancedUISystem(self.theme)
        
        # Setup event callbacks
        self.ui.on_block_created = self.on_block_created
        self.ui.on_block_updated = self.on_block_updated
        self.ui.on_segment_added = self.on_segment_added
        self.ui.on_ui_element_created = self.on_ui_element_created
        
    def on_block_created(self, block):
        """Handle block creation event"""
        print(f"📦 Block created: {block.title} ({block.block_type.value})")
        
    def on_block_updated(self, block):
        """Handle block update event"""
        print(f"🔄 Block updated: {block.title} - Status: {block.status}")
        
    def on_segment_added(self, block, segment):
        """Handle segment addition event"""
        print(f"📄 Segment added to {block.title}: {segment.content[:50]}...")
        
    def on_ui_element_created(self, element):
        """Handle UI element creation event"""
        print(f"🎨 UI element created: {element.element_type.value}")
        
    def demo_nmap_scan(self):
        """Demonstrate nmap scan with blocks and segments"""
        print("\n🔍 Demonstrating Nmap Scan...")
        
        # Create nmap scan block
        block_id = self.ui.create_block(
            BlockType.SECURITY_SCAN,
            "Nmap Port Scan - 192.168.1.0/24",
            command="nmap -sS -p 1-1000 192.168.1.0/24",
            security_level="medium",
            tags=["nmap", "port-scan", "network-recon"]
        )
        
        # Simulate nmap output with segments
        nmap_outputs = [
            "Starting Nmap 7.94 ( https://nmap.org )",
            "Nmap scan report for 192.168.1.1",
            "Host is up (0.0010s latency).",
            "PORT     STATE SERVICE",
            "22/tcp   open  ssh",
            "80/tcp   open  http",
            "443/tcp  open  https",
            "8080/tcp open  http-proxy",
            "Nmap scan report for 192.168.1.5",
            "Host is up (0.0015s latency).",
            "PORT     STATE SERVICE",
            "21/tcp   open  ftp",
            "22/tcp   open  ssh",
            "23/tcp   open  telnet",
            "80/tcp   open  http",
            "Nmap done: 256 IP addresses (2 hosts up) scanned in 45.32 seconds"
        ]
        
        # Add segments with simulated timing
        for i, output in enumerate(nmap_outputs):
            self.ui.add_segment_to_block(
                block_id,
                output,
                "output",
                metadata={"line_number": i + 1}
            )
            # Update progress
            progress = (i + 1) / len(nmap_outputs)
            self.ui.update_block_progress(block_id, progress)
            time.sleep(0.1)  # Simulate scanning time
            
        # Mark as completed
        block = self.ui.get_block(block_id)
        block.status = "completed"
        
        return block_id
        
    def demo_vulnerability_scan(self):
        """Demonstrate vulnerability scanning with alerts"""
        print("\n🚨 Demonstrating Vulnerability Scan...")
        
        # Create vulnerability scan block
        block_id = self.ui.create_block(
            BlockType.VULNERABILITY,
            "Nikto Web Vulnerability Scan",
            command="nikto -h http://192.168.1.5",
            security_level="high",
            tags=["nikto", "web-scan", "vulnerability"]
        )
        
        # Show progress bar
        progress_id = self.ui.progress_manager.create_progress_bar(
            "nikto_scan",
            "Scanning web vulnerabilities...",
            x=10,
            y=50,
            width=400,
            height=25
        )
        
        # Simulate vulnerability findings
        vulnerabilities = [
            {
                "severity": "high",
                "description": "Server leaks inodes via ETags",
                "url": "/index.php"
            },
            {
                "severity": "medium",
                "description": "X-Frame-Options header not set",
                "url": "/"
            },
            {
                "severity": "low",
                "description": "Server banner disclosure",
                "url": "/"
            },
            {
                "severity": "critical",
                "description": "SQL injection vulnerability found",
                "url": "/login.php?id=1"
            }
        ]
        
        # Add vulnerability findings as segments
        for i, vuln in enumerate(vulnerabilities):
            content = f"[{vuln['severity'].upper()}] {vuln['description']} - {vuln['url']}"
            self.ui.add_segment_to_block(
                block_id,
                content,
                "vulnerability",
                metadata=vuln
            )
            
            # Update progress
            progress = (i + 1) / len(vulnerabilities)
            self.ui.progress_manager.update_progress(progress_id, progress)
            
            # Show alert for critical vulnerabilities
            if vuln['severity'] == 'critical':
                self.ui.notification_manager.show_alert(
                    f"Critical vulnerability found: {vuln['description']}",
                    AlertLevel.CRITICAL,
                    modal=True,
                    buttons=[
                        {"text": "Investigate", "action": "investigate"},
                        {"text": "Ignore", "action": "ignore"}
                    ]
                )
                
            time.sleep(0.5)
            
        # Complete progress bar
        self.ui.progress_manager.complete_progress(progress_id)
        
        # Create vulnerability chart
        chart_id = self.ui.security_viz.create_vulnerability_chart(
            vulnerabilities,
            x=450,
            y=50,
            width=350,
            height=250
        )
        
        return block_id
        
    def demo_exploit_attempt(self):
        """Demonstrate exploit attempt with real-time feedback"""
        print("\n💥 Demonstrating Exploit Attempt...")
        
        # Create exploit block
        block_id = self.ui.create_block(
            BlockType.EXPLOIT,
            "SQL Injection Exploit",
            command="sqlmap -u 'http://192.168.1.5/login.php?id=1' --dbs",
            security_level="critical",
            tags=["sqlmap", "sql-injection", "exploit"]
        )
        
        # Show warning notification
        self.ui.notification_manager.show_notification(
            "Starting SQL injection exploit attempt",
            AlertLevel.WARNING,
            duration=3.0,
            title="Security Alert"
        )
        
        # Simulate sqlmap output
        sqlmap_outputs = [
            "sqlmap/1.7.2 starting at 10:30:15",
            "GET parameter 'id' is vulnerable to SQL injection",
            "testing MySQL >= 5.0.12 AND time-based blind",
            "confirmed: time-based blind SQL injection",
            "available databases [3]:",
            "[*] information_schema",
            "[*] mysql",
            "[*] webapp_db",
            "database management system: MySQL >= 5.0.12"
        ]
        
        # Add segments with exploitation results
        for i, output in enumerate(sqlmap_outputs):
            self.ui.add_segment_to_block(
                block_id,
                output,
                "exploit_output",
                metadata={"step": i + 1}
            )
            
            # Show success notification when databases are found
            if "available databases" in output:
                self.ui.notification_manager.show_notification(
                    "Database enumeration successful!",
                    AlertLevel.SUCCESS,
                    duration=2.0
                )
                
            time.sleep(0.3)
            
        return block_id
        
    def demo_network_topology(self):
        """Demonstrate network topology visualization"""
        print("\n🌐 Demonstrating Network Topology...")
        
        # Create network discovery block
        block_id = self.ui.create_block(
            BlockType.RECON,
            "Network Discovery",
            command="netdiscover -r 192.168.1.0/24",
            security_level="low",
            tags=["netdiscover", "network", "discovery"]
        )
        
        # Sample network hosts
        hosts = [
            {"ip": "192.168.1.1", "hostname": "router", "os": "Linux", "ports": [22, 80, 443]},
            {"ip": "192.168.1.5", "hostname": "webserver", "os": "Linux", "ports": [21, 22, 80, 443]},
            {"ip": "192.168.1.10", "hostname": "database", "os": "Linux", "ports": [22, 3306]},
            {"ip": "192.168.1.15", "hostname": "workstation", "os": "Windows", "ports": [135, 139, 445]}
        ]
        
        # Sample connections
        connections = [
            {"source": "192.168.1.1", "target": "192.168.1.5", "protocol": "HTTP"},
            {"source": "192.168.1.5", "target": "192.168.1.10", "protocol": "MySQL"},
            {"source": "192.168.1.1", "target": "192.168.1.15", "protocol": "SMB"}
        ]
        
        # Add host discovery segments
        for host in hosts:
            content = f"Discovered host: {host['ip']} ({host['hostname']}) - {host['os']}"
            self.ui.add_segment_to_block(
                block_id,
                content,
                "discovery",
                metadata=host
            )
            
        # Create network graph
        graph_id = self.ui.security_viz.create_network_graph(
            hosts,
            connections,
            x=50,
            y=300,
            width=600,
            height=400
        )
        
        return block_id
        
    def demo_timeline_analysis(self):
        """Demonstrate security events timeline"""
        print("\n📊 Demonstrating Timeline Analysis...")
        
        # Create timeline analysis block
        block_id = self.ui.create_block(
            BlockType.INFO,
            "Security Events Timeline",
            security_level="medium",
            tags=["timeline", "analysis", "events"]
        )
        
        # Sample security events
        events = [
            {
                "timestamp": time.time() - 3600,  # 1 hour ago
                "event": "Nmap scan initiated",
                "severity": "low",
                "source": "192.168.1.100"
            },
            {
                "timestamp": time.time() - 3300,  # 55 minutes ago
                "event": "Port 22 connection attempt",
                "severity": "medium",
                "source": "192.168.1.100"
            },
            {
                "timestamp": time.time() - 3000,  # 50 minutes ago
                "event": "SQL injection detected",
                "severity": "high",
                "source": "192.168.1.100"
            },
            {
                "timestamp": time.time() - 2700,  # 45 minutes ago
                "event": "Database access granted",
                "severity": "critical",
                "source": "192.168.1.100"
            },
            {
                "timestamp": time.time() - 2400,  # 40 minutes ago
                "event": "Data exfiltration detected",
                "severity": "critical",
                "source": "192.168.1.100"
            }
        ]
        
        # Add timeline segments
        for event in events:
            event_time = time.strftime("%H:%M:%S", time.localtime(event['timestamp']))
            content = f"[{event_time}] {event['event']} - Severity: {event['severity']}"
            self.ui.add_segment_to_block(
                block_id,
                content,
                "timeline_event",
                metadata=event
            )
            
        # Create timeline visualization
        timeline_id = self.ui.security_viz.create_timeline(
            events,
            x=50,
            y=100,
            width=700,
            height=180
        )
        
        return block_id
        
    def demo_custom_elements(self):
        """Demonstrate custom UI elements"""
        print("\n🎨 Demonstrating Custom UI Elements...")
        
        # Create custom status indicator
        status_id = self.ui.create_custom_ui_element(
            UIElementType.STATUS_INDICATOR,
            x=10,
            y=10,
            width=200,
            height=30,
            content={
                "status": "Scanning",
                "active": True,
                "color": "green"
            },
            style={
                "background_color": (0.2, 0.2, 0.2, 0.8),
                "border_radius": 15.0,
                "font_size": 12
            }
        )
        
        # Create custom sidebar
        sidebar_id = self.ui.create_custom_ui_element(
            UIElementType.SIDEBAR,
            x=0,
            y=0,
            width=250,
            height=800,
            content={
                "title": "Security Tools",
                "items": [
                    {"name": "Nmap", "status": "available"},
                    {"name": "Nikto", "status": "running"},
                    {"name": "SQLMap", "status": "available"},
                    {"name": "Burp Suite", "status": "unavailable"}
                ]
            },
            style={
                "background_color": (0.1, 0.1, 0.1, 0.9),
                "border_radius": 0.0,
                "font_size": 13
            }
        )
        
        # Create floating panel
        panel_id = self.ui.create_custom_ui_element(
            UIElementType.FLOATING_PANEL,
            x=300,
            y=150,
            width=400,
            height=300,
            content={
                "title": "Vulnerability Details",
                "data": {
                    "cve": "CVE-2023-1234",
                    "severity": "Critical",
                    "description": "Remote code execution vulnerability",
                    "affected_systems": ["192.168.1.5", "192.168.1.10"]
                }
            },
            style={
                "background_color": (0.15, 0.15, 0.15, 0.95),
                "border_radius": 10.0,
                "shadow_blur": 8.0,
                "font_size": 12
            }
        )
        
        return [status_id, sidebar_id, panel_id]
        
    def print_summary(self):
        """Print summary of the demo"""
        print("\n📋 Demo Summary:")
        print("=" * 50)
        
        # Get blocks summary
        summary = self.ui.get_blocks_summary()
        print(f"Total blocks created: {summary['total_blocks']}")
        print(f"Total segments: {summary['total_segments']}")
        print(f"Active UI elements: {summary['active_ui_elements']}")
        
        print("\nBlocks by type:")
        for block_type, count in summary['blocks_by_type'].items():
            print(f"  {block_type}: {count}")
            
        print("\nBlocks by security level:")
        for security_level, count in summary['blocks_by_security'].items():
            print(f"  {security_level}: {count}")
            
        # Get all notifications
        notifications = self.ui.notification_manager.get_active_notifications()
        print(f"\nActive notifications: {len(notifications)}")
        
        # Get all progress bars
        progress_bars = self.ui.progress_manager.get_progress_bars()
        print(f"Active progress bars: {len(progress_bars)}")
        
        # Get all visualizations
        visualizations = self.ui.security_viz.get_visualizations()
        print(f"Active visualizations: {len(visualizations)}")
        
    def export_demo_data(self):
        """Export demo data to file"""
        print("\n💾 Exporting demo data...")
        
        # Export blocks
        self.ui.export_blocks("demo_blocks.json")
        
        # Export UI elements
        ui_elements = self.ui.get_all_ui_elements()
        export_data = {
            "export_time": time.time(),
            "ui_elements": [
                {
                    "id": elem.id,
                    "type": elem.element_type.value,
                    "position": {"x": elem.x, "y": elem.y},
                    "size": {"width": elem.width, "height": elem.height},
                    "content": elem.content,
                    "style": elem.style
                }
                for elem in ui_elements
            ]
        }
        
        with open("demo_ui_elements.json", "w") as f:
            json.dump(export_data, f, indent=2)
            
        print("Demo data exported to demo_blocks.json and demo_ui_elements.json")
        
    def run_full_demo(self):
        """Run the complete demonstration"""
        print("🚀 Starting Advanced UI System Demo")
        print("=" * 50)
        
        # Run all demos
        self.demo_nmap_scan()
        self.demo_vulnerability_scan()
        self.demo_exploit_attempt()
        self.demo_network_topology()
        self.demo_timeline_analysis()
        self.demo_custom_elements()
        
        # Print summary
        self.print_summary()
        
        # Export data
        self.export_demo_data()
        
        print("\n✅ Demo completed successfully!")

if __name__ == "__main__":
    demo = UIDemo()
    demo.run_full_demo()
