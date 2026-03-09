#!/usr/bin/env python3
"""
CyBrain CLI - Endpoint Detection and Response System
Main CLI interface using Rich for interactive menu
"""

import subprocess
import sys
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm

console = Console()

class CyBrainCLI:
    def __init__(self):
        self.workspace = Path(__file__).parent
        self.console = console

    def display_header(self):
        header = Panel.fit(
            "[bold blue]CyBrain EDR[/bold blue]\n"
            "[dim]Endpoint Detection & Response System[/dim]\n"
            "[yellow]Powered by eBPF, AI Anomaly Detection & MITRE ATT&CK[/yellow]",
            title="[bold green]Welcome[/bold green]"
        )
        self.console.print(header)

    def show_menu(self):
        table = Table(title="Main Menu")
        table.add_column("Option", style="cyan", no_wrap=True)
        table.add_column("Description", style="magenta")

        table.add_row("1", "Install/Verify Tetragon")
        table.add_row("2", "Launch Active Protection")
        table.add_row("3", "Open SOC Dashboard")
        table.add_row("4", "Simulate Attack")
        table.add_row("5", "Exit")

        self.console.print(table)

    def install_tetragon(self):
        """Install or verify Tetragon installation"""
        script_path = self.workspace / "scripts" / "install_tetragon.sh"
        if not script_path.exists():
            self.console.print("[red]Error: install_tetragon.sh not found![/red]")
            return

        self.console.print("[yellow]Installing/Verifying Tetragon...[/yellow]")
        try:
            result = subprocess.run(
                ["bash", str(script_path)],
                capture_output=True,
                text=True,
                cwd=self.workspace
            )
            if result.returncode == 0:
                self.console.print("[green]Tetragon installation/verification completed successfully![/green]")
                self.console.print(result.stdout)
            else:
                self.console.print(f"[red]Error during installation: {result.stderr}[/red]")
        except Exception as e:
            self.console.print(f"[red]Failed to run installation script: {e}[/red]")

    def launch_protection(self):
        """Launch the brain orchestrator in background"""
        brain_script = self.workspace / "agents" / "brain.py"
        if not brain_script.exists():
            self.console.print("[red]Error: brain.py not found![/red]")
            return

        self.console.print("[yellow]Launching Active Protection...[/yellow]")
        try:
            # Launch in background
            process = subprocess.Popen(
                [sys.executable, str(brain_script)],
                cwd=self.workspace
            )
            self.console.print(f"[green]Active Protection launched (PID: {process.pid})[/green]")
            self.console.print("[dim]The system is now monitoring for threats...[/dim]")
        except Exception as e:
            self.console.print(f"[red]Failed to launch protection: {e}[/red]")

    def open_dashboard(self):
        """Open the Streamlit SOC Dashboard"""
        dashboard_script = self.workspace / "dashboard" / "app.py"
        if not dashboard_script.exists():
            self.console.print("[red]Error: dashboard/app.py not found![/red]")
            return

        self.console.print("[yellow]Opening SOC Dashboard...[/yellow]")
        try:
            subprocess.run([
                sys.executable, "-m", "streamlit", "run", str(dashboard_script)
            ], cwd=self.workspace)
        except KeyboardInterrupt:
            self.console.print("[yellow]Dashboard closed.[/yellow]")
        except Exception as e:
            self.console.print(f"[red]Failed to open dashboard: {e}[/red]")

    def simulate_attack(self):
        """Run attack simulation script"""
        sim_script = self.workspace / "scripts" / "simulate_attack.py"
        if not sim_script.exists():
            self.console.print("[red]Error: simulate_attack.py not found![/red]")
            return

        self.console.print("[yellow]Running attack simulation...[/yellow]")
        try:
            result = subprocess.run(
                [sys.executable, str(sim_script)],
                cwd=self.workspace,
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                self.console.print("[green]Attack simulation completed![/green]")
                self.console.print(result.stdout)
            else:
                self.console.print(f"[red]Simulation failed: {result.stderr}[/red]")
        except Exception as e:
            self.console.print(f"[red]Failed to run simulation: {e}[/red]")

    def run(self):
        """Main CLI loop"""
        self.display_header()

        while True:
            self.show_menu()
            choice = Prompt.ask("\n[bold cyan]Choose an option[/bold cyan]", choices=["1", "2", "3", "4", "5"])

            if choice == "1":
                self.install_tetragon()
            elif choice == "2":
                self.launch_protection()
            elif choice == "3":
                self.open_dashboard()
            elif choice == "4":
                self.simulate_attack()
            elif choice == "5":
                self.console.print("[green]Goodbye![/green]")
                break

            # Wait for user to continue
            if choice != "3":  # Don't pause after opening dashboard
                Prompt.ask("\n[bold]Press Enter to continue[/bold]")

if __name__ == "__main__":
    cli = CyBrainCLI()
    cli.run()
