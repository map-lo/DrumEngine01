#!/usr/bin/env python3
"""
DrumEngine01 Build Script

Orchestrates the entire build process based on build_config.py settings:
1. Configure and build plugins with CMake
2. Package factory content (presets and samples)
3. Build macOS installer

Usage:
    python build.py [--config CONFIG_FILE]
    
Options:
    --config    Path to config file (default: build_config.py)
"""

import argparse
import subprocess
import sys
import os
from pathlib import Path
import importlib.util


class Colors:
    """ANSI color codes for terminal output"""
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    RED = '\033[0;31m'
    BLUE = '\033[0;34m'
    NC = '\033[0m'  # No Color


class BuildOrchestrator:
    def __init__(self, config_path: str = "build_config.py"):
        self.project_root = Path(__file__).parent
        self.config = self.load_config(config_path)
        self.errors = []
        
    def load_config(self, config_path: str):
        """Load configuration from Python file"""
        config_file = self.project_root / config_path
        
        if not config_file.exists():
            print(f"{Colors.RED}Error: Config file not found: {config_file}{Colors.NC}")
            sys.exit(1)
        
        # Load config module dynamically
        spec = importlib.util.spec_from_file_location("build_config", config_file)
        config = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(config)
        
        print(f"{Colors.BLUE}Loaded configuration from: {config_file}{Colors.NC}")
        print(f"  Build Type: {config.BUILD_TYPE}")
        print(f"  Preset Limit: {config.PRESET_LIMIT or 'None (all presets)'}")
        print(f"  Clean Build: {config.CLEAN_BUILD}")
        print(f"  Build Installer: {config.BUILD_INSTALLER}")
        print()
        
        return config
    
    def run_command(self, cmd: list, cwd: Path = None, description: str = None, env: dict = None):
        """Run a shell command and handle errors"""
        if description:
            print(f"{Colors.BLUE}▶ {description}{Colors.NC}")
        
        print(f"  Command: {' '.join(cmd)}")
        print()
        
        try:
            result = subprocess.run(
                cmd,
                cwd=cwd or self.project_root,
                check=True,
                capture_output=False,
                text=True,
                env=env
            )
            return True
        except subprocess.CalledProcessError as e:
            error_msg = f"Command failed with exit code {e.returncode}"
            print(f"{Colors.RED}✗ {error_msg}{Colors.NC}")
            self.errors.append(error_msg)
            return False
    
    def step_clean_build(self):
        """Step 1: Clean build artifacts if requested"""
        if not self.config.CLEAN_BUILD:
            print(f"{Colors.YELLOW}Skipping clean (CLEAN_BUILD=False){Colors.NC}")
            print()
            return True
        
        print(f"{Colors.GREEN}{'='*70}{Colors.NC}")
        print(f"{Colors.GREEN}Step 1: Cleaning Build Artifacts{Colors.NC}")
        print(f"{Colors.GREEN}{'='*70}{Colors.NC}")
        print()
        
        build_artefacts = self.project_root / self.config.BUILD_DIR / "DrumEngine01_artefacts"
        dist_dir = self.project_root / self.config.DIST_DIR
        
        if build_artefacts.exists():
            print(f"Removing: {build_artefacts}")
            import shutil
            shutil.rmtree(build_artefacts)
        
        if dist_dir.exists():
            print(f"Removing: {dist_dir}")
            import shutil
            shutil.rmtree(dist_dir)
        
        print(f"{Colors.GREEN}✓ Clean complete{Colors.NC}")
        print()
        return True
    
    def step_configure_cmake(self):
        """Step 2: Configure CMake"""
        print(f"{Colors.GREEN}{'='*70}{Colors.NC}")
        print(f"{Colors.GREEN}Step 2: Configuring CMake{Colors.NC}")
        print(f"{Colors.GREEN}{'='*70}{Colors.NC}")
        print()
        
        build_dir = self.project_root / self.config.BUILD_DIR
        build_dir.mkdir(exist_ok=True)
        
        return self.run_command(
            ["cmake", "..", f"-DCMAKE_BUILD_TYPE={self.config.BUILD_TYPE}"],
            cwd=build_dir,
            description="Configuring CMake"
        )
    
    def step_build_plugins(self):
        """Step 3: Build plugins"""
        print(f"{Colors.GREEN}{'='*70}{Colors.NC}")
        print(f"{Colors.GREEN}Step 3: Building Plugins{Colors.NC}")
        print(f"{Colors.GREEN}{'='*70}{Colors.NC}")
        print()
        
        build_dir = self.project_root / self.config.BUILD_DIR
        
        return self.run_command(
            ["cmake", "--build", ".", "--config", self.config.BUILD_TYPE],
            cwd=build_dir,
            description=f"Building plugins ({self.config.BUILD_TYPE})"
        )
    
    def step_package_content(self):
        """Step 4: Package factory content"""
        print(f"{Colors.GREEN}{'='*70}{Colors.NC}")
        print(f"{Colors.GREEN}Step 4: Packaging Factory Content{Colors.NC}")
        print(f"{Colors.GREEN}{'='*70}{Colors.NC}")
        print()
        
        generators_dir = self.project_root / self.config.GENERATORS_DIR
        script = generators_dir / "package_presets_for_installer.py"
        
        cmd = ["python3", str(script)]
        
        if self.config.PRESET_LIMIT is not None:
            cmd.extend(["--limit", str(self.config.PRESET_LIMIT)])
            print(f"{Colors.YELLOW}Note: Using preset limit of {self.config.PRESET_LIMIT} for testing{Colors.NC}")
            print()
        
        return self.run_command(
            cmd,
            description="Packaging presets and samples"
        )
    
    def step_build_installer(self):
        """Step 5: Build installer"""
        if not self.config.BUILD_INSTALLER:
            print(f"{Colors.YELLOW}Skipping installer build (BUILD_INSTALLER=False){Colors.NC}")
            print()
            return True
        
        print(f"{Colors.GREEN}{'='*70}{Colors.NC}")
        print(f"{Colors.GREEN}Step 5: Building Installer{Colors.NC}")
        print(f"{Colors.GREEN}{'='*70}{Colors.NC}")
        print()
        
        installer_dir = self.project_root / self.config.INSTALLER_DIR
        script = installer_dir / "build_installer.sh"
        
        # Pass version to installer script
        env = os.environ.copy()
        env['DRUMENGINE_VERSION'] = self.config.VERSION
        
        return self.run_command(
            [str(script)],
            cwd=installer_dir,
            description="Building macOS installer package",
            env=env
        )
    
    def print_summary(self):
        """Print build summary"""
        print()
        print(f"{Colors.GREEN}{'='*70}{Colors.NC}")
        print(f"{Colors.GREEN}Build Summary{Colors.NC}")
        print(f"{Colors.GREEN}{'='*70}{Colors.NC}")
        
        if self.errors:
            print(f"{Colors.RED}Build completed with {len(self.errors)} error(s):{Colors.NC}")
            for error in self.errors:
                print(f"{Colors.RED}  ✗ {error}{Colors.NC}")
            print()
            return False
        else:
            print(f"{Colors.GREEN}✓ Build completed successfully!{Colors.NC}")
            print()
            print(f"Version: {Colors.BLUE}{self.config.VERSION}{Colors.NC}")
            print()
            
            # Show output locations
            dist_dir = self.project_root / self.config.DIST_DIR
            
            print("Output locations:")
            
            if self.config.BUILD_INSTALLER:
                installer_name = f"DrumEngine01-{self.config.VERSION}-Installer.pkg"
                installer_path = dist_dir / "installer" / installer_name
                if installer_path.exists():
                    print(f"  📦 Installer: {installer_path}")
            
            factory_content = dist_dir / "factory-content"
            if factory_content.exists():
                print(f"  📁 Factory Content: {factory_content}")
            
            print()
            return True
    
    def run(self):
        """Execute the full build process"""
        print()
        print(f"{Colors.BLUE}{'='*70}{Colors.NC}")
        print(f"{Colors.BLUE}DrumEngine01 Build Process{Colors.NC}")
        print(f"{Colors.BLUE}{'='*70}{Colors.NC}")
        print()
        
        steps = [
            self.step_clean_build,
            self.step_configure_cmake,
            self.step_build_plugins,
            self.step_package_content,
            self.step_build_installer,
        ]
        
        for step in steps:
            if not step():
                print(f"{Colors.RED}Build failed. Stopping.{Colors.NC}")
                self.print_summary()
                return 1
        
        success = self.print_summary()
        return 0 if success else 1


def main():
    parser = argparse.ArgumentParser(
        description='Build DrumEngine01 from configuration',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        '--config',
        default='build_config.py',
        help='Path to configuration file (default: build_config.py)'
    )
    
    args = parser.parse_args()
    
    orchestrator = BuildOrchestrator(config_path=args.config)
    return orchestrator.run()


if __name__ == "__main__":
    sys.exit(main())
