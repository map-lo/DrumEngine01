#!/usr/bin/env python3
"""
DrumEngine01 Build Script

Orchestrates the entire build process based on build configuration:
1. Configure and build plugins with CMake
2. Sign AAX plugins with PACE wraptool
3. Package factory content (presets and samples)
4. Build macOS installer

Usage:
    python build.py --dev              Build development version (DrumEngine01Dev)
    python build.py --release          Build release version (DrumEngine01)
    python build.py --dev --skip-signing    Build dev without AAX signing
    
Options:
    --dev           Build development version (uses build_config_dev.py, CMAKE_BUILD_TYPE=Debug)
    --release       Build release version (uses build_config_release.py, CMAKE_BUILD_TYPE=Release)
    --skip-signing  Skip AAX signing step even if SIGN_AAX=True in config
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
    def __init__(self, build_type: str, skip_signing: bool = False):
        self.project_root = Path(__file__).parent
        self.build_type = build_type  # "dev" or "release"
        self.cmake_build_type = "Debug" if build_type == "dev" else "Release"
        self.skip_signing = skip_signing
        
        # Load appropriate config file
        config_file = f"build_config_{build_type}.py"
        self.config = self.load_config(config_file)
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
        print(f"  Build Type: {self.build_type.upper()} (CMAKE_BUILD_TYPE={self.cmake_build_type})")
        print(f"  Plugin Name: {'DrumEngine01Dev' if self.build_type == 'dev' else 'DrumEngine01'}")
        print(f"  Plugin Code: {'Den0' if self.build_type == 'dev' else 'Den1'}")
        print(f"  Preset Limit: {config.PRESET_LIMIT or 'None (all presets)'}")
        print(f"  Clean Build: {config.CLEAN_BUILD}")
        print(f"  Build Installer: {config.BUILD_INSTALLER}")
        print(f"  Sign AAX: {config.SIGN_AAX and not self.skip_signing}")
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
    
    def step_remove_installed_plugins(self):
        """Step 2: Remove system-level installed plugins (for dev builds)"""
        if self.build_type != "dev":
            print(f"{Colors.YELLOW}Skipping plugin removal (not a dev build){Colors.NC}")
            print()
            return True
        
        print(f"{Colors.GREEN}{'='*70}{Colors.NC}")
        print(f"{Colors.GREEN}Step 2: Removing System-Level Installed Plugins{Colors.NC}")
        print(f"{Colors.GREEN}{'='*70}{Colors.NC}")
        print()
        
        # System-level plugin directories (where installer puts them)
        system_vst3 = Path("/Library/Audio/Plug-Ins/VST3/DrumEngine01.vst3")
        system_au = Path("/Library/Audio/Plug-Ins/Components/DrumEngine01.component")
        
        plugins_to_remove = []
        
        if system_vst3.exists():
            plugins_to_remove.append(("VST3", system_vst3))
        
        if system_au.exists():
            plugins_to_remove.append(("AU", system_au))
        
        if not plugins_to_remove:
            print(f"No system plugins found to remove")
            print()
            return True
        
        # Need sudo to remove system-level plugins
        print(f"{Colors.YELLOW}Removing system-level plugins requires administrator privileges{Colors.NC}")
        
        for plugin_type, plugin_path in plugins_to_remove:
            print(f"Removing system {plugin_type}: {plugin_path}")
            if not self.run_command(
                ["sudo", "rm", "-rf", str(plugin_path)],
                description=f"Removing {plugin_type} plugin"
            ):
                print(f"{Colors.RED}Failed to remove {plugin_type} plugin{Colors.NC}")
                return False
        
        print(f"{Colors.GREEN}✓ System plugins removed (dev build will be used){Colors.NC}")
        print()
        return True
    
    def step_configure_cmake(self):
        """Step 3: Configure CMake"""
        print(f"{Colors.GREEN}{'='*70}{Colors.NC}")
        print(f"{Colors.GREEN}Step 3: Configuring CMake{Colors.NC}")
        print(f"{Colors.GREEN}{'='*70}{Colors.NC}")
        print()
        
        build_dir = self.project_root / self.config.BUILD_DIR
        build_dir.mkdir(exist_ok=True)
        
        return self.run_command(
            ["cmake", "..", f"-DCMAKE_BUILD_TYPE={self.cmake_build_type}"],
            cwd=build_dir,
            description="Configuring CMake"
        )
    
    def step_build_plugins(self):
        """Step 4: Build plugins"""
        print(f"{Colors.GREEN}{'='*70}{Colors.NC}")
        print(f"{Colors.GREEN}Step 4: Building Plugins{Colors.NC}")
        print(f"{Colors.GREEN}{'='*70}{Colors.NC}")
        print()
        
        build_dir = self.project_root / self.config.BUILD_DIR
        
        return self.run_command(
            ["cmake", "--build", ".", "--config", self.cmake_build_type],
            cwd=build_dir,
            description=f"Building plugins ({self.cmake_build_type})"
        )
    
    def step_sign_aax(self):
        """Step 5: Sign AAX plugins with PACE wraptool"""
        if not self.config.SIGN_AAX or self.skip_signing:
            reason = "skipped by --skip-signing flag" if self.skip_signing else "SIGN_AAX=False"
            print(f"{Colors.YELLOW}Skipping AAX signing ({reason}){Colors.NC}")
            print()
            return True
        
        print(f"{Colors.GREEN}{'='*70}{Colors.NC}")
        print(f"{Colors.GREEN}Step 5: Signing AAX Plugins{Colors.NC}")
        print(f"{Colors.GREEN}{'='*70}{Colors.NC}")
        print()
        
        sign_script = self.project_root / "sign_aax.py"
        
        if not sign_script.exists():
            print(f"{Colors.YELLOW}Warning: sign_aax.py not found, skipping AAX signing{Colors.NC}")
            print()
            return True
        
        return self.run_command(
            ["python3", str(sign_script), f"--build-type={self.build_type}"],
            description="Signing AAX plugins with PACE wraptool"
        )
    
    def step_package_content(self):
        """Step 6: Package factory content"""
        if not self.config.BUILD_INSTALLER:
            print(f"{Colors.YELLOW}Skipping content packaging (BUILD_INSTALLER=False){Colors.NC}")
            print()
            return True
        
        print(f"{Colors.GREEN}{'='*70}{Colors.NC}")
        print(f"{Colors.GREEN}Step 6: Packaging Factory Content{Colors.NC}")
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
        """Step 7: Build installer"""
        if not self.config.BUILD_INSTALLER:
            print(f"{Colors.YELLOW}Skipping installer build (BUILD_INSTALLER=False){Colors.NC}")
            print()
            return True
        
        print(f"{Colors.GREEN}{'='*70}{Colors.NC}")
        print(f"{Colors.GREEN}Step 7: Building Installer{Colors.NC}")
        print(f"{Colors.GREEN}{'='*70}{Colors.NC}")
        print()
        
        installer_dir = self.project_root / self.config.INSTALLER_DIR
        script = installer_dir / "build_installer.sh"
        
        # Pass version and build type to installer script
        env = os.environ.copy()
        env['DRUMENGINE_VERSION'] = self.config.VERSION
        env['DRUMENGINE_BUILD_TYPE'] = self.build_type
        
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
            print(f"Build: {Colors.BLUE}{self.build_type.upper()}{Colors.NC}")
            print()
            
            # Show output locations
            dist_dir = self.project_root / self.config.DIST_DIR
            
            print("Output locations:")
            
            if self.config.BUILD_INSTALLER:
                plugin_name = "DrumEngine01Dev" if self.build_type == "dev" else "DrumEngine01"
                installer_name = f"{plugin_name}-{self.config.VERSION}-Installer.pkg"
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
            self.step_remove_installed_plugins,
            self.step_configure_cmake,
            self.step_build_plugins,
            self.step_sign_aax,
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
        description='Build DrumEngine01 plugin',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python build.py --dev              Build development version
  python build.py --release          Build release version  
  python build.py --dev --skip-signing    Build dev without AAX signing
        '''
    )
    
    build_group = parser.add_mutually_exclusive_group(required=True)
    build_group.add_argument(
        '--dev',
        action='store_true',
        help='Build development version (DrumEngine01Dev with code Den0)'
    )
    build_group.add_argument(
        '--release',
        action='store_true',
        help='Build release version (DrumEngine01 with code Den1)'
    )
    
    parser.add_argument(
        '--skip-signing',
        action='store_true',
        help='Skip AAX signing step (useful for testing builds without PACE config)'
    )
    
    args = parser.parse_args()
    
    build_type = "dev" if args.dev else "release"
    orchestrator = BuildOrchestrator(build_type=build_type, skip_signing=args.skip_signing)
    return orchestrator.run()


if __name__ == "__main__":
    sys.exit(main())
