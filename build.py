#!/usr/bin/env python3
"""
DrumEngine01 Build Script

Orchestrates the entire build process based on build configuration:
1. Build WebView UI (Vite dist)
2. Configure and build plugins with CMake
3. Sign macOS plugins (VST3/AU)
4. Sign AAX plugins with PACE wraptool
5. Package factory content (presets)
6. Build macOS installer

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
    def __init__(
        self,
        build_type: str,
        skip_signing: bool = False,
        run_build: bool = True,
        run_package: bool = True,
        run_sign: bool = True,
    ):
        self.project_root = Path(__file__).parent
        self.build_type = build_type  # "dev" or "release"
        self.cmake_build_type = "Debug" if build_type == "dev" else "Release"
        self.skip_signing = skip_signing
        self.run_build = run_build
        self.run_package = run_package
        self.run_sign = run_sign
        self.build_number_path = self.project_root / "build_number.txt"
        
        # Load appropriate config file
        config_file = f"build_config_{build_type}.py"
        self.config = self.load_config(config_file)
        self.build_number = self.increment_build_number()
        self.config.BUILD_NUMBER = self.build_number
        self.errors = []

        print(f"  Build Number: {self.build_number}")
        print()
        
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

    def read_build_number(self) -> int:
        if not self.build_number_path.exists():
            return 0

        try:
            return int(self.build_number_path.read_text().strip())
        except ValueError:
            return 0

    def write_build_number(self, number: int):
        self.build_number_path.write_text(f"{number}\n")

    def increment_build_number(self) -> int:
        current = self.read_build_number()
        next_number = current + 1
        self.write_build_number(next_number)
        return next_number
    
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

    def step_build_ui(self):
        """Step 3: Build WebView UI (Vite dist)"""
        print(f"{Colors.GREEN}{'='*70}{Colors.NC}")
        print(f"{Colors.GREEN}Step 3: Building WebView UI (Vite dist){Colors.NC}")
        print(f"{Colors.GREEN}{'='*70}{Colors.NC}")
        print()

        ui_dir = self.project_root / "src" / "ui"
        if not ui_dir.exists():
            print(f"{Colors.RED}Error: UI directory not found: {ui_dir}{Colors.NC}")
            self.errors.append(f"UI directory not found: {ui_dir}")
            return False

        return self.run_command(
            ["npm", "run", "build"],
            cwd=ui_dir,
            description="Building UI bundle with Vite"
        )
    
    def step_configure_cmake(self):
        """Step 4: Configure CMake"""
        print(f"{Colors.GREEN}{'='*70}{Colors.NC}")
        print(f"{Colors.GREEN}Step 4: Configuring CMake{Colors.NC}")
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
        """Step 5: Build plugins"""
        print(f"{Colors.GREEN}{'='*70}{Colors.NC}")
        print(f"{Colors.GREEN}Step 5: Building Plugins{Colors.NC}")
        print(f"{Colors.GREEN}{'='*70}{Colors.NC}")
        print()
        
        build_dir = self.project_root / self.config.BUILD_DIR
        
        return self.run_command(
            ["cmake", "--build", ".", "--config", self.cmake_build_type],
            cwd=build_dir,
            description=f"Building plugins ({self.cmake_build_type})"
        )
    
    def step_sign_macos_plugins(self):
        """Step 6: Sign macOS plugins (VST3/AU)"""
        if not getattr(self.config, "SIGN_MAC_PLUGINS", False):
            print(f"{Colors.YELLOW}Skipping macOS plugin signing (SIGN_MAC_PLUGINS=False){Colors.NC}")
            print()
            return True

        identity = getattr(self.config, "MAC_CODE_SIGN_IDENTITY", None)
        if not identity:
            print(f"{Colors.RED}Error: MAC_CODE_SIGN_IDENTITY not set in build config{Colors.NC}")
            self.errors.append("MAC_CODE_SIGN_IDENTITY not set")
            print()
            return False

        print(f"{Colors.GREEN}{'='*70}{Colors.NC}")
        print(f"{Colors.GREEN}Step 6: Signing macOS Plugins (VST3/AU){Colors.NC}")
        print(f"{Colors.GREEN}{'='*70}{Colors.NC}")
        print()

        if self.build_type == "dev":
            plugin_name = "DrumEngine01Dev"
            cmake_build_type = "Debug"
        else:
            plugin_name = "DrumEngine01"
            cmake_build_type = "Release"

        artefacts_dir = self.project_root / "build" / "DrumEngine01_artefacts" / cmake_build_type
        plugins_to_sign = []

        if "VST3" in self.config.PLUGIN_FORMATS:
            plugins_to_sign.append(("VST3", artefacts_dir / "VST3" / f"{plugin_name}.vst3"))

        if "AU" in self.config.PLUGIN_FORMATS:
            plugins_to_sign.append(("AU", artefacts_dir / "AU" / f"{plugin_name}.component"))

        if not plugins_to_sign:
            print(f"{Colors.YELLOW}No macOS plugin formats configured for signing{Colors.NC}")
            print()
            return True

        for fmt, plugin_path in plugins_to_sign:
            if not plugin_path.exists():
                print(f"{Colors.YELLOW}{fmt} plugin not found: {plugin_path}{Colors.NC}")
                print(f"{Colors.YELLOW}Skipping signing for {fmt}{Colors.NC}")
                print()
                continue

            print(f"Signing {fmt} plugin:")
            print(f"  Path: {plugin_path}")
            print()

            if not self.run_command(
                ["codesign", "--force", "--deep", "--options", "runtime", "--timestamp", "--sign", identity, str(plugin_path)],
                description=f"Code signing {fmt} plugin"
            ):
                return False

        print(f"{Colors.GREEN}✓ macOS plugin signing completed{Colors.NC}")
        print()
        return True

    def step_sign_aax(self):
        """Step 7: Sign AAX plugins with PACE wraptool"""
        if not self.config.SIGN_AAX or self.skip_signing:
            reason = "skipped by --skip-signing flag" if self.skip_signing else "SIGN_AAX=False"
            print(f"{Colors.YELLOW}Skipping AAX signing ({reason}){Colors.NC}")
            print()
            return True
        
        print(f"{Colors.GREEN}{'='*70}{Colors.NC}")
        print(f"{Colors.GREEN}Step 7: Signing AAX Plugins{Colors.NC}")
        print(f"{Colors.GREEN}{'='*70}{Colors.NC}")
        print()
        
        sign_script = self.project_root / "sign_aax.py"
        
        if not sign_script.exists():
            print(f"{Colors.YELLOW}Warning: sign_aax.py not found, skipping AAX signing{Colors.NC}")
            print()
            return True
        
        if not self.run_command(
            ["python3", str(sign_script), f"--build-type={self.build_type}"],
            description="Signing AAX plugins with PACE wraptool"
        ):
            return False

        return True

    def step_install_signed_aax(self):
        """Step 8: Copy signed AAX plugin to system location"""
        if not self.config.SIGN_AAX or self.skip_signing:
            reason = "skipped by --skip-signing flag" if self.skip_signing else "SIGN_AAX=False"
            print(f"{Colors.YELLOW}Skipping signed AAX install ({reason}){Colors.NC}")
            print()
            return True

        print(f"{Colors.GREEN}{'='*70}{Colors.NC}")
        print(f"{Colors.GREEN}Step 8: Installing Signed AAX Plugin{Colors.NC}")
        print(f"{Colors.GREEN}{'='*70}{Colors.NC}")
        print()

        if self.build_type == "dev":
            plugin_name = "DrumEngine01Dev"
            cmake_build_type = "Debug"
        else:
            plugin_name = "DrumEngine01"
            cmake_build_type = "Release"

        signed_aax = self.project_root / "build" / "DrumEngine01_artefacts" / cmake_build_type / "AAX" / f"{plugin_name}.aaxplugin"
        system_aax_dir = Path("/Library/Application Support/Avid/Audio/Plug-Ins")
        system_aax = system_aax_dir / f"{plugin_name}.aaxplugin"

        if not signed_aax.exists():
            print(f"{Colors.YELLOW}Signed AAX plugin not found: {signed_aax}{Colors.NC}")
            print(f"{Colors.YELLOW}Skipping system install for AAX{Colors.NC}")
            print()
            return True

        print(f"Installing signed AAX plugin to system location:")
        print(f"  Source: {signed_aax}")
        print(f"  Target: {system_aax}")
        print()

        if not self.run_command(
            ["sudo", "mkdir", "-p", str(system_aax_dir)],
            description="Ensuring AAX system directory exists"
        ):
            return False

        if system_aax.exists():
            if not self.run_command(
                ["sudo", "rm", "-rf", str(system_aax)],
                description="Removing existing system AAX plugin"
            ):
                return False

        if not self.run_command(
            ["sudo", "cp", "-R", str(signed_aax), str(system_aax)],
            description="Copying signed AAX plugin to system location"
        ):
            return False

        print(f"{Colors.GREEN}✓ Signed AAX plugin installed to system location{Colors.NC}")
        print()
        return True

    def step_install_vst3_au(self):
        """Step 9: Copy VST3/AU plugins to system locations"""
        print(f"{Colors.GREEN}{'='*70}{Colors.NC}")
        print(f"{Colors.GREEN}Step 9: Installing VST3/AU Plugins{Colors.NC}")
        print(f"{Colors.GREEN}{'='*70}{Colors.NC}")
        print()

        if self.build_type == "dev":
            plugin_name = "DrumEngine01Dev"
            cmake_build_type = "Debug"
        else:
            plugin_name = "DrumEngine01"
            cmake_build_type = "Release"

        artefacts_dir = self.project_root / "build" / "DrumEngine01_artefacts" / cmake_build_type
        installs = []

        if "VST3" in self.config.PLUGIN_FORMATS:
            vst3_src = artefacts_dir / "VST3" / f"{plugin_name}.vst3"
            vst3_dest_dir = Path("/Library/Audio/Plug-Ins/VST3")
            vst3_dest = vst3_dest_dir / f"{plugin_name}.vst3"
            installs.append(("VST3", vst3_src, vst3_dest_dir, vst3_dest))

        if "AU" in self.config.PLUGIN_FORMATS:
            au_src = artefacts_dir / "AU" / f"{plugin_name}.component"
            au_dest_dir = Path("/Library/Audio/Plug-Ins/Components")
            au_dest = au_dest_dir / f"{plugin_name}.component"
            installs.append(("AU", au_src, au_dest_dir, au_dest))

        if not installs:
            print(f"{Colors.YELLOW}No VST3/AU formats configured for install{Colors.NC}")
            print()
            return True

        for fmt, src, dest_dir, dest in installs:
            if not src.exists():
                print(f"{Colors.YELLOW}{fmt} plugin not found: {src}{Colors.NC}")
                print(f"{Colors.YELLOW}Skipping system install for {fmt}{Colors.NC}")
                print()
                continue

            print(f"Installing {fmt} plugin to system location:")
            print(f"  Source: {src}")
            print(f"  Target: {dest}")
            print()

            if not self.run_command(
                ["sudo", "mkdir", "-p", str(dest_dir)],
                description=f"Ensuring {fmt} system directory exists"
            ):
                return False

            if dest.exists():
                if not self.run_command(
                    ["sudo", "rm", "-rf", str(dest)],
                    description=f"Removing existing system {fmt} plugin"
                ):
                    return False

            if not self.run_command(
                ["sudo", "cp", "-R", str(src), str(dest)],
                description=f"Copying {fmt} plugin to system location"
            ):
                return False

        print(f"{Colors.GREEN}✓ VST3/AU plugins installed to system locations{Colors.NC}")
        print()
        return True
    
    def step_package_content(self):
        """Step 10: Package factory content"""
        if not self.config.BUILD_INSTALLER:
            print(f"{Colors.YELLOW}Skipping content packaging (BUILD_INSTALLER=False){Colors.NC}")
            print()
            return True
        
        print(f"{Colors.GREEN}{'='*70}{Colors.NC}")
        print(f"{Colors.GREEN}Step 10: Packaging Factory Content{Colors.NC}")
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
            description="Packaging presets"
        )
    
    def step_build_installer(self):
        """Step 11: Build installer"""
        if not self.config.BUILD_INSTALLER:
            print(f"{Colors.YELLOW}Skipping installer build (BUILD_INSTALLER=False){Colors.NC}")
            print()
            return True
        
        print(f"{Colors.GREEN}{'='*70}{Colors.NC}")
        print(f"{Colors.GREEN}Step 11: Building Installer{Colors.NC}")
        print(f"{Colors.GREEN}{'='*70}{Colors.NC}")
        print()
        
        installer_dir = self.project_root / self.config.INSTALLER_DIR
        script = installer_dir / "build_installer.sh"
        
        # Pass version and build type to installer script
        env = os.environ.copy()
        env['DRUMENGINE_VERSION'] = self.config.VERSION
        env['DRUMENGINE_BUILD_TYPE'] = self.build_type
        env['DRUMENGINE_BUILD_NUMBER'] = str(self.config.BUILD_NUMBER)

        if hasattr(self.config, "NOTARIZE_COMPONENT_PKGS"):
            env['NOTARIZE_COMPONENT_PKGS'] = "true" if self.config.NOTARIZE_COMPONENT_PKGS else "false"

        if hasattr(self.config, "INSTALLER_CODE_SIGN_IDENTITY") and self.config.INSTALLER_CODE_SIGN_IDENTITY:
            env['INSTALLER_CODE_SIGN_IDENTITY'] = str(self.config.INSTALLER_CODE_SIGN_IDENTITY)

        if hasattr(self.config, "NOTARYTOOL_PROFILE") and self.config.NOTARYTOOL_PROFILE:
            env['NOTARYTOOL_PROFILE'] = str(self.config.NOTARYTOOL_PROFILE)

        if hasattr(self.config, "APPLE_ID") and self.config.APPLE_ID:
            env['APPLE_ID'] = str(self.config.APPLE_ID)

        if hasattr(self.config, "TEAM_ID") and self.config.TEAM_ID:
            env['TEAM_ID'] = str(self.config.TEAM_ID)

        if hasattr(self.config, "APPLE_APP_SPECIFIC_PASSWORD") and self.config.APPLE_APP_SPECIFIC_PASSWORD:
            env['APPLE_APP_SPECIFIC_PASSWORD'] = str(self.config.APPLE_APP_SPECIFIC_PASSWORD)
        
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
            print(f"Version: {Colors.BLUE}{self.config.VERSION}{Colors.NC}")
            print(f"Build Number: {Colors.BLUE}{self.config.BUILD_NUMBER}{Colors.NC}")
            print()
            
            # Show output locations
            dist_dir = self.project_root / self.config.DIST_DIR
            
            print("Output locations:")
            
            if self.config.BUILD_INSTALLER:
                plugin_name = "DrumEngine01Dev" if self.build_type == "dev" else "DrumEngine01"
                installer_name = f"{plugin_name}-{self.config.VERSION}-b{self.config.BUILD_NUMBER}-Installer.pkg"
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
        
        steps = []

        if self.run_build:
            steps.extend([
                self.step_clean_build,
                self.step_remove_installed_plugins,
                self.step_build_ui,
                self.step_configure_cmake,
                self.step_build_plugins,
            ])

        if self.run_package:
            steps.append(self.step_package_content)

        if self.run_sign:
            steps.extend([
                self.step_sign_macos_plugins,
                self.step_sign_aax,
                self.step_install_signed_aax,
                self.step_install_vst3_au,
                self.step_build_installer,
            ])
        
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

    parser.add_argument(
        '--skip-build',
        action='store_true',
        help='Skip build steps (clean, UI, configure, compile)'
    )

    parser.add_argument(
        '--skip-package',
        action='store_true',
        help='Skip packaging presets'
    )

    parser.add_argument(
        '--skip-sign',
        action='store_true',
        help='Skip signing/notarization steps (macOS/AAX/installer)'
    )
    
    args = parser.parse_args()
    
    build_type = "dev" if args.dev else "release"
    orchestrator = BuildOrchestrator(
        build_type=build_type,
        skip_signing=args.skip_signing,
        run_build=not args.skip_build,
        run_package=not args.skip_package,
        run_sign=not args.skip_sign,
    )
    return orchestrator.run()


if __name__ == "__main__":
    sys.exit(main())
