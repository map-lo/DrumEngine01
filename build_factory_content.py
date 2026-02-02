#!/usr/bin/env python3
"""
DrumEngine01 Factory Content Build Script
Builds factory content installer (signed/notarized if configured)

Usage:
    python build_factory_content.py
    python build_factory_content.py --only-pkg
    python build_factory_content.py --only-installer
    python build_factory_content.py --only-notarize --installer-path /path/to/DrumEngine01-FactoryContent-1.2.3.pkg
"""

import argparse
import importlib.util
import os
import subprocess
import sys
from pathlib import Path


class Colors:
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    RED = '\033[0;31m'
    BLUE = '\033[0;34m'
    NC = '\033[0m'


def load_config(project_root: Path):
    config_file = project_root / "build_config_factory_content.py"
    if not config_file.exists():
        print(f"{Colors.RED}Error: Config file not found: {config_file}{Colors.NC}")
        sys.exit(1)

    spec = importlib.util.spec_from_file_location("build_config", config_file)
    config = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(config)
    return config


def run_command(cmd, cwd: Path, description: str, env: dict | None = None):
    print(f"{Colors.BLUE}▶ {description}{Colors.NC}")
    print(f"  Command: {' '.join(cmd)}")
    print()

    try:
        subprocess.run(cmd, cwd=cwd, check=True, capture_output=False, text=True, env=env)
        return True
    except subprocess.CalledProcessError as e:
        print(f"{Colors.RED}✗ Command failed with exit code {e.returncode}{Colors.NC}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Build factory content installer only")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--only-pkg", action="store_true", help="Only build the content pkg (no installer)")
    group.add_argument("--only-installer", action="store_true", help="Only build installer from existing content pkg")
    group.add_argument("--only-notarize", action="store_true", help="Only notarize an existing content installer")
    parser.add_argument("--installer-path", type=str, help="Path to existing content installer for notarization")

    args = parser.parse_args()
    project_root = Path(__file__).parent
    config = load_config(project_root)

    print()
    print(f"{Colors.BLUE}{'='*70}{Colors.NC}")
    print(f"{Colors.BLUE}DrumEngine01 Factory Content Build (Release Config){Colors.NC}")
    print(f"{Colors.BLUE}{'='*70}{Colors.NC}")
    print()

    presets_dir = project_root / "presets"
    if not presets_dir.exists():
        print(f"{Colors.RED}Error: Presets directory not found: {presets_dir}{Colors.NC}")
        return 1

    print(f"Using presets directly from: {presets_dir}")
    print()

    installer_dir = project_root / config.INSTALLER_DIR
    script = installer_dir / "build_installer.sh"

    env = os.environ.copy()
    env["DRUMENGINE_VERSION"] = config.VERSION
    env["DRUMENGINE_BUILD_NUMBER"] = "0"
    env["FACTORY_CONTENT_VERSION"] = str(getattr(config, "FACTORY_CONTENT_VERSION", config.VERSION))
    env["BUILD_PLUGINS_INSTALLER"] = "false"
    env["BUILD_CONTENT_PKG"] = "true"
    env["BUILD_CONTENT_INSTALLER"] = "true"
    env["NOTARIZE_CONTENT_INSTALLER"] = "false"

    if args.only_pkg:
        env["BUILD_CONTENT_INSTALLER"] = "false"
        env["NOTARIZE_CONTENT_INSTALLER"] = "false"
    elif args.only_installer:
        env["BUILD_CONTENT_PKG"] = "false"
        env["NOTARIZE_CONTENT_INSTALLER"] = "false"
    elif args.only_notarize:
        env["BUILD_CONTENT_PKG"] = "false"
        env["BUILD_CONTENT_INSTALLER"] = "false"
        env["NOTARIZE_CONTENT_INSTALLER"] = "true"
        if args.installer_path:
            env["CONTENT_INSTALLER_PATH"] = args.installer_path
        else:
            print(f"{Colors.RED}Error: --installer-path is required with --only-notarize{Colors.NC}")
            return 1

    if hasattr(config, "CONTENT_PKG_CACHE_DIR") and config.CONTENT_PKG_CACHE_DIR:
        cache_dir = Path(config.CONTENT_PKG_CACHE_DIR)
        if not cache_dir.is_absolute():
            cache_dir = project_root / cache_dir
        env["CONTENT_PKG_CACHE_DIR"] = str(cache_dir)

    if hasattr(config, "INSTALLER_CODE_SIGN_IDENTITY") and config.INSTALLER_CODE_SIGN_IDENTITY:
        env["INSTALLER_CODE_SIGN_IDENTITY"] = str(config.INSTALLER_CODE_SIGN_IDENTITY)

    if hasattr(config, "NOTARYTOOL_PROFILE") and config.NOTARYTOOL_PROFILE:
        env["NOTARYTOOL_PROFILE"] = str(config.NOTARYTOOL_PROFILE)

    if hasattr(config, "APPLE_ID") and config.APPLE_ID:
        env["APPLE_ID"] = str(config.APPLE_ID)

    if hasattr(config, "TEAM_ID") and config.TEAM_ID:
        env["TEAM_ID"] = str(config.TEAM_ID)

    if hasattr(config, "APPLE_APP_SPECIFIC_PASSWORD") and config.APPLE_APP_SPECIFIC_PASSWORD:
        env["APPLE_APP_SPECIFIC_PASSWORD"] = str(config.APPLE_APP_SPECIFIC_PASSWORD)

    return 0 if run_command([str(script)], installer_dir, "Building factory content installer", env=env) else 1


if __name__ == "__main__":
    sys.exit(main())
