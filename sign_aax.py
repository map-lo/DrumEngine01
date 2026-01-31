#!/usr/bin/env python3
"""
AAX Plugin Signing Script

Signs AAX plugins using PACE wraptool from the Eden SDK.
This script is called by build.py after the CMake build completes.

Usage:
    python sign_aax.py --build-type=dev
    python sign_aax.py --build-type=release
"""

import argparse
import subprocess
import sys
from pathlib import Path


class Colors:
    """ANSI color codes for terminal output"""
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    RED = '\033[0;31m'
    BLUE = '\033[0;34m'
    NC = '\033[0m'  # No Color


def load_pace_config():
    """Load PACE configuration"""
    pace_config_path = Path(__file__).parent / "pace_config.py"
    
    if not pace_config_path.exists():
        print(f"{Colors.YELLOW}╔═══════════════════════════════════════════════════════════════╗{Colors.NC}")
        print(f"{Colors.YELLOW}║  PACE Configuration Not Found                                 ║{Colors.NC}")
        print(f"{Colors.YELLOW}╚═══════════════════════════════════════════════════════════════╝{Colors.NC}")
        print()
        print(f"AAX signing requires PACE Eden SDK credentials.")
        print()
        print(f"To set up PACE signing:")
        print(f"  1. Copy {Colors.BLUE}pace_config_template.py{Colors.NC} to {Colors.BLUE}pace_config.py{Colors.NC}")
        print(f"  2. Fill in your PACE credentials in pace_config.py")
        print(f"  3. Re-run the build")
        print()
        print(f"To skip signing during development:")
        print(f"  python build.py --dev --skip-signing")
        print()
        return None
    
    # Load config module
    import importlib.util
    spec = importlib.util.spec_from_file_location("pace_config", pace_config_path)
    config = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(config)
    
    return config


def validate_pace_config(config):
    """Validate that PACE config has required fields"""
    required_fields = ['WRAPTOOL_PATH', 'ACCOUNT_ID', 'ACCOUNT_PASSWORD', 'WCGUID', 'SIGNID']
    
    for field in required_fields:
        if not hasattr(config, field):
            print(f"{Colors.RED}Error: Missing {field} in pace_config.py{Colors.NC}")
            return False
        
        value = getattr(config, field)
        if not value or value.startswith("your-") or value.startswith("/path/to/"):
            print(f"{Colors.RED}Error: {field} not configured in pace_config.py{Colors.NC}")
            print(f"{Colors.YELLOW}Please edit pace_config.py and set your PACE credentials{Colors.NC}")
            return False
    
    wraptool_path = Path(config.WRAPTOOL_PATH)
    if not wraptool_path.exists():
        print(f"{Colors.RED}Error: wraptool not found at: {wraptool_path}{Colors.NC}")
        print(f"{Colors.YELLOW}Please check WRAPTOOL_PATH in pace_config.py{Colors.NC}")
        return False
    
    return True


def sign_aax_plugin(aax_path: Path, config, build_type: str) -> bool:
    """Sign an AAX plugin with PACE wraptool"""
    
    if not aax_path.exists():
        print(f"{Colors.YELLOW}AAX plugin not found: {aax_path}{Colors.NC}")
        print(f"{Colors.YELLOW}Skipping signing for this format{Colors.NC}")
        return True
    
    print(f"{Colors.BLUE}Signing: {aax_path.name}{Colors.NC}")
    
    # Determine which signid to use
    if build_type == "dev" and hasattr(config, 'DEV_SIGNID') and config.DEV_SIGNID:
        signid = config.DEV_SIGNID
    elif build_type == "release" and hasattr(config, 'RELEASE_SIGNID') and config.RELEASE_SIGNID:
        signid = config.RELEASE_SIGNID
    else:
        signid = config.SIGNID
    
    # Build wraptool command
    # Note: wraptool signs in-place, modifying the original .aaxplugin bundle
    cmd = [
        config.WRAPTOOL_PATH,
        "sign",
        "--verbose",
        "--account", config.ACCOUNT_ID,
        "--password", config.ACCOUNT_PASSWORD,
        "--wcguid", config.WCGUID,
        "--signid", signid,
        "--in", str(aax_path),
        "--out", str(aax_path)  # Sign in-place
    ]
    
    print(f"  Command: {config.WRAPTOOL_PATH} sign --account *** --password *** --wcguid *** --signid *** --in {aax_path.name} --out {aax_path.name}")
    print()
    
    try:
        result = subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True
        )
        
        print(f"{Colors.GREEN}✓ Successfully signed {aax_path.name}{Colors.NC}")
        
        # Show wraptool output if verbose
        if result.stdout:
            print(f"{Colors.BLUE}Wraptool output:{Colors.NC}")
            print(result.stdout)
        
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"{Colors.RED}✗ Failed to sign {aax_path.name}{Colors.NC}")
        print(f"{Colors.RED}Error: {e}{Colors.NC}")
        
        if e.stdout:
            print(f"\nOutput:\n{e.stdout}")
        if e.stderr:
            print(f"\nError output:\n{e.stderr}")
        
        return False


def main():
    parser = argparse.ArgumentParser(description='Sign AAX plugins with PACE wraptool')
    parser.add_argument(
        '--build-type',
        choices=['dev', 'release'],
        help='Build type (dev or release) - determines plugin name if --aax-path not provided'
    )
    parser.add_argument(
        '--aax-path',
        type=str,
        help='Path to specific AAX plugin to sign (overrides build-type path)'
    )
    
    args = parser.parse_args()
    
    # Require either build-type or aax-path
    if not args.build_type and not args.aax_path:
        parser.error('Either --build-type or --aax-path must be specified')
    
    if args.aax_path and not args.build_type:
        # Infer build type from path if possible, or default to 'dev'
        args.build_type = 'dev'
    
    print()
    print(f"{Colors.GREEN}{'='*70}{Colors.NC}")
    print(f"{Colors.GREEN}AAX Plugin Signing with PACE Wraptool{Colors.NC}")
    print(f"{Colors.GREEN}{'='*70}{Colors.NC}")
    print()
    
    # Load PACE configuration
    config = load_pace_config()
    if config is None:
        return 1
    
    if not validate_pace_config(config):
        return 1
    
    print(f"{Colors.BLUE}PACE Configuration:{Colors.NC}")
    print(f"  Account: {config.ACCOUNT_ID}")
    print(f"  Wraptool: {config.WRAPTOOL_PATH}")
    print()
    
    # Determine AAX plugin path
    if args.aax_path:
        # Use provided path
        aax_path = Path(args.aax_path)
        print(f"Signing AAX plugin from custom path...")
        print(f"  Path: {aax_path}")
        print()
    else:
        # Determine plugin name and path based on build type
        project_root = Path(__file__).parent
        
        if args.build_type == "dev":
            plugin_name = "DrumEngine01Dev"
            cmake_build_type = "Debug"
        else:
            plugin_name = "DrumEngine01"
            cmake_build_type = "Release"
        
        # AAX plugin path
        aax_path = project_root / "build" / "DrumEngine01_artefacts" / cmake_build_type / "AAX" / f"{plugin_name}.aaxplugin"
        
        print(f"Signing AAX plugin for {args.build_type} build...")
        print()
    
    # Sign the AAX plugin
    success = sign_aax_plugin(aax_path, config, args.build_type)
    
    print()
    if success:
        print(f"{Colors.GREEN}✓ AAX signing completed successfully{Colors.NC}")
        return 0
    else:
        print(f"{Colors.RED}✗ AAX signing failed{Colors.NC}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
