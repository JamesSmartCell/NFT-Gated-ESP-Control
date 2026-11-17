Import("env")
import subprocess
import os

def get_git_version():
    """
    Generate firmware version string: <PROJECT_ID>@<SEMVER>+<SHORTHASH>
    Example: garagedoor@1.2.0+ab12cd3
    
    - PROJECT_ID: from build flag, default "garagedoor"
    - SEMVER: from FIRMWARE_VERSION define in code
    - SHORTHASH: git commit SHA (7 chars), add -dirty if working tree modified
    """
    try:
        repo_root = env['PROJECT_DIR']
        
        # Get short git SHA (7 characters)
        git_sha = subprocess.check_output(
            ['git', 'rev-parse', '--short=7', 'HEAD'],
            cwd=repo_root,
            stderr=subprocess.DEVNULL
        ).decode('ascii').strip()
        
        # Check if working directory is dirty (ignore untracked files)
        try:
            subprocess.check_output(
                ['git', 'diff-index', '--quiet', 'HEAD', '--'],
                cwd=repo_root,
                stderr=subprocess.DEVNULL
            )
            dirty_suffix = ''
        except subprocess.CalledProcessError:
            dirty_suffix = '-dirty'
        
        git_short_hash = git_sha + dirty_suffix
        
        # Return just the hash - will be combined with PROJECT_ID@SEMVER in main.cpp
        env.Append(CPPDEFINES=[('GIT_SHORT_HASH', '\\"%s\\"' % git_short_hash)])
        print('Git version hash: %s' % git_short_hash)
        
    except Exception as e:
        print('Warning: Could not get git SHA: %s' % e)
        env.Append(CPPDEFINES=[('GIT_SHORT_HASH', '\\"unknown\\"')])
        print('Using fallback git hash: unknown')

get_git_version()
