import os
import shutil
from functools import lru_cache
from pathlib import Path

from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager


def _executable(path_value: str) -> Path:
    path = Path(path_value).expanduser().resolve()
    if not path.is_file() or not os.access(path, os.X_OK):
        raise RuntimeError(f"Executable not found or not executable: {path}")
    return path


@lru_cache(maxsize=8)
def _resolve_chromedriver(env_path: str, path_value: str) -> str:
    if env_path:
        return str(_executable(env_path))

    path_driver = shutil.which("chromedriver", path=path_value)
    if path_driver:
        return str(_executable(path_driver))

    # Online fallback for host-side development. The AE container always sets
    # CHROMEDRIVER_PATH to its packaged, version-matched driver.
    return ChromeDriverManager().install()


def configure_chrome_options(options):
    """Apply an explicit browser binary when CHROME_BINARY is configured."""
    browser_path = os.environ.get("CHROME_BINARY", "").strip()
    if browser_path:
        options.binary_location = str(_executable(browser_path))
    return options


def make_chrome_service() -> Service:
    driver_path = _resolve_chromedriver(
        os.environ.get("CHROMEDRIVER_PATH", "").strip(),
        os.environ.get("PATH", ""),
    )
    return Service(driver_path)
