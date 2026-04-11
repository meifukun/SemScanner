"""
EventExecutor - Event executor

Responsible for triggering various events (click, dblclick, mouseover, custom events, etc.)
"""

import time
from selenium.common.exceptions import ElementClickInterceptedException


class EventExecutor:
    """Event executor: executes corresponding browser operations based on event type"""

    def __init__(self, driver):
        """
        Initialize event executor

        Args:
            driver: Selenium WebDriver instance
        """
        self.driver = driver

    def execute_event(self, elem, event_type: str) -> bool:
        """
        Execute corresponding operation based on event type

        Args:
            elem: Selenium WebElement
            event_type: Event type (already normalized, e.g. "click", "select_node", "dblclick", etc.)

        Returns:
            bool: Whether execution succeeded
        """
        try:
            # Route to specific method
            if event_type == 'click':
                return self._execute_click(elem)

            elif event_type == 'dblclick':
                return self._execute_dblclick(elem)

            elif event_type == 'mouseover':
                return self._execute_mouseover(elem)

            elif event_type == 'keydown':
                return self._execute_keydown(elem)

            elif event_type == 'scroll':
                return self._execute_scroll(elem)

            # Custom events (framework-specific)
            elif event_type in ['select_node', 'open_node', 'close_node']:
                # jsTree events: just click directly
                return self._execute_click(elem)

            else:
                # Unknown event type, try generic method
                return self._execute_generic_event(elem, event_type)

        except Exception as e:
            print(f"[EventExecutor] Failed to execute event {event_type}: {e}")
            return False

    def _execute_click(self, elem) -> bool:
        """
        Execute click operation (most common)

        Strategy:
        1. Try Selenium native click
        2. If intercepted, scroll and retry
        3. Finally use JS click

        Returns:
            bool: Whether succeeded
        """
        try:
            elem.click()
            return True
        except ElementClickInterceptedException:
            # Element intercepted, scroll into view and retry
            try:
                self.driver.execute_script("arguments[0].scrollIntoView(true);", elem)
                time.sleep(0.2)
                elem.click()
                return True
            except:
                # JS click (bypasses interception check)
                self.driver.execute_script("arguments[0].click();", elem)
                return True
        except Exception as e:
            # Last try: JS click
            try:
                self.driver.execute_script("arguments[0].click();", elem)
                return True
            except:
                print(f"[EventExecutor] Click failed: {e}")
                return False

    def _execute_dblclick(self, elem) -> bool:
        """
        Execute double-click operation

        Returns:
            bool: Whether succeeded
        """
        try:
            from selenium.webdriver.common.action_chains import ActionChains
            actions = ActionChains(self.driver)
            actions.double_click(elem).perform()
            return True
        except:
            # Fallback: JS trigger dblclick event
            self.driver.execute_script("""
                const event = new MouseEvent('dblclick', {
                    bubbles: true,
                    cancelable: true,
                    view: window
                });
                arguments[0].dispatchEvent(event);
            """, elem)
            return True

    def _execute_mouseover(self, elem) -> bool:
        """
        Execute hover operation (mouse over)

        Used to trigger dropdown menus, tooltips, etc.

        Returns:
            bool: Whether succeeded
        """
        try:
            from selenium.webdriver.common.action_chains import ActionChains
            actions = ActionChains(self.driver)
            actions.move_to_element(elem).perform()
            time.sleep(0.3)  # Wait for hover effect to appear
            return True
        except:
            # Fallback: JS trigger mouseover event
            self.driver.execute_script("""
                ['mouseover', 'mouseenter'].forEach(type => {
                    arguments[0].dispatchEvent(new MouseEvent(type, {
                        bubbles: true,
                        cancelable: true,
                        view: window
                    }));
                });
            """, elem)
            return True

    def _execute_keydown(self, elem, key_code: int = 13) -> bool:
        """
        Execute keyboard event

        Args:
            key_code: Key code (default 13=Enter)

        Returns:
            bool: Whether succeeded
        """
        try:
            self.driver.execute_script("""
                arguments[0].dispatchEvent(new KeyboardEvent('keydown', {
                    bubbles: true,
                    cancelable: true,
                    keyCode: arguments[1],
                    which: arguments[1]
                }));
            """, elem, key_code)
            return True
        except:
            return False

    def _execute_scroll(self, elem) -> bool:
        """
        Scroll to element

        Returns:
            bool: Whether succeeded
        """
        try:
            self.driver.execute_script("arguments[0].scrollIntoView(true);", elem)
            return True
        except:
            return False

    def _execute_generic_event(self, elem, event_type: str) -> bool:
        """
        Generic event execution (unknown type)

        Strategy:
        1. Try normal click first (works in most cases)
        2. If jQuery available, try trigger
        3. Otherwise use CustomEvent

        Returns:
            bool: Whether succeeded
        """
        # Prefer normal click
        success = self._execute_click(elem)
        if success:
            return True

        # Try jQuery trigger
        try:
            has_jquery = self.driver.execute_script("return typeof jQuery !== 'undefined'")
            if has_jquery:
                self.driver.execute_script("""
                    $(arguments[0]).trigger(arguments[1]);
                """, elem, event_type)
                return True
        except:
            pass

        # Last try: CustomEvent
        try:
            self.driver.execute_script("""
                arguments[0].dispatchEvent(new CustomEvent(arguments[1], {
                    bubbles: true,
                    cancelable: true
                }));
            """, elem, event_type)
            return True
        except:
            return False
