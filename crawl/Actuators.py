import os
from typing import Any, Dict, Iterable, List, Optional, Union

from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait, Select
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import (
    StaleElementReferenceException,
    ElementNotInteractableException,
    NoSuchElementException,
    TimeoutException,
    WebDriverException,
)
# todo: could add a press enter operation, so the model can use it to submit a form if no submit button is found
class Actuators:
    """
    Executor for common web actions:
    - execute_action_by_id(action_id, **kwargs) smart dispatch (most universal)
    - click_by_id / type_text_by_id / select_by_id / set_checkbox_by_id / select_radio_by_id ...
    - fill_form(form_id, data) / submit_form(form_id, submit_id=None)
    """
    DEFAULT_TEXT = "test"           # Default value for text input
    DEFAULT_TEXTAREA = "hello"      # Default value for textarea

    def __init__(self, sensors, timeout: int = 10):
        self.driver = sensors.driver
        self.sensors = sensors
        self.wait = WebDriverWait(self.driver, timeout)


    # Methods adapted for executor, external parameters unified as value
    def execute_action_by_id(self, action_id: int, value: Optional[str] = None) -> bool:
        """
        Look up the action table by action_id and execute the corresponding operation.
        :param action_id: The ID of the action element to execute
        :param value: The corresponding value, e.g. text for input field, value for dropdown selection, etc.
        :return: Whether execution succeeded
        """
        actions_mapping = self.sensors.get_actions_mapping()
        element = actions_mapping.get_action_elem(action_id)

        # If element not found, return False
        if element is None:
            print(f"[Actuators] Cannot find element for action_id={action_id}")
            return False

        # If element type not found, also return False
        action_type = actions_mapping.get_action_type(action_id)
        if action_type is None:
            print(f"[Actuators] Cannot find element type for action_id={action_id}")
            return False

        try:
            # Determine specific operation based on action_type
            if action_type == "clickable":
                return self._handle_click_action(element, action_id)

            elif action_type == "form":
                # Handle form submission
                if value == "submit":  # Can pass submit info via kwargs
                    return self.submit_form(action_id)
                return True

            elif action_type.startswith("input"):
                # Input type operation: handle text input
                parts = action_type.split(":", 1)
                subtype = parts[1] if len(parts) > 1 else (element.get_attribute('type') or 'text').lower()

                if subtype in {"text", "password", "email", "search", "tel", "url", "number",
                            "date", "datetime-local", "month", "week", "time", "color"}:
                    text = value or self.DEFAULT_TEXT  # Use default text or passed text
                    return self._handle_text_input(element, text=text)

                elif subtype == "file":
                    return self._handle_file_input(element, file_path=value)

                elif subtype == "checkbox":
                    checked = True if value is None else bool(value)
                    return self._handle_checkbox(element, checked=checked)

                elif subtype == "radio":
                    return self._handle_radio(element)
                elif subtype == "range":
                    return self._handle_range_input(element, value=value)

                else:
                    # Handle other input types (submit buttons, image, etc.)
                    return self._handle_click_action(element, action_id)

            elif action_type == "select":
                # Dropdown select operation
                return self._handle_select(element, value=value)

            elif action_type == "textarea":
                # Handle textarea
                text = value or self.DEFAULT_TEXTAREA
                return self._handle_textarea(element, text=text)
            # Added in execute_action_by_id
            elif action_type == "select:mat":
                # Material Select needs special handling: click to open, then select option
                return self._handle_mat_select(element, value=value)

            else:
                print(f"[Actuators] Unknown action type: {action_type}")
                return False

        except (StaleElementReferenceException, ElementNotInteractableException,
                WebDriverException) as e:
            print(f"[Actuators] Execution failed id={action_id} type={action_type} err={e}")
            return False

    def _handle_range_input(self, element, value=None) -> bool:
        """Safely set <input type=range> value and trigger input/change events"""
        try:
            self._wait_interactable(element)

            def _to_float(s, default):
                try:
                    return float(s)
                except:
                    return default

            cur = _to_float(element.get_attribute('value'), 0.0)
            mn  = _to_float(element.get_attribute('min'), 0.0)
            mx  = _to_float(element.get_attribute('max'), 100.0)
            st  = _to_float(element.get_attribute('step'), 1.0)

            if value is None:
                target = cur
            else:
                try:
                    target = float(value)
                except:
                    target = cur

            # Clamp to range and round to step
            target = max(mn, min(mx, target))
            if st > 0:
                target = mn + round((target - mn) / st) * st

            # Use JS to set value directly and dispatch events (compatible with Angular/React listeners)
            self.driver.execute_script("""
                const el = arguments[0], val = arguments[1];
                el.value = String(val);
                el.dispatchEvent(new Event('input',  { bubbles: true }));
                el.dispatchEvent(new Event('change', { bubbles: true }));
            """, element, target)

            return True
        except Exception as e:
            print(f"[Actuators] Range input failed: {e}")
            return False


    def _handle_mat_select(self, element, value=None):
        """Handle Material Select (needs click to expand)"""
        try:
            # 1. Click to open dropdown
            self._safe_click(element)

            # 2. Find and click option
            if value:
                # Find mat-option in overlay
                options = self.driver.find_elements(By.CSS_SELECTOR,
                    'mat-option, [role="option"]')
                for opt in options:
                    if value in opt.text:
                        return self._safe_click(opt)
            return False
        except Exception as e:
            print(f"[Actuators] Material Select failed: {e}")
            return False

    # ======= Convenience methods =======
    def click_by_id(self, action_id: int) -> bool:
        return self.execute_action_by_id(action_id)

    def type_text_by_id(self, action_id: int, text: str, enter: bool=False) -> bool:
        return self.execute_action_by_id(action_id, text=text, enter=enter)

    def select_by_id(self, action_id: int,
                     value: Optional[Union[str, int]] = None,
                     text: Optional[Union[str, int]] = None,
                     index: Optional[int] = None,
                     values: Optional[Iterable[Union[str, int]]] = None,
                     texts: Optional[Iterable[Union[str, int]]] = None) -> bool:
        return self.execute_action_by_id(action_id, value=value, text=text,
                                         index=index, values=values, texts=texts)

    def set_checkbox_by_id(self, action_id: int, checked: bool=True) -> bool:
        return self.execute_action_by_id(action_id, checked=checked)

    def toggle_checkbox_by_id(self, action_id: int) -> bool:
        return self.execute_action_by_id(action_id, toggle=True)

    def select_radio_by_id(self, action_id: int,
                           value: Optional[str]=None,
                           label: Optional[str]=None,
                           index: Optional[int]=None) -> bool:
        return self.execute_action_by_id(action_id, value=value, label=label, index=index)

    # ======= Form-level operations =======
    def fill_form(self, form_id: int, data: Dict[str, Any]) -> bool:
        """
        data keys first match field's name, then id.
        Value types:
          - text/textarea: str
          - checkbox: bool
          - radio: str (by value) or {'label': '...'} or {'index': 0}
          - select: str/int or list[str|int] (multi-select)
        """
        actions = self.sensors.get_actions_mapping()
        form_elem = actions.get_action_elem(form_id)
        if form_elem is None:
            print(f"[Actuators] Form not found: id={form_id}")
            return False

        fields = self.sensors.get_form_fields(form_elem)
        ok = True
        for field in fields:
            try:
                tag = (field.tag_name or '').lower()
                f_name = (field.get_attribute('name') or '').strip()
                f_id = (field.get_attribute('id') or '').strip()

                key = None
                if f_name and f_name in data:
                    key = f_name
                elif f_id and f_id in data:
                    key = f_id
                else:
                    # Not in data, skip
                    continue

                val = data[key]
                # Find this field's id in actions_mapping (for dispatch)
                # Since Sensors also add_action for fields, could use reverse lookup interface (if available)
                # But here we directly call handlers based on tag/type, which is faster.
                if tag == 'input':
                    subtype = (field.get_attribute('type') or 'text').lower()
                    if subtype in {'text','password','email','search','tel','url','number',
                                   'date','datetime-local','month','week','time','color'}:
                        self._handle_text_input(field, text=str(val))
                    elif subtype == 'file':
                        self._handle_file_input(field, file_path=str(val))
                    elif subtype == 'checkbox':
                        if isinstance(val, bool):
                            self._handle_checkbox(field, checked=val)
                        else:
                            # Not bool, ignore
                            pass
                    elif subtype == 'radio':
                        # Radio is a group operation: find same-name group
                        self._handle_radio(field,
                                           value=val if isinstance(val, str) else None,
                                           label=val.get('label') if isinstance(val, dict) else None,
                                           index=val.get('index') if isinstance(val, dict) else None)
                    else:
                        # Other unknown input, treat as text
                        self._handle_text_input(field, text=str(val))
                elif tag == 'select':
                    # Single or multiple values
                    if isinstance(val, (list, tuple, set)):
                        self._handle_select(field, values=list(val), texts=None)
                    else:
                        # Single value: try by text/value/index
                        self._handle_select(field, value=val, text=val if isinstance(val, str) else None)
                elif tag == 'textarea':
                    self._handle_textarea(field, text=str(val))
                else:
                    pass
            except Exception as e:
                print(f"[Actuators] Failed to fill field name/id={f_name or f_id} err={e}")
                ok = False
        return ok

    def submit_form(self, form_id: int, submit_id: Optional[int]=None) -> bool:
        """
        Preferentially click explicit submit control; if not found, call form.submit()
        """
        actions = self.sensors.get_actions_mapping()
        form_elem = actions.get_action_elem(form_id)
        if form_elem is None:
            print(f"[Actuators] Form not found: id={form_id}")
            return False

        # If submit_id specified, click it first
        if submit_id is not None:
            submit_elem = actions.get_action_elem(submit_id)
            if submit_elem is None:
                print(f"[Actuators] Specified submit_id does not exist: {submit_id}")
                return False
            return self._safe_click(submit_elem)

        # Find submit control within form
        try:
            submit = None
            # Common submit controls
            candidates = form_elem.find_elements(
                By.CSS_SELECTOR,
                'input[type="submit"], button[type="submit"], button:not([type]), input[type="image"]'
            )
            if candidates:
                submit = candidates[0]
            if submit:
                return self._safe_click(submit)
        except StaleElementReferenceException:
            pass

        # Fallback: native submit
        try:
            self.driver.execute_script("arguments[0].submit();", form_elem)
            return True
        except WebDriverException as e:
            print(f"[Actuators] form.submit() failed: {e}")
            return False

    # ======= Type-specific handlers =======
    def _handle_click_action(self, element, action_id: int) -> bool:
        ok = self._safe_click(element)
        return ok

    def _handle_text_input(self, element, text: str, press_enter: bool=False) -> bool:
        try:
            self._wait_interactable(element)
            element.clear()
            element.send_keys(text)
            if press_enter:
                element.send_keys(Keys.ENTER)
            return True
        except (StaleElementReferenceException, ElementNotInteractableException, WebDriverException) as e:
            print(f"[Actuators] Text input failed: {e}")
            return False

    def _handle_textarea(self, element, text: str, press_enter: bool=False) -> bool:
        return self._handle_text_input(element, text=text, press_enter=press_enter)

    def _handle_file_input(self, element, file_path: Optional[str]) -> bool:
        if not file_path or not os.path.exists(file_path):
            print("[Actuators] File path invalid or does not exist")
            return False
        try:
            self._wait_interactable(element)
            element.send_keys(os.path.abspath(file_path))
            return True
        except (StaleElementReferenceException, ElementNotInteractableException, WebDriverException) as e:
            print(f"[Actuators] File upload failed: {e}")
            return False

    def _handle_checkbox(self, element, checked: bool=True) -> bool:
        try:
            self._wait_interactable(element)
            if element.is_selected() != checked:
                return self._safe_click(element)
            return True
        except (StaleElementReferenceException, ElementNotInteractableException, WebDriverException) as e:
            print(f"[Actuators] Checkbox toggle failed: {e}")
            return False

    def _handle_radio(self, element, value=None):
        """Simplified: CHECK X means select the radio with ID=X"""
        try:
            self._wait_interactable(element)
            if not element.is_selected():
                return self._safe_click(element)
            return True
        except Exception as e:
            print(f"[Actuators] Radio selection failed: {e}")
            return False


    def _handle_select(self, element,
                       value: Optional[Union[str, int]] = None,
                       text: Optional[Union[str, int]] = None,
                       index: Optional[int] = None,
                       values: Optional[Iterable[Union[str, int]]] = None,
                       texts: Optional[Iterable[Union[str, int]]] = None) -> bool:
        try:
            self._wait_interactable(element)
            sel = Select(element)
            is_multi = sel.is_multiple

            def _select_one(v=None, t=None, i=None):
                # Select a single item, try text -> value -> index
                if t is not None:
                    try:
                        sel.select_by_visible_text(str(t))
                        return True
                    except NoSuchElementException:
                        pass
                if v is not None:
                    try:
                        sel.select_by_value(str(v))
                        return True
                    except NoSuchElementException:
                        pass
                if i is not None:
                    try:
                        sel.select_by_index(int(i))
                        return True
                    except (NoSuchElementException, ValueError):
                        pass
                # None matched, try treating t/v as the other
                if t is None and v is not None:
                    try:
                        sel.select_by_visible_text(str(v))
                        return True
                    except NoSuchElementException:
                        pass
                if v is None and t is not None:
                    try:
                        sel.select_by_value(str(t))
                        return True
                    except NoSuchElementException:
                        pass
                return False

            changed = False
            if is_multi and (values or texts):
                # Multi-select
                # Clear first (can optionally keep existing selections)
                sel.deselect_all()
                if texts:
                    for t in texts:
                        changed = _select_one(t=t) or changed
                if values:
                    for v in values:
                        changed = _select_one(v=v) or changed
            else:
                # Single select: by text/value/index
                if any(x is not None for x in (text, value, index)):
                    changed = _select_one(v=value, t=text, i=index)
                else:
                    # Not specified, keep current; if nothing selected, select first (not disabled)
                    options = element.find_elements(By.TAG_NAME, 'option')
                    selected = [o for o in options if o.is_selected()]
                    if not selected and options:
                        # Find first selectable option
                        for idx, o in enumerate(options):
                            if (o.get_attribute('disabled') is None) and o.is_enabled():
                                try:
                                    sel.select_by_index(idx)
                                    changed = True
                                    break
                                except Exception:
                                    continue

            return True if changed or is_multi else True
        except (StaleElementReferenceException, ElementNotInteractableException, WebDriverException) as e:
            print(f"[Actuators] Dropdown selection failed: {e}")
            return False

    def _wait_interactable(self, element):
        """
        Wait for element to be interactable

        Optimization: simplified wait logic
        Since element has already been verified to exist through ResilientElementFinder,
        we only need a simple wait here to let the page stabilize, avoiding redundant element lookups
        """
        # Simple wait to give the page time to stabilize (including JavaScript dynamically modifying attributes)
        import time
        time.sleep(0.8)

    # Original implementation (disabled to avoid redundant element access)
    # def _wait_interactable(self, element):
    #     # Avoid element_to_be_clickable's locator requirement, use custom wait here
    #     self.wait.until(lambda d: self._is_displayed_and_enabled(element))

    # def _is_displayed_and_enabled(self, element) -> bool:
    #     try:
    #         return element.is_displayed() and element.is_enabled()
    #     except StaleElementReferenceException:
    #         return False

    def _is_displayed_and_enabled(self, element) -> bool:
        return True

    def _safe_click(self, element) -> bool:
        try:
            self._wait_interactable(element)
            try:
                element.click()
            except WebDriverException:
                # Fall back to JS click (handles overlay/animation)
                self.driver.execute_script("arguments[0].click();", element)
            return True
        except (StaleElementReferenceException, ElementNotInteractableException, WebDriverException) as e:
            print(f"[Actuators] Click failed: {e}")
            return False

    def _short_id(self, element) -> str:
        # For naming screenshots: prefer element id/name, otherwise use memory id
        try:
            eid = (element.get_attribute('id') or element.get_attribute('name') or '').strip()
            return eid if eid else str(id(element))
        except StaleElementReferenceException:
            return "stale"

    def _get_label_text_for_input(self, input_elem) -> str:
        try:
            input_id = input_elem.get_attribute('id')
            if input_id:
                lbl = self.driver.find_element(By.XPATH, f'//label[@for="{input_id}"]')
                if lbl and lbl.text:
                    return lbl.text.strip()
        except Exception:
            pass
        try:
            lbl_wrap = input_elem.find_element(By.XPATH, 'ancestor::label[1]')
            if lbl_wrap and lbl_wrap.text:
                return lbl_wrap.text.strip()
        except Exception:
            pass
        return ""
