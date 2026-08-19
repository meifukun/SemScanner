import time
import openai
from typing import Optional, Tuple
from task.tasks import Task
import os
import re
from urllib.parse import urlsplit, urlunsplit
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.common.exceptions import NoAlertPresentException, TimeoutException
from selenium.common.exceptions import NoAlertPresentException

# Import event executor
from crawl.EventExecutor import EventExecutor
from config.llm_config import get_model_name, get_temperature

def clear_alert(driver, action="dismiss", text=None):
    """
    Check if a browser popup (alert/confirm/prompt) exists and clear it.

    :param driver: WebDriver instance
    :param action: "accept" or "dismiss", default dismiss (equivalent to clicking cancel)
    :param text:   If it's a prompt, text can be entered before handling
    :return: True if a popup was handled, False if no popup
    """
    try:
        alert = driver.switch_to.alert
        print(f"Popup detected: {alert.text}")

        if text is not None:
            alert.send_keys(text)

        if action == "accept":
            alert.accept()
        else:
            alert.dismiss()

        print("Popup handled")
        return True
    except NoAlertPresentException:
        return False
    except Exception as e:
        print("Error handling popup:",e)
        return False


def _norm_url(u: str) -> str:
    # p = urlsplit(u)
    # return urlunsplit((p.scheme, p.netloc, p.path, p.query, ""))
    return u

class InteractionExecutionAgent:
    def __init__(self, sensors, actuators, client, url_in_scope=None):
        self.sensors = sensors
        self.driver = sensors.driver
        self.actuators = actuators
        self.client = client
        self.url_in_scope = url_in_scope
        self._tracer = None  # ExecutionTracer, can be set later
        self._task_queue = None   # added
        self._store = None  # WebAppStore reference
        self._task_log_file = None  # Task-level log file handle
        self._task_log_path = None  # Task log path

        # Event executor (independent from element executor)
        self.event_executor = EventExecutor(self.driver)

    # --- Allow external registration of tracer ---
    def set_tracer(self, tracer, task_queue, store):
        """
        Set tracer, task_queue and store references

        Args:
            tracer: ExecutionTracer instance
            task_queue: TaskQueue instance
            store: WebAppStore instance
        """
        self._tracer = tracer
        self._task_queue = task_queue
        self._store = store

    def _log(self, message: str):
        """
        Task-level log (writes to the current task's log file)

        Falls back to print if no task log is set (backward compatible)
        """
        if self._task_log_file:
            self._task_log_file.write(message + "\n")
            self._task_log_file.flush()  # Flush immediately to avoid loss
        else:
            print(message)

    def _open_task_log(self, photo_dir, task_id: str):
        """
        Open task log file

        Args:
            photo_dir: Task screenshot directory (e.g. traces/100/ or Path object)
            task_id: Task ID
        """
        # Ensure directory exists (supports both Path objects and strings)
        photo_dir = str(photo_dir)  # Convert to string
        os.makedirs(photo_dir, exist_ok=True)
        self._task_log_path = os.path.join(photo_dir, f"task_{task_id}.log")
        self._task_log_file = open(self._task_log_path, 'w', encoding='utf-8')
        self._log(f"[InteractionExecutionAgent] Task log created: {self._task_log_path}")

    def _close_task_log(self):
        """Close task log file"""
        if self._task_log_file:
            self._log(f"[InteractionExecutionAgent] Task log closed")
            self._task_log_file.close()
            self._task_log_file = None
            self._task_log_path = None

    # ====== Keep original implementation below (slightly reorganized) ======
    # def load_bridge_prompt(self) -> str:
    #     with open("prompt/bridge.txt", "r") as file:
    #         return file.read()

    def load_bridge_prompt(self) -> str:
        with open("prompt/interaction_execution_agent.txt", "r") as file:
            return file.read()

    def generate_bridge_prompt(self, task: Task, page_description: str, last_step: str) -> str:
        prompt = self.load_bridge_prompt()
        self._log(f"[InteractionExecutionAgent] Info sent to LLM:\nTask description: {task.task_id, task.description} \nLast Step: {last_step}\nCurrent URL: {self.driver.current_url}\nPage Title: {self.driver.title}\n")
        return prompt.format(
            page_description=page_description,
            task_description=task.description,
            # page_info=page_info,
            current_url=self.driver.current_url,
            last_step=last_step,
            page_title=self.driver.title
        )

    def generate_bridge_onestep_prompt(self, task: Task, page_description: str, execution_history: str) -> str:
        prompt = self.load_bridge_prompt()

        # Format history, show "None" if empty
        history_text = execution_history if execution_history.strip() else "None (this is the first step)"

        self._log(f"[InteractionExecutionAgent] Info sent to LLM:\nTask description: {task.task_id, task.description} \nCurrent URL: {self.driver.current_url}\nPage Title: {self.driver.title}\nHistory: {history_text[:200]}...\n")
        return prompt.format(
            page_description=page_description,
            task_description=task.description,
            current_url=self.driver.current_url,
            page_title=self.driver.title,
            execution_history=history_text  # Add history
        )

    def query_llm(self, prompt: str) -> str:
        try:
            idx = prompt.rfind("CURRENT BROWSER CONTENT:")
            system_content = prompt[:idx]
            user_content = prompt[idx:]

            # Enhanced system prompt to guide reasoning mode to be more cautious with CONTINUE
            enhanced_system = system_content + "\n\n**REASONING GUIDELINES**:\n"
            enhanced_system += "1. Think step-by-step before deciding on CONTINUE\n"
            enhanced_system += "2. Default to NOT using CONTINUE unless you have strong evidence\n"
            enhanced_system += "3. Consider: Can I complete this task with the visible elements? If yes, NO CONTINUE\n"
            enhanced_system += "4. Verify: Does the task explicitly require another page? If no, NO CONTINUE\n"

            msg = [
                {"role": "system", "content": enhanced_system},
                {"role": "user", "content": user_content}
            ]
            completion = self.client.chat.completions.create(
                model=get_model_name("bridge"),
                messages=msg,
                temperature=get_temperature("bridge")
            )
            return completion.choices[0].message.content
        except Exception as e:
            self._log(f"[InteractionExecutionAgent] LLM call failed: {e}")
            return "STOP"

    # --- Parse LLM commands (same as above) ---
    CMD_PATTERNS = [
        (re.compile(r'^\s*CLICK\s+(\d+)\s*$', re.I), 'CLICK'),
        (re.compile(r'^\s*TYPE\s+(\d+)\s+with\s+"?(.*?)"?\s*$', re.I), 'TYPE'),
        (re.compile(r'^\s*SELECT\s+(\d+)\s+with\s+"?(.*?)"?\s*$', re.I), 'SELECT'),
        (re.compile(r'^\s*CHECK\s+(\d+)\s*$', re.I), 'CHECK'),
        (re.compile(r'^\s*UNCHECK\s+(\d+)\s*$', re.I), 'UNCHECK'),
        (re.compile(r'^\s*SUBMIT\s+FORM\s+with\s+(\d+)\s*$', re.I), 'SUBMIT'),
        (re.compile(r'^\s*UPLOAD\s+FILE\s+with\s+(\d+)(?:\s+(.+))?\s*$', re.I), 'UPLOAD'),
        (re.compile(r'^\s*PRESS\s+ENTER\s*$', re.I), 'PRESS_ENTER'),
        # Trigger event
        (re.compile(r'^\s*TRIGGER\s+(\d+)\s*$', re.I), 'TRIGGER'),
        # --- Ending Commands ---
        (re.compile(r'^\s*DONE\s*$', re.I), 'DONE'),
        (re.compile(r'^\s*FAIL\s*$', re.I), 'FAIL'),
        (re.compile(r'^\s*BACK\s+"(.+?)"\s*$', re.I), 'BACK'),
        # Continue marker
        (re.compile(r'^\s*CONTINUE\s*$', re.I), 'CONTINUE')
    ]


    def _parse_command(self, cmd: str) -> Tuple[Optional[str], Optional[int], Optional[str], str]:
        for pat, kind in self.CMD_PATTERNS:
            mm = pat.match(cmd)
            if mm:
                if kind in ('CLICK','CHECK','UNCHECK','SUBMIT','TRIGGER'):
                    return kind, int(mm.group(1)), None, cmd
                if kind in ('TYPE','SELECT'):
                    return kind, int(mm.group(1)), mm.group(2), cmd
                if kind == 'UPLOAD':
                    path = (mm.group(2) or '').strip() if mm.lastindex and mm.lastindex >= 2 else ''
                    return 'UPLOAD', int(mm.group(1)), (path if path else None), cmd
                if kind == 'PRESS_ENTER':
                    return 'PRESS_ENTER', None, None, cmd
                if kind in ('DONE', 'FAIL'):
                    return kind, None, None, cmd
                if kind == 'BACK':
                    # value carries the url
                    return 'BACK', None, mm.group(1), cmd
        return None, None, None, cmd

    def _action_repr(self, action_id: int) -> str:
        """
        Find the corresponding element in the abstract page for the given action_id and generate a readable representation.
        Directly gets the corresponding line from get_abstract_page(), locating by id.
        """
        # Get abstract page content
        abstract_page = self.sensors.get_abstract_page()

        # Find the line containing this action_id (assumes identification by id=x format)
        action_line = None
        for line in abstract_page.splitlines():
            if f"id={action_id}" in line:
                action_line = line
                break

        # If no corresponding line found, return an unknown identifier
        if action_line is None:
            return f"<unknown id={action_id}>"

        # Parse the line content and return the string representation
        # Assumes each line's content could be HTML tags or other format descriptions
        return action_line.strip()  # Directly return that line's content


    # --- Classify jump type ---
    def _classify_jump(self, command_kind: str, action_id: int, old_handles, new_handles) -> str:
        """
        Classify the type of page navigation

        Optimization: avoid redundant element lookup, only judge based on command type and page changes

        Args:
            command_kind: Command type
            action_id: Action element ID (kept for interface compatibility, currently unused)
            old_handles: Window handle list before the action
            new_handles: Window handle list after the action
        """
        # Check if a new window was opened
        if len(new_handles) > len(old_handles):
            return 'new-window'

        # Judge jump type based on command type
        if command_kind in ('SUBMIT', 'PRESS_ENTER'):
            return 'form-submit'
        if command_kind == 'CLICK':
            return 'button-click'
        if command_kind in ('TYPE', 'SELECT'):
            return 'interaction'

        return 'programmatic'

    def _nav_type(self) -> str:
        """
        Get navigation type (via Performance API)

        Returns:
            Navigation type string
        """
        try:
            return self.driver.execute_script(
                "try{var e=performance.getEntriesByType('navigation');return e&&e.length?e[e.length-1].type:''}catch(e){return ''}"
            ) or ""
        except Exception:
            return ""

    # --- Single step execution (keeping your original execute_task_step dispatch logic) ---
    def execute_task_step(self, task: Task, action_id: int, value: Optional[str] = None, force_event: bool = False) -> bool:
        """
        Execute a single step operation (supports both element and event systems)

        Optimization: supports explicit event execution
        - If force_event=True (TRIGGER command), only execute event, no fallback to element
        - Otherwise, check event mapping first, then fallback to element operation

        Args:
            task: Task object (kept for interface compatibility, currently unused)
            action_id: Operation ID to execute (could be element ID or event ID)
            value: Operation parameter (e.g. text to input, value to select, etc.)
            force_event: Whether to force event-only execution (used by TRIGGER command)

        Returns:
            bool: Whether the operation succeeded
        """
        try:
            event_mapping = self.sensors.get_event_mapping()

            # TRIGGER command: only execute event, no fallback
            if force_event:
                if event_mapping.has_event(action_id):
                    self._log(f"[InteractionExecutionAgent] TRIGGER command: found event ID {action_id}, starting execution")
                    return self._execute_event(action_id, value)
                else:
                    self._log(f"[InteractionExecutionAgent] TRIGGER failed: event ID {action_id} does not exist")
                    return False

            # Normal command: prioritize event, fallback to element
            if event_mapping.has_event(action_id):
                # This is an event ID, use event executor
                return self._execute_event(action_id, value)
            else:
                # This is an element ID, use the original Actuators
                success = self.actuators.execute_action_by_id(action_id, value=value)
                return success
        except Exception as e:
            # Catch any exception, print error and return failure
            self._log(f"[InteractionExecutionAgent] Error during operation execution: {e}")
            import traceback
            traceback.print_exc()
            return False

    def _execute_event(self, event_id: int, value: Optional[str] = None) -> bool:
        """
        Execute an event (independent from element execution)

        Args:
            event_id: Event ID
            value: Parameter (currently unused, reserved for interface)

        Returns:
            bool: Whether execution succeeded
        """
        event_mapping = self.sensors.get_event_mapping()
        event_info = event_mapping.get_event(event_id)

        if not event_info:
            self._log(f"[InteractionExecutionAgent] Event ID {event_id} does not exist")
            return False

        xpath = event_info['xpath']
        event_type = event_info['event_type']
        text = event_info['text']

        self._log(f"[InteractionExecutionAgent] Executing event {event_id}: type={event_type}, text='{text}', xpath={xpath[:80]}...")

        # Locate element
        elem = None
        try:
            elem = self.driver.find_element(By.XPATH, xpath)
        except Exception as e:
            self._log(f"[InteractionExecutionAgent] XPath locating failed: {e}")

            # Fallback: try using original_id or original_class
            original_id = event_info.get('original_id', '')
            original_class = event_info.get('original_class', '')

            if original_id:
                try:
                    elem = self.driver.find_element(By.ID, original_id)
                    self._log(f"[InteractionExecutionAgent] Fallback succeeded: using ID={original_id}")
                except:
                    pass

            if not elem and original_class:
                try:
                    # Try matching by class + text
                    candidates = self.driver.find_elements(By.CLASS_NAME, original_class.split()[0])
                    for candidate in candidates:
                        if text in candidate.text:
                            elem = candidate
                            self._log(f"[InteractionExecutionAgent] Fallback succeeded: using class+text")
                            break
                except:
                    pass

            if not elem:
                self._log(f"[InteractionExecutionAgent] All locating methods failed")
                return False

        # Execute event
        try:
            success = self.event_executor.execute_event(elem, event_type)
            if success:
                self._log(f"[InteractionExecutionAgent] Event execution succeeded")
            else:
                self._log(f"[InteractionExecutionAgent] Event execution failed")
            return success
        except Exception as e:
            self._log(f"[InteractionExecutionAgent] Event execution exception: {e}")
            import traceback
            traceback.print_exc()
            return False

    def _is_subtask_line(self, line: str) -> bool:
        """
        Determine if a line is a subtask line:
        Format: initial_url:<URL> description:<TEXT>
        """
        return re.match(r'^\s*initial_url\s*:\s*\S+\s+description\s*:\s*.+$', line, flags=re.IGNORECASE) is not None

    def _parse_subtasks_from_lines(self, lines):
        """
        Parse subtask lines into list objects:
        [{"initial_url": "...", "description": "..."}, ...]
        Assumes input lines have been filtered for empty lines and all satisfy _is_subtask_line
        """
        subtasks = []
        pat = re.compile(r'^\s*initial_url\s*:\s*(\S+)\s+description\s*:\s*(.+)$', flags=re.IGNORECASE)
        for ln in lines:
            m = pat.match(ln)
            if not m:
                continue
            initial_url = m.group(1).strip()
            description = m.group(2).strip()
            if initial_url and description:
                subtasks.append({"initial_url": initial_url, "description": description})
        return subtasks

    def run_task(self, task, photo_dir, logging_in=False):
        # Open task log file
        self._open_task_log(photo_dir, task.task_id)
        try:
            self._log("-------------------------------------------------")
            self._log(f"[InteractionExecutionAgent] Starting task {task.task_id}: {task.description}")
            if self.url_in_scope and not self.url_in_scope(task.initial_url):
                self._log(
                    f"[ScopeGuard] Refusing task outside target origin: "
                    f"{task.initial_url}"
                )
                task.set_completed()
                return
            # Fix: don't reload page, Crawler has already loaded it
            # Check if current URL is already the target URL
            current_url = self.driver.current_url
            screenshot_dir = photo_dir
            os.makedirs(screenshot_dir, exist_ok=True)
            screenshot_path = os.path.join(screenshot_dir, "initial.png")
            self.driver.save_screenshot(screenshot_path)
            # Max consecutive CONTINUE count limit
            MAX_CONTINUE_LOOPS = 5
            continue_loops = 0
            # Record last URL for detecting page changes
            last_url = self.driver.current_url
            need_rescan = False  # Flag for whether rescan is needed (DOM changed but URL didn't)
            while not task.completed:
                current_url = self.driver.current_url
                if self.url_in_scope and not self.url_in_scope(current_url):
                    self._log(
                        f"[ScopeGuard] Browser left target origin before a task step: "
                        f"{current_url}"
                    )
                    self.driver.get(task.initial_url)
                    task.set_completed()
                    break
                # Don't cache, update everything directly.
                self.sensors.update_abstract_page()

                page_description = self.sensors.get_abstract_page()
                self._log(f"[InteractionExecutionAgent] LLM input\n{page_description}")
                prompt = self.generate_bridge_onestep_prompt(task, page_description, task.get_history())
                command_text = self.query_llm(prompt)
                self._log(f"[InteractionExecutionAgent] LLM output: {command_text}")
                # Extract and display CONTINUE Decision section (for debugging)
                if "CONTINUE Decision:" in command_text:
                    decision_start = command_text.find("CONTINUE Decision:")
                    command_start = command_text.find("Command:", decision_start)
                    if decision_start != -1 and command_start != -1:
                        decision_text = command_text[decision_start:command_start].strip()
                        self._log(f"[InteractionExecutionAgent] {decision_text}")
                # # Step 1: Split text by "Command:"
                try:
                    command_parts = command_text.split("Command:")
                    commands = command_parts[1].strip().splitlines()
                except Exception as e:
                    self._log(f"[InteractionExecutionAgent] Failed to parse command ({e}). LLM output may not follow format {command_text}, retrying this step.")
                    continue  # Go to next while iteration, re-query LLM
                saw_continue = False
                for command_text in commands:
                    if command_text == "CONTINUE":
                        saw_continue = True
                        # Don't break, continue executing all actions needed on this page
                        continue
                    kind, action_id, value, raw_cmd = self._parse_command(command_text)
                    self._log(f"[InteractionExecutionAgent] Parsed command: kind={kind}, id={action_id}, value={value}")
                    if not kind:
                        self._log(f"[InteractionExecutionAgent] Unrecognized command: {raw_cmd}")
                        # Log error but continue executing subsequent commands
                        # Reason: could be LLM output format error, shouldn't block subsequent correct commands
                        self._log(f"[InteractionExecutionAgent] Skipping unrecognized command, continuing with subsequent commands")
                        continue  # Skip this iteration, continue next command
                    elif kind in ("DONE"):
                        self._log(f"[InteractionExecutionAgent] Received ending command: {kind}, ending current task")
                        # Record history in one-line format (occurs on old_url page)
                        old_url = self.driver.current_url
                        action_repr = "<ending>"
                        history_line = f'page="{_norm_url(old_url)} | cmd="{raw_cmd}" | component={action_repr}"'
                        task.add_history(history_line)
                        task.set_completed()
                        break
                    elif kind in ("FAIL"):
                        self._log(f"[InteractionExecutionAgent] Received failure command: {kind}, ending current task")
                        # Record history in one-line format (occurs on old_url page)
                        task.clear_history()
                        self.driver.get(task.initial_url)
                        # fail_count += 1
                        task.set_completed()
                        break
                    old_url = self.driver.current_url
                    old_handles = list(self.driver.window_handles)
                    # Sometimes if the output doesn't match, redo a round
                    try:
                        # Get action_repr first (element hasn't gone stale yet)
                        if action_id is not None:
                            action_repr = self._action_repr(action_id)
                        else:
                            action_repr = "<keyboard: Enter>"
                    except Exception as e:
                        self._log(f"[InteractionExecutionAgent] Failed to parse command ({e}). LLM output action may not match {command_text}, retrying this step.")
                        continue  # Go to next while iteration, re-query LLM
                    # Clear and start recording
                    if self._tracer and getattr(self._tracer, "network_capture", None):
                        self._tracer.network_capture.clear_requests()
                    # Execute
                    if kind == "CLICK":
                        success = self.execute_task_step(task, action_id)
                    elif kind == "TRIGGER":
                        # TRIGGER command: only execute event
                        success = self.execute_task_step(task, action_id, force_event=True)
                    elif kind == "TYPE":
                        success = self.execute_task_step(task, action_id, value=value)
                    elif kind == "SELECT":
                        success = self.execute_task_step(task, action_id, value=value)
                    elif kind == "CHECK":
                        success = self.execute_task_step(task, action_id, value=True)
                    elif kind == "UNCHECK":
                        success = self.execute_task_step(task, action_id, value=False)
                    elif kind == "SUBMIT":
                        success = self.execute_task_step(task, action_id)
                    elif kind == "UPLOAD":
                        # file_path = value
                        # if not file_path:
                        #     # todo: complete file upload vulnerability detection, just use a default for now during crawl phase
                        #     file_path = "crawl/file_upload.txt"
                        # success = self.execute_task_step(task, action_id, value=value)
                        success = True  # Pretend success to avoid task interruption
                        continue  # Skip subsequent processing
                    # PRESS ENTER
                    elif kind == "PRESS_ENTER":
                        try:
                            active = self.driver.switch_to.active_element
                            active.send_keys(Keys.ENTER)
                            success = True
                        except Exception as e:
                            self._log(f"[InteractionExecutionAgent] PRESS ENTER failed: {e}")
                            success = False
                    elif kind == "BACK":
                        back_url = value
                        self._log(f"[InteractionExecutionAgent] Received BACK, navigating to: {back_url}")
                        action_repr = "<navigation: BACK>"
                        if self.url_in_scope and not self.url_in_scope(back_url):
                            self._log(f"[ScopeGuard] Refusing out-of-scope BACK URL: {back_url}")
                            task.set_completed()
                            break
                        self.driver.get(back_url)
                        success = True  # BACK operation treated as success
                    else:
                        self._log(f"[InteractionExecutionAgent] Unimplemented action: {kind}")
                        # Log error but continue executing subsequent commands
                        # Reason: could be an unsupported command from LLM, shouldn't block subsequent commands
                        self._log(f"[InteractionExecutionAgent] Skipping unimplemented action, continuing with subsequent commands")
                        continue  # Skip this iteration, continue next command
                    if not success:
                        self._log(f"[InteractionExecutionAgent] Execution failed: {raw_cmd}")
                        # Log failure but continue executing subsequent commands
                        # Reason: one operation failing (e.g. file upload) shouldn't block subsequent operations (e.g. form submit)
                        # Record failed history
                        history_line = f'page="{_norm_url(old_url)} | cmd="{raw_cmd}" | component={action_repr}" | status=FAILED'
                        task.add_history(history_line)
                        # Screenshot to record failure state
                        screenshot_filename = re.sub(r"[^a-zA-Z0-9._-]+", "_", raw_cmd)[:120] + "_FAILED.png"
                        screenshot_path = os.path.join(screenshot_dir, screenshot_filename)
                        try:
                            self.driver.save_screenshot(screenshot_path)
                            self._log(f"[InteractionExecutionAgent] Failure screenshot: {screenshot_path}")
                        except Exception:
                            pass
                        self._log(f"[InteractionExecutionAgent] Skipping failed operation, continuing with subsequent commands")
                        continue  # Skip remaining processing for this iteration, continue next command


                    # # Wait briefly for URL/DOM to stabilize
                    # try:
                    #     time.sleep(0.5)
                    # except Exception:
                    #     pass

                    # Wait for page to stabilize
                    try:
                        if kind in ('SUBMIT', 'TRIGGER'):
                            # For form submit type operations, wait for URL change or timeout
                            from selenium.webdriver.support.ui import WebDriverWait
                            try:
                                WebDriverWait(self.driver, 7).until(
                                    lambda d: d.current_url != old_url
                                )
                                self._log(f"[InteractionExecutionAgent] URL change detected, redirect complete")
                            except TimeoutException:
                                # Timeout without URL change is also OK (could be AJAX submit or in-page operation)
                                self._log(f"[InteractionExecutionAgent] URL unchanged after 3 second wait, continuing execution")
                        else:
                            time.sleep(0.5)
                    except Exception:
                        pass

                    # Check and clear popups
                    clear_alert(self.driver, action="dismiss")
                    new_url = self.driver.current_url
                    if self.url_in_scope and not self.url_in_scope(new_url):
                        self._log(
                            f"[ScopeGuard] Blocking navigation outside target origin: "
                            f"{old_url} -> {new_url}"
                        )
                        self.driver.get(task.initial_url)
                        task.set_completed()
                        break
                    new_handles = list(self.driver.window_handles)
                    jump_kind = self._classify_jump(kind, action_id, old_handles, new_handles)
                    # Detect page navigation
                    page_changed = (new_url != old_url)
                    if page_changed:
                        self._log(f"[InteractionExecutionAgent] Page navigation detected: {old_url} -> {new_url}")
                    # Record execution history
                    history_line = f'page="{_norm_url(old_url)} | cmd="{raw_cmd}" | component={action_repr}"'
                    task.add_history(history_line)
                    # Screenshot
                    screenshot_filename = re.sub(r"[^a-zA-Z0-9._-]+", "_", raw_cmd)[:120] + ".png"
                    screenshot_path = os.path.join(screenshot_dir, screenshot_filename)
                    self.driver.save_screenshot(screenshot_path)
                    self._log(f"[InteractionExecutionAgent] Screenshot: {screenshot_path}")
                    # Callback tracer: notify of this step's from->to, action repr, jump kind
                    if self._tracer:
                        self._tracer.step(
                            from_url=_norm_url(old_url),
                            to_url=_norm_url(new_url),
                            action_id=action_id,
                            action_repr=action_repr,
                            command_kind=kind,
                            jump_kind=jump_kind,
                            raw_cmd=raw_cmd,
                            logging_in=logging_in,
                        )
                    # If navigation action caused page jump, stop executing remaining commands this round
                    # But all recording work (history, screenshot, tracer) is completed before stopping
                    if page_changed and kind in ["SUBMIT", "CLICK", "BACK"]:
                        self._log(f"[InteractionExecutionAgent] {kind} action caused page navigation, stopping remaining commands this round")
                        self._log(f"[InteractionExecutionAgent] New page will be processed in the next loop iteration")
                        # Update last_url to trigger new page loading logic
                        last_url = new_url
                        # break
                    # If task needs termination condition (STOP returned by model), keep original logic
                    if kind == "STOP":
                        task.set_completed()
                        break
                if saw_continue:
                    continue_loops += 1
                    if continue_loops >= MAX_CONTINUE_LOOPS:
                        self._log(f"[InteractionExecutionAgent] CONTINUE count reached limit {MAX_CONTINUE_LOOPS}, ending task")
                        self._log(f"[InteractionExecutionAgent] Hint: task may be too complex, or LLM is overusing CONTINUE")
                        task.set_completed()
                        break
                    else:
                        self._log(f"[InteractionExecutionAgent] CONTINUE detected, continuing next round ({continue_loops}/{MAX_CONTINUE_LOOPS})")
                        self._log(f"[InteractionExecutionAgent] LLM believes task needs to continue, will rescan page and ask again")
                        # Set rescan flag (unless URL already changed)
                        # Because CONTINUE usually means DOM may have changed (e.g. show/hide elements, modal, etc.)
                        need_rescan = True
                        continue  # Back to while, re-fetch page, re-query LLM
                else:
                    # No CONTINUE, this round is considered complete
                    task.set_completed()
                    break
        finally:
            # Ensure task log file is closed regardless
            self._close_task_log()
