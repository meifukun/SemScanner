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
# todo: 可以加一个press enter操作，大模型填写完form后如果发现没有submit按钮可以用这个操作来提交
class Actuators:
    """
    常见网页动作的执行器：
    - execute_action_by_id(action_id, **kwargs) 智能分发（最通用）
    - click_by_id / type_text_by_id / select_by_id / set_checkbox_by_id / select_radio_by_id ...
    - fill_form(form_id, data) / submit_form(form_id, submit_id=None)
    """
    DEFAULT_TEXT = "test"           # 文本输入默认值
    DEFAULT_TEXTAREA = "hello"      # 文本域默认值

    def __init__(self, sensors, timeout: int = 10):
        self.driver = sensors.driver
        self.sensors = sensors
        self.wait = WebDriverWait(self.driver, timeout)

    # # ======= 公共入口：智能分发 =======
    # def execute_action_by_id(self, action_id: int, **kwargs) -> bool:
    #     """
    #     根据 action_id 查表并执行对应类型的操作。
    #     kwargs 用于传参（如 text/values/checked/index 等）。
    #     """
    #     actions_mapping = self.sensors.get_actions_mapping()
    #     element = actions_mapping.get_action_elem(action_id)
    #     action_type = actions_mapping.get_action_type(action_id)

    #     if element is None or action_type is None:
    #         print(f"[Actuators] 无法找到 action_id={action_id} 的元素或类型")
    #         return False

    #     # 统一滚动到视区，并等待可见
    #     if not self._ensure_visible(element):
    #         print(f"[Actuators] 元素不可见/无法滚动到视区: id={action_id}, type={action_type}")
    #         return False

    #     try:
    #         if action_type == "clickable":
    #             return self._handle_click_action(element, action_id)

    #         if action_type == "form":
    #             # 如果传了 submit=True 则提交；否则仅返回 True（已定位到 form）
    #             if kwargs.get("submit"):
    #                 return self.submit_form(action_id, submit_id=kwargs.get("submit_id"))
    #             return True

    #         # 输入类：input:*
    #         if action_type.startswith("input:"):
    #             subtype = action_type.split(":", 1)[1]

    #             # 常见文本类 input
    #             if subtype in {"text", "password", "email", "search", "tel", "url", "number",
    #                            "date", "datetime-local", "month", "week", "time", "color"}:
    #                 text = kwargs.get("text", self.DEFAULT_TEXT)
    #                 press_enter = bool(kwargs.get("enter", False))
    #                 return self._handle_text_input(element, text=text, press_enter=press_enter)

    #             # 文件上传
    #             if subtype == "file":
    #                 file_path = kwargs.get("file_path")
    #                 return self._handle_file_input(element, file_path=file_path)

    #             # 复选框
    #             if subtype == "checkbox":
    #                 if "checked" in kwargs:
    #                     return self._handle_checkbox(element, checked=bool(kwargs["checked"]))
    #                 if kwargs.get("toggle"):
    #                     return self._safe_click(element)
    #                 # 未指定则默认勾上
    #                 return self._handle_checkbox(element, checked=True)

    #             # 单选（按 name 分组）
    #             if subtype == "radio":
    #                 # 可传 value / label / index
    #                 return self._handle_radio(element,
    #                                           value=kwargs.get("value"),
    #                                           label=kwargs.get("label"),
    #                                           index=kwargs.get("index"))

    #             # 提交/按钮类
    #             if subtype in {"submit", "button", "image"}:
    #                 return self._handle_click_action(element, action_id)

    #             # 其他未知 input，当作文本输入
    #             text = kwargs.get("text", self.DEFAULT_TEXT)
    #             return self._handle_text_input(element, text=text)

    #         # 下拉选择
    #         if action_type == "select":
    #             # 可传 value / text / index / values(list) / texts(list)
    #             return self._handle_select(element,
    #                                        value=kwargs.get("value"),
    #                                        text=kwargs.get("text"),
    #                                        index=kwargs.get("index"),
    #                                        values=kwargs.get("values"),
    #                                        texts=kwargs.get("texts"))

    #         # 文本域
    #         if action_type == "textarea":
    #             text = kwargs.get("text", self.DEFAULT_TEXTAREA)
    #             press_enter = bool(kwargs.get("enter", False))
    #             return self._handle_textarea(element, text=text, press_enter=press_enter)

    #         print(f"[Actuators] 未知操作类型: {action_type}")
    #         return False

    #     except (StaleElementReferenceException, ElementNotInteractableException,
    #             WebDriverException) as e:
    #         print(f"[Actuators] 执行失败 id={action_id} type={action_type} err={e}")
    #         return False

    # 与执行器适配的方法，外部参数统一为value
    def execute_action_by_id(self, action_id: int, value: Optional[str] = None) -> bool:
        """
        根据 action_id 查表并执行对应类型的操作。
        :param action_id: 要执行的操作元素的 ID
        :param value: 对应的值，例如文本输入框的文本、下拉选择的值等
        :return: 是否成功执行
        """
        actions_mapping = self.sensors.get_actions_mapping()
        element = actions_mapping.get_action_elem(action_id)
        
        # 如果没有找到元素，则返回 False
        if element is None:
            print(f"[Actuators] 无法找到 action_id={action_id} 对应的元素")
            return False

        # 如果元素类型没有找到，也返回 False
        action_type = actions_mapping.get_action_type(action_id)
        if action_type is None:
            print(f"[Actuators] 无法找到 action_id={action_id} 对应的元素类型")
            return False

        # 统一滚动到视区，并等待可见
        if not self._ensure_visible(element):
            print(f"[Actuators] 元素不可见或无法滚动到视区: id={action_id}, type={action_type}")
            return False

        try:
            # 根据 action_type 来判断要执行的具体操作
            if action_type == "clickable":
                return self._handle_click_action(element, action_id)

            elif action_type == "form":
                # 处理表单提交
                if value == "submit":  # 可以通过 kwargs 来传递 submit 信息
                    return self.submit_form(action_id)
                return True

            elif action_type.startswith("input:"):
                # 输入类型操作：处理文本输入
                subtype = action_type.split(":", 1)[1]

                if subtype in {"text", "password", "email", "search", "tel", "url", "number", 
                            "date", "datetime-local", "month", "week", "time", "color"}:
                    text = value or self.DEFAULT_TEXT  # 使用默认文本或者传递的文本
                    return self._handle_text_input(element, text=text)

                elif subtype == "file":
                    return self._handle_file_input(element, file_path=value)

                elif subtype == "checkbox":
                    checked = True if value is None else bool(value)
                    return self._handle_checkbox(element, checked=checked)

                elif subtype == "radio":
                    return self._handle_radio(element, value=value)

                else:
                    # 处理其他类型的输入（提交按钮、image 等）
                    return self._handle_click_action(element, action_id)

            elif action_type == "select":
                # 下拉选择操作
                return self._handle_select(element, value=value)

            elif action_type == "textarea":
                # 处理文本域
                text = value or self.DEFAULT_TEXTAREA
                return self._handle_textarea(element, text=text)

            else:
                print(f"[Actuators] 未知操作类型: {action_type}")
                return False

        except (StaleElementReferenceException, ElementNotInteractableException,
                WebDriverException) as e:
            print(f"[Actuators] 执行失败 id={action_id} type={action_type} err={e}")
            return False


    # ======= 便捷方法 =======
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

    # ======= 表单级操作 =======
    def fill_form(self, form_id: int, data: Dict[str, Any]) -> bool:
        """
        data 的 key 优先匹配字段的 name，其次 id。
        value 的类型：
          - 文本类/textarea：str
          - checkbox：bool
          - radio：str(按 value) 或 {'label': '...'} 或 {'index': 0}
          - select：str/int 或 list[str|int]（多选）
        """
        actions = self.sensors.get_actions_mapping()
        form_elem = actions.get_action_elem(form_id)
        if form_elem is None:
            print(f"[Actuators] 未找到 form: id={form_id}")
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
                    # 不在 data 里，跳过
                    continue

                val = data[key]
                # 找出该字段在 actions_mapping 里的 id（用于分发）
                # 由于你在 Sensors 里对字段也 add_action 了，可通过反查接口（假设有）
                # 但这里我们直接根据 tag/type 调用处理器，更快。
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
                            # 不是 bool，忽略
                            pass
                    elif subtype == 'radio':
                        # radio 是 group 操作：根据 name 找同组
                        self._handle_radio(field,
                                           value=val if isinstance(val, str) else None,
                                           label=val.get('label') if isinstance(val, dict) else None,
                                           index=val.get('index') if isinstance(val, dict) else None)
                    else:
                        # 其他未知 input，当作文本
                        self._handle_text_input(field, text=str(val))
                elif tag == 'select':
                    # 单值或多值
                    if isinstance(val, (list, tuple, set)):
                        self._handle_select(field, values=list(val), texts=None)
                    else:
                        # 单值：尝试按 text/value/index
                        self._handle_select(field, value=val, text=val if isinstance(val, str) else None)
                elif tag == 'textarea':
                    self._handle_textarea(field, text=str(val))
                else:
                    pass
            except Exception as e:
                print(f"[Actuators] 填充字段失败 name/id={f_name or f_id} err={e}")
                ok = False
        return ok

    def submit_form(self, form_id: int, submit_id: Optional[int]=None) -> bool:
        """
        优先点击明确的提交控件；若找不到，则调用 form.submit()
        """
        actions = self.sensors.get_actions_mapping()
        form_elem = actions.get_action_elem(form_id)
        if form_elem is None:
            print(f"[Actuators] 未找到 form: id={form_id}")
            return False

        # 如果指定了 submit_id，优先点击它
        if submit_id is not None:
            submit_elem = actions.get_action_elem(submit_id)
            if submit_elem is None:
                print(f"[Actuators] 指定的 submit_id 不存在: {submit_id}")
                return False
            return self._safe_click(submit_elem)

        # 在 form 内查找提交控件
        try:
            submit = None
            # 常见提交控件
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

        # 兜底：原生提交
        try:
            self.driver.execute_script("arguments[0].submit();", form_elem)
            return True
        except WebDriverException as e:
            print(f"[Actuators] form.submit() 失败: {e}")
            return False

    # ======= 各类型处理器 =======
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
            print(f"[Actuators] 文本输入失败: {e}")
            return False

    def _handle_textarea(self, element, text: str, press_enter: bool=False) -> bool:
        return self._handle_text_input(element, text=text, press_enter=press_enter)

    def _handle_file_input(self, element, file_path: Optional[str]) -> bool:
        if not file_path or not os.path.exists(file_path):
            print("[Actuators] 文件路径无效或不存在")
            return False
        try:
            self._wait_interactable(element)
            element.send_keys(os.path.abspath(file_path))
            return True
        except (StaleElementReferenceException, ElementNotInteractableException, WebDriverException) as e:
            print(f"[Actuators] 文件上传失败: {e}")
            return False

    def _handle_checkbox(self, element, checked: bool=True) -> bool:
        try:
            self._wait_interactable(element)
            if element.is_selected() != checked:
                return self._safe_click(element)
            return True
        except (StaleElementReferenceException, ElementNotInteractableException, WebDriverException) as e:
            print(f"[Actuators] 勾选复选框失败: {e}")
            return False

    def _handle_radio(self, element, value: Optional[str]=None,
                      label: Optional[str]=None, index: Optional[int]=None) -> bool:
        """
        radio 按 name 分组；优先用 value/label/index 选择；都没有则点当前这个
        """
        try:
            name = element.get_attribute('name') or ''
            if name:
                group = self.driver.find_elements(By.CSS_SELECTOR, f'input[type="radio"][name="{name}"]')
            else:
                group = [element]

            target = None
            # 1) 按 value
            if value is not None:
                for r in group:
                    if (r.get_attribute('value') or '') == str(value):
                        target = r
                        break
            # 2) 按 label 文本（for 或包裹）
            if target is None and label:
                for r in group:
                    txt = self._get_label_text_for_input(r)
                    if txt and txt.strip() == str(label).strip():
                        target = r
                        break
            # 3) 按 index
            if target is None and index is not None and 0 <= index < len(group):
                target = group[index]
            # 4) 兜底：当前元素
            if target is None:
                target = element

            self._wait_interactable(target)
            if not target.is_selected():
                return self._safe_click(target)
            return True
        except (StaleElementReferenceException, ElementNotInteractableException, WebDriverException) as e:
            print(f"[Actuators] 选择单选失败: {e}")
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
                # 选择单个项，尝试 text -> value -> index
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
                # 都没命中，最后再尝试把 t/v 当作另一种
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
                # 多选
                # 先清空（可根据需要保留已有）
                sel.deselect_all()
                if texts:
                    for t in texts:
                        changed = _select_one(t=t) or changed
                if values:
                    for v in values:
                        changed = _select_one(v=v) or changed
            else:
                # 单选：按 text/value/index 三者之一
                if any(x is not None for x in (text, value, index)):
                    changed = _select_one(v=value, t=text, i=index)
                else:
                    # 未指定，则保持现状；如无已选，选第一项（不 disabled）
                    options = element.find_elements(By.TAG_NAME, 'option')
                    selected = [o for o in options if o.is_selected()]
                    if not selected and options:
                        # 找到第一个可选项
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
            print(f"[Actuators] 选择下拉失败: {e}")
            return False

    # ======= 小工具 =======
    def _ensure_visible(self, element) -> bool:
        try:
            self.driver.execute_script(
                "arguments[0].scrollIntoView({block:'center', inline:'nearest'});", element)
            return element.is_displayed()
        except WebDriverException:
            return False

    def _wait_interactable(self, element):
        # 避免 element_to_be_clickable 的定位器需求，这里用自定义 wait
        self.wait.until(lambda d: self._is_displayed_and_enabled(element))

    def _is_displayed_and_enabled(self, element) -> bool:
        try:
            return element.is_displayed() and element.is_enabled()
        except StaleElementReferenceException:
            return False

    def _safe_click(self, element) -> bool:
        try:
            self._wait_interactable(element)
            try:
                element.click()
            except WebDriverException:
                # 退回 JS 点击（处理遮挡/动画）
                self.driver.execute_script("arguments[0].click();", element)
            return True
        except (StaleElementReferenceException, ElementNotInteractableException, WebDriverException) as e:
            print(f"[Actuators] 点击失败: {e}")
            return False

    def _short_id(self, element) -> str:
        # 用于命名截图：优先用元素 id/name，否则用内存 id
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


