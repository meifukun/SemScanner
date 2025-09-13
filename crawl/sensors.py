from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.common.exceptions import NoSuchElementException, StaleElementReferenceException
from crawl.ActionMapping import ActionsMapping
from bs4 import BeautifulSoup
import time
import re

# todo: 加入对网页的功能抽象

class Sensors:
    def __init__(self, driver):
        self.driver = driver
        self.abstract_page = ''
        self.actions_mapping = ActionsMapping()  # 将 ActionsMapping 封装在 Sensors 中

    def get_abstract_page(self):
        return self.abstract_page

    def get_actions_mapping(self):
        """返回 ActionsMapping 对象"""
        return self.actions_mapping

    # ========== 核心更新：抽象页面，包含表单字段 ==========
    def update_abstract_page(self):
        # 重置计数器
        self.actions_mapping.clear()

        # 获取页面元素
        clickable_elements = self.get_unique_clickables()
        forms = self.get_forms()

        # 清空现有的抽象页面内容
        self.abstract_page = ''

        # 处理可点击元素
        for elem in clickable_elements:
            try:
                id_counter = self.actions_mapping.add_action(elem, 'clickable')
                self.abstract_page += self.clickable_to_string(elem, id_counter) + '\n'
            except StaleElementReferenceException:
                continue

        # 处理表单及其字段
        for form in forms:
            try:
                # form的id删了，因为内部有更细粒度的id了
                # form_id = self.actions_mapping.add_action(form, 'form')
                self.abstract_page += self.form_block_to_string(form) + '\n'
            except StaleElementReferenceException:
                continue

    # ========== 元素 → 文本表示 ==========
    def clickable_to_string(self, elem, id_counter=None):
        # 获取元素的文本和标签
        tag_name = (elem.tag_name or '').lower()
        inner_text = self.element_to_text(elem)

        # 如果是提交按钮，转化为按钮标签
        if tag_name == 'input' and (elem.get_attribute('type') or '').lower() == 'submit':
            tag_name = 'button'

        id_string = f' id={id_counter}' if id_counter else ''
        return f'<{tag_name}{id_string}>{inner_text}</{tag_name}>'

    def input_field_to_string(self, elem, id_counter=None):
        t = (elem.get_attribute('type') or 'text').lower()
        name = self.safe_attr(elem, 'name')
        placeholder = self.safe_attr(elem, 'placeholder')
        value = self.safe_attr(elem, 'value')
        required = ' required' if self.has_attr(elem, 'required') else ''
        disabled = ' disabled' if (not elem.is_enabled()) else ''
        checked = ''
        if t in ('checkbox', 'radio'):
            try:
                checked = ' checked' if elem.is_selected() else ''
            except StaleElementReferenceException:
                checked = ''

        label = self.get_label_for_input(elem)

        id_string = f' id={id_counter}' if id_counter else ''
        return (f'<input{id_string} type="{t}" name="{name}" placeholder="{placeholder}"'
                f' value="{value}"{required}{disabled}{checked}>{label}</input>')

    def select_to_string(self, elem, id_counter=None):
        name = self.safe_attr(elem, 'name')
        required = ' required' if self.has_attr(elem, 'required') else ''
        multiple = ' multiple' if self.has_attr(elem, 'multiple') else ''
        disabled = ' disabled' if (not elem.is_enabled()) else ''
        label = self.get_label_for_input(elem)

        options = elem.find_elements(By.TAG_NAME, 'option')
        options_count = len(options)

        id_string = f' id={id_counter}' if id_counter else ''
        # 头部行：保留你原有的风格与统计信息
        header = (f'<select{id_string} name="{name}" options={options_count}'
                f'{required}{multiple}{disabled}>{label}')

        # 没有选项时直接闭合
        if options_count == 0:
            return header + '</select>'

        lines = [header]
        listed = 0
        for opt in options:
            if listed >= getattr(self, 'MAX_OPTIONS_TO_LIST', 200):
                remaining = options_count - listed
                lines.append(f'  <!-- ... {remaining} more options not shown -->')
                break
            try:
                val = self.safe_attr(opt, 'value')
                txt = (opt.text or '').strip()
                sel = ' selected' if opt.is_selected() else ''
                dis = ' disabled' if (not opt.is_enabled()) else ''
                group_label = self.get_optgroup_label(opt)
                grp_attr = f' group="{group_label}"' if group_label else ''
                lines.append(f'  <option value="{val}"{sel}{dis}{grp_attr}>{txt}</option>')
                listed += 1
            except Exception:
                # 避免单个 option 异常影响整体
                continue

        lines.append('</select>')
        return '\n'.join(lines)

    def get_optgroup_label(self, option_elem):
        """若 option 属于某个 <optgroup>，取其 label；否则返回空字符串。"""
        from selenium.common.exceptions import NoSuchElementException, StaleElementReferenceException
        try:
            grp = option_elem.find_element(By.XPATH, 'ancestor::optgroup[1]')
            return self.safe_attr(grp, 'label') or ''
        except (NoSuchElementException, StaleElementReferenceException):
            return ''


    def textarea_to_string(self, elem, id_counter=None):
        name = self.safe_attr(elem, 'name')
        placeholder = self.safe_attr(elem, 'placeholder')
        required = ' required' if self.has_attr(elem, 'required') else ''
        disabled = ' disabled' if (not elem.is_enabled()) else ''
        # textarea 的 value 是其 text
        value = (elem.get_attribute('value') or elem.text or '').strip()
        label = self.get_label_for_input(elem)

        id_string = f' id={id_counter}' if id_counter else ''
        return (f'<textarea{id_string} name="{name}" placeholder="{placeholder}"'
                f'{required}{disabled} value="{value}">{label}</textarea>')

    # def form_to_string(self, elem, id_counter=None):
    #     # 获取表单的属性（name, action, method）
    #     name = self.safe_attr(elem, 'name') or self.safe_attr(elem, 'id')
    #     action = self.safe_attr(elem, 'action')
    #     method = (self.safe_attr(elem, 'method') or '').upper() or 'GET'
    #     id_string = f' id={id_counter}' if id_counter else ''
    #     return f'<form{id_string} name="{name}" action="{action}" method="{method}">'

    # 不要form id的版本，因为内部有更细粒度的可操作id了
    def form_to_string(self, elem):
        # 获取表单的属性（name, action, method）
        name = self.safe_attr(elem, 'name') or self.safe_attr(elem, 'id')
        action = self.safe_attr(elem, 'action')
        method = (self.safe_attr(elem, 'method') or '').upper() or 'GET'
        return f'<form name="{name}" action="{action}" method="{method}">'

    def form_block_to_string(self, form_elem, form_id=None):
        """包含表单起始行 + 字段行 + 收尾</form>"""
        # lines = [self.form_to_string(form_elem, form_id)]
        lines = [self.form_to_string(form_elem)]
        fields = self.get_form_fields(form_elem)

        for field in fields:
            try:
                field_id = self.add_action_for_field(field)
                # 根据标签类型分别序列化
                tag = (field.tag_name or '').lower()
                if tag == 'input':
                    line = self.input_field_to_string(field, field_id)
                elif tag == 'select':
                    line = self.select_to_string(field, field_id)
                elif tag == 'textarea':
                    line = self.textarea_to_string(field, field_id)
                else:
                    # 兜底（极少见）
                    line = f'<{tag} id={field_id}></{tag}>'
                lines.append('  ' + line)  # 缩进，阅读友好
            except StaleElementReferenceException:
                continue
        lines.append('</form>')
        return '\n'.join(lines)

    # ========== 元素收集 & 过滤 ==========
    def get_unique_clickables(self):
        # 获取所有可点击元素（a, button, input[type="submit"]等）
        clickables = self.driver.find_elements(
            By.CSS_SELECTOR,
            'a, button, input[type="submit"], input[type="button"], [onclick]'
        )
        return self.filter_clickables(clickables)

    def get_forms(self):
        # 获取所有表单元素
        return self.driver.find_elements(By.TAG_NAME, 'form')

    def get_form_fields(self, form_elem):
        """
        返回 form 内部可交互字段：input/select/textarea
        - 过滤隐藏 input[type=hidden]
        - 过滤不可见/被遮挡
        """
        try:
            fields = form_elem.find_elements(By.CSS_SELECTOR, 'input, select, textarea')
        except StaleElementReferenceException:
            return []

        visible_fields = []
        for f in fields:
            try:
                if (f.tag_name.lower() == 'input' and (f.get_attribute('type') or '').lower() == 'hidden'):
                    continue
                if self.is_obscured_or_invisible(f):
                    continue
                visible_fields.append(f)
            except StaleElementReferenceException:
                continue
        return visible_fields

    def filter_clickables(self, clickables):
        # 过滤无效的可点击元素，例如不可见/被遮挡的元素
        valid_clickables = []
        for clickable in clickables:
            try:
                if self.is_obscured_or_invisible(clickable):
                    continue
                valid_clickables.append(clickable)
            except StaleElementReferenceException:
                continue
        return valid_clickables

    def is_obscured_or_invisible(self, element):
        # 检查元素是否被遮挡或不可见
        try:
            self.driver.execute_script("arguments[0].scrollIntoView({block:'center', inline:'nearest'});", element)
            return not element.is_displayed()
        except Exception:
            return True

    def element_to_text(self, element):
        # 获取元素的文本内容（无文本返回空字符串）
        try:
            return (element.text or '').strip()
        except StaleElementReferenceException:
            return ''

    # ========== Label 解析（更稳健） ==========
    def get_label_for_input(self, input_elem):
        """
        优先级：
        1) <label for="id"> 绑定
        2) 包裹式 <label>...<input/>... </label>
        3) aria-label
        4) aria-labelledby 指向的文本
        5) title
        """
        # 1) for 绑定
        try:
            input_id = self.safe_attr(input_elem, 'id')
            if input_id:
                lbl = self.driver.find_element(By.XPATH, f'//label[@for="{input_id}"]')
                if lbl:
                    txt = (lbl.text or '').strip()
                    if txt:
                        return txt
        except NoSuchElementException:
            pass
        except StaleElementReferenceException:
            return ''

        # 2) 包裹式 label
        try:
            lbl_wrap = input_elem.find_element(By.XPATH, 'ancestor::label[1]')
            if lbl_wrap:
                txt = (lbl_wrap.text or '').strip()
                if txt:
                    return txt
        except NoSuchElementException:
            pass
        except StaleElementReferenceException:
            return ''

        # 3) aria-label
        aria_label = self.safe_attr(input_elem, 'aria-label')
        if aria_label:
            return aria_label

        # 4) aria-labelledby
        labelledby = self.safe_attr(input_elem, 'aria-labelledby')
        if labelledby:
            texts = []
            for _id in labelledby.split():
                try:
                    el = self.driver.find_element(By.ID, _id)
                    if el:
                        t = (el.text or '').strip()
                        if t:
                            texts.append(t)
                except NoSuchElementException:
                    continue
                except StaleElementReferenceException:
                    continue
            if texts:
                return ' '.join(texts)

        # 5) title 兜底
        title = self.safe_attr(input_elem, 'title')
        return title or ''

    # ========== 工具/辅助 ==========
    def add_action_for_field(self, elem):
        """为字段添加 action，类型区分更细，便于后续操作"""
        tag = (elem.tag_name or '').lower()
        if tag == 'input':
            t = (elem.get_attribute('type') or 'text').lower()
            kind = f'input:{t}'
        else:
            kind = tag  # 'select' / 'textarea'
        return self.actions_mapping.add_action(elem, kind)

    def safe_attr(self, elem, name):
        try:
            return elem.get_attribute(name) or ''
        except StaleElementReferenceException:
            return ''

    def has_attr(self, elem, name):
        try:
            return elem.get_attribute(name) is not None
        except StaleElementReferenceException:
            return False
    
    from bs4 import BeautifulSoup, Comment
    # ========== 新增：提取有价值的信息，让大模型做整体抽象 ==========
    def extract_valuable_information(self,
                                    drop_hidden: bool = True,
                                    drop_boilerplate: bool = True,
                                    text_max: int = 160) -> str:
        """
        提取“有信息价值”的骨架 HTML（保留交互元素 + 可读结构 + 主要文本）。
        - 修复：保留<form>控件；避免一行输出；清理<title>泄露。
        """

        import re
        from bs4 import BeautifulSoup, Comment
        from selenium.webdriver.common.by import By
        from selenium.common.exceptions import StaleElementReferenceException, NoSuchElementException

        html = self.driver.page_source
        soup = BeautifulSoup(html, "html.parser")

        # ---------- 工具 ----------
        def safe_attrs(el):
            return (getattr(el, "attrs", {}) or {})

        def has_any_attr(el, keys):
            try:
                return bool(set(safe_attrs(el).keys()) & set(keys))
            except Exception:
                return False

        def norm_text(s: str) -> str:
            s = re.sub(r"\s+", " ", (s or "").strip())
            if text_max and len(s) > text_max:
                s = s[: text_max - 1] + "…"
            return s

        # ---------- 0) 收集“强保留”元素 ----------
        must_keep_ids, must_keep_names, must_keep_hrefs = set(), set(), set()
        fuzzy_keys = []  # (tag, text[:60])

        try:
            clickables = self.get_unique_clickables()
        except Exception:
            clickables = []
        for el in clickables:
            try:
                _id = (el.get_attribute("id") or "").strip()
                _name = (el.get_attribute("name") or "").strip()
                _href = (el.get_attribute("href") or "").strip()
                _tag = (el.tag_name or "").lower()
                _txt = norm_text(self.element_to_text(el))
                if _id: must_keep_ids.add(_id)
                if _name: must_keep_names.add(_name)
                if _href: must_keep_hrefs.add(_href)
                if _txt: fuzzy_keys.append((_tag, _txt[:60]))
            except StaleElementReferenceException:
                continue

        try:
            forms = self.get_forms()
        except Exception:
            forms = []
        kept_form_ids, all_fields = set(), []
        for f in forms:
            try:
                fields = self.get_form_fields(f)
            except StaleElementReferenceException:
                fields = []
            all_fields.extend(fields)

        for fld in all_fields:
            try:
                _id = (fld.get_attribute("id") or "").strip()
                _name = (fld.get_attribute("name") or "").strip()
                _tag = (fld.tag_name or "").lower()
                _txt = norm_text(self.get_label_for_input(fld)) if _tag == "input" else ""
                if _id: must_keep_ids.add(_id)
                if _name: must_keep_names.add(_name)
                if _txt: fuzzy_keys.append((_tag, _txt[:60]))
                # 保留其 form
                try:
                    form_ancestor = fld.find_element(By.XPATH, "ancestor::form[1]")
                    if form_ancestor:
                        fid = (form_ancestor.get_attribute("id") or "").strip()
                        if fid:
                            kept_form_ids.add(fid)
                except Exception:
                    pass
            except StaleElementReferenceException:
                continue

        # ---------- 1) 删除注释 ----------
        for c in soup.find_all(string=lambda t: isinstance(t, Comment)):
            c.extract()

        # ---------- 2) 删除无用标签 ----------
        # 注意把 <title> 也删掉，避免标题文本落入正文
        for sel in ["script", "style", "template", "noscript", "meta", "iframe", "svg", "canvas", "object", "title"]:
            for el in soup.select(sel):
                el.decompose()

        # <head> 资源型 <link>（不动 <a>）
        head = soup.head
        if head:
            for sel in [
                'link[rel~="stylesheet"]', 'link[rel~="preload"]', 'link[rel~="preconnect"]',
                'link[rel~="dns-prefetch"]', 'link[rel~="modulepreload"]', 'link[rel~="icon"]',
                'link[rel~="shortcut icon"]', 'link[rel~="apple-touch-icon"]', 'link[as]'
            ]:
                for el in head.select(sel):
                    el.decompose()

        # ---------- 3) 可选：删除隐藏节点 ----------
        if drop_hidden:
            for el in soup.select("[hidden], [aria-hidden='true'], input[type='hidden'], "
                                "[style*='display:none'], [style*='visibility:hidden']"):
                el.decompose()

        # ---------- 4) 可选：删除样板噪声 ----------
        if drop_boilerplate:
            for sel in ["#wpadminbar", "#wpfooter",
                        ".cookie-banner", ".cookies", ".gdpr",
                        ".ads", ".ad", ".advert", ".sponsor",
                        ".analytics", ".tracking", ".clear", ".clearfix"]:
                for el in soup.select(sel):
                    el.decompose()

        # ---------- 5) 标签白名单（其余 unwrap） ----------
        allowed_tags = {
            "html","body","header","nav","main","footer",
            "section","article","aside","div","span","p",
            "h1","h2","h3","h4","h5","h6",
            "a","button","img","br","hr",
            "ul","ol","li",
            "table","thead","tbody","tr","th","td",
            "form","label","input","select","option","textarea",
            "small","strong","em"
        }
        for el in list(soup.find_all(True)):
            if el.name not in allowed_tags:
                el.unwrap()

        # ---------- 6) 属性白名单 & class 精简 ----------
        keep_attrs = {
            "id","class","href","src","alt","title",
            "role","aria-label","type","placeholder","value","name","for","action","method",
            # 额外保留 data-* 里对你动作有用的两个（可扩展）
            "data-help-url", "data-source-url"
        }
        for el in soup.find_all(True):
            attrs = safe_attrs(el)
            filtered = {k: v for k, v in attrs.items() if k in keep_attrs}
            if "class" in filtered:
                classes = filtered["class"]
                if isinstance(classes, (list, tuple)):
                    classes = [c for c in classes if c not in ("clear", "clearfix", "container")]
                    class_str = " ".join(classes)
                    if len(class_str) > 60:
                        filtered.pop("class", None)
                    else:
                        filtered["class"] = classes
                else:
                    if len(str(classes)) > 60:
                        filtered.pop("class", None)
            el.attrs = filtered

        # ---------- 7) 标注强保留 ----------
        def mark_keep_by_attr(attr_name: str, values: set):
            if not values:
                return
            for v in list(values):
                for el in soup.find_all(attrs={attr_name: v}):
                    el.attrs["data-keep"] = "1"

        mark_keep_by_attr("id", must_keep_ids | kept_form_ids)
        mark_keep_by_attr("name", must_keep_names)

        if must_keep_hrefs:
            for el in soup.find_all("a", href=True):
                try:
                    if el["href"] in must_keep_hrefs:
                        el.attrs["data-keep"] = "1"
                except Exception:
                    pass

        def fuzzy_mark(tag: str, txt: str):
            if not txt:
                return
            for el in soup.find_all(tag):
                t = norm_text(el.get_text(" ", strip=True))
                if t and txt in t:
                    el.attrs["data-keep"] = "1"
                    break

        for tag, txt in fuzzy_keys:
            fuzzy_mark(tag, txt)

        for lab in soup.find_all("label"):
            _for = lab.get("for")
            if _for and _for in must_keep_ids:
                lab.attrs["data-keep"] = "1"

        # ---------- 8) 文本归一化 ----------
        for tn in list(soup.find_all(string=True)):
            text = str(tn)
            if not text or not text.strip():
                tn.extract()
                continue
            tn.replace_with(norm_text(text))

        # ---------- 9) 保留强保留的祖先 ----------
        def mark_ancestors(el, max_depth=6):
            depth = 0
            while el and getattr(el, "parent", None) is not None and depth < max_depth:
                el = el.parent
                if getattr(el, "name", None) in {"html","body","header","nav","main","footer",
                                                "section","article","aside","div"}:
                    el.attrs["data-keep-ctx"] = "1"
                depth += 1

        for el in soup.find_all(attrs={"data-keep": "1"}):
            mark_ancestors(el)

        for el in soup.find_all(["h1","h2","h3"]):
            el.attrs["data-keep-head"] = "1"

        # ---------- 10) 删除无信息空容器（表单控件永不删） ----------
        important_child_tags = {"img", "a", "button", "input", "select", "textarea", "table", "ul", "ol", "form"}
        form_control_tags = {"input", "select", "textarea", "button"}

        def is_meaningful_container(el) -> bool:
            if el.has_attr("data-keep") or el.has_attr("data-keep-ctx") or el.has_attr("data-keep-head"):
                return True
            if el.name in form_control_tags:
                return True  # 表单控件无条件保留
            if el.find(list(important_child_tags)) is not None:
                return True
            text = el.get_text(" ", strip=True)
            if text and len(text) >= 2 and el.name in {"p","li","th","td","span","div"}:
                return True
            if has_any_attr(el, {"id","href","src","alt","role","aria-label","action","method",
                                "type","name","value","placeholder","for"}):
                return True
            return False

        changed = True
        while changed:
            changed = False
            for el in list(soup.find_all(True)):
                if el.name in form_control_tags:
                    continue  # 永不删除 input/select/textarea/button
                if el.name == "img":
                    if el.get("alt") or el.get("src"):
                        continue
                # 空节点快速删除（考虑更多有用属性）
                if (not el.contents and not el.get_text(strip=True) and
                    not has_any_attr(el, {"id","href","src","alt","type","name","value","placeholder","for"})):
                    el.decompose()
                    changed = True
                    continue
                if el.name not in {"html","body"} and not is_meaningful_container(el):
                    el.decompose()
                    changed = True

        # ---------- 11) 去掉内部标记 & 美化输出（保留换行与缩进） ----------
        for el in soup.find_all(True):
            for k in ("data-keep", "data-keep-ctx", "data-keep-head"):
                if el.has_attr(k):
                    del el.attrs[k]

        # 用 prettify 而不是正则压缩，保留层次和换行
        return soup.prettify(formatter="minimal")






# 待优化
# 尤其是iframe的扩展，不知道DVWA HIGH的sql是不是就属于这种情况？

# 很棒的一版！我按「潜在问题/改进点 → 目前能处理的类型 → 明确处理不了/覆盖不全的类型」三块给你梳理。

# ---

# # 1) 潜在问题 & 快速改进建议

# * **属性未做转义（高优）**
#   你直接把 `placeholder/value/label...` 等塞进属性字符串里（如 `value="..."`）。一旦包含引号/换行/尖括号，摘要就会被“戳破”。
#   **建议**：用 `html.escape()`（`quote=True`）统一转义 attribute；对文本节点保留原样或也做最小转义。

# * **`option.disabled` 的判断不准确（中优）**
#   你用 `opt.is_enabled()` 标记 `disabled`。但当 `<select disabled>` 时，所有 option 都会“看起来 disabled”。
#   **建议**：对 option 同时检查 `opt.get_attribute('disabled') is not None`。`select` 的 `disabled` 仍然保留在 `<select>` 上。

# * **“unique” 未去重（中优）**
#   `get_unique_clickables()` 名称与实现不符；可能重复记录同一元素。
#   **建议**：按 `WebElement.id` 或 `(tag, normalized_text, href, rect)` 去重。

# * **点击元素信息偏少（中优）**
#   只输出 `<tag>内文</tag>`，没有 `href`/`type`/`aria-label` 等，容易混淆同名按钮/链接。
#   **建议**：

#   * `<a>`：补 `href`（必要时截断）、`target`；
#   * `<button>`：补 `type/name/value`；
#   * 若 `inner_text` 为空，回退到 `aria-label/title/img@alt` 组合。

# * **遮挡/可见性判断较弱（中优）**
#   仅 `scrollIntoView + is_displayed()`。无法识别被其他元素覆盖、`pointer-events:none` 等。且对每个元素都滚动，性能抖动。
#   **建议**：

#   * 先用 `getBoundingClientRect()` 快速判范围，不滚动；
#   * 取元素中心点，用 `document.elementFromPoint` 做命中校验；
#   * 检查 `pointer-events`；必要时才滚动。

# * **Label 查找代价偏高（低优）**
#   `//label[@for=...]` 是全局搜索；每个字段都跑一次可能比较重。
#   **建议**：优先在表单作用域内找，或把 `id→label` 建索引（先扫一遍 label 再查）。

# * **未处理/弱处理的输入属性（低优）**
#   `readonly/maxlength/minlength/min/max/step/autocomplete/pattern/accept/multiple` 等都很有用，当前未输出。
#   **建议**：逐步补充最关键的几项（如 `readonly/maxlength/min/max/accept`）。

# * **超长 select**
#   你用 `getattr(self, 'MAX_OPTIONS_TO_LIST', 200)` 有默认值，但类里没显式常量。
#   **建议**：在类级/实例级显式定义 `MAX_OPTIONS_TO_LIST = 200`，便于配置与阅读。

# * **异常处理过于宽泛**
#   `is_obscured_or_invisible` 里 `except Exception: return True` 会把偶发脚本错误当成“不可见”。
#   **建议**：只捕获 `WebDriverException/StaleElementReferenceException` 等可预期异常；其它异常记录日志再继续。

# * **未移除无用 import**
#   `time`/`re` 未使用，可去掉。

# * **字符串 DSL 的 HTML 规范性**
#   你有意保留 `<input>... </input>` 的闭合方式作为 DSL（不是合法 HTML），这没问题，但建议一致性：

#   * 既然 DSL，不必完全遵循 HTML，自定规范即可；
#   * 或者把 `<input/>` 改为自闭合，减少误解。

# ---

# # 2) 当前能稳定覆盖/表达的类型

# * **可点击元素**

#   * `a`、`button`、`input[type=submit|button]`、带内联 `onclick` 的元素。
#   * 可见性有基本过滤（`is_displayed()`）。
#   * **用途**：能给上层 LLM 一个“这个页面能点哪些东西”的粗略地图。

# * **表单与字段**

#   * `form`（`name/action/method`）；
#   * `input`（含 `checkbox/radio/file/...`，隐藏 `hidden` 被过滤），输出 `type/name/placeholder/value/required/disabled/checked`；
#   * `select`（单/多选），**已能完整列出 `option`**（value/文本/selected/disabled + `optgroup`）；
#   * `textarea`（`name/placeholder/value/required/disabled`）。
#   * **Label 关联**：for 绑定、包裹 label、`aria-label`、`aria-labelledby`、`title`（优先级合理）。

# * **Action 映射**

#   * 对 clickables、表单和每个字段都会 `add_action`，类型细分到 `input:<type>`，便于后续执行具体操作。

# ---

# # 3) 目前处理不了/覆盖不全的东西（仅分析，不必现在实现）

# * **Shadow DOM / Web Components**
#   标准 `find_elements` 不会穿透 shadow root；大量现代组件（尤其是设计系统）在 shadow DOM 里。需要显式遍历 `shadowRoot`.

# * **多层 iframe**
#   你没做 `switch_to.frame` 递归。广告、支付、reCAPTCHA、社交登录等常在 iframe 里。

# * **非内联事件的“可交互元素”**
#   现代前端多用 `addEventListener` 或框架事件（React/Vue/Svelte）。你只抓 `[onclick]`，会漏掉一大批“看起来像按钮的 div/span”。
#   可能的补充线索：`role="button"`, `tabindex>=0`, `cursor:pointer`, `key listeners` 等。

# * **`contenteditable` 可编辑区域**
#   富文本编辑器（Quill/ProseMirror/Slate）通常是 `contenteditable` 的 `div`，不在 `input/textarea` 范畴。

# * **复杂/自绘控件**

#   * 日期/时间选择器：实际输入发生在弹层或隐藏 input；
#   * 自定义下拉选择（非 `<select>`，而是 div 组合）；
#   * Canvas/SVG 上的交互；
#   * 滑块/拖拽区域；
#   * Portal（React Portals）导致 DOM 嵌套不在 form 下。

# * **动态/渐显字段**
#   需要滚动/点击/等待后才出现的字段（懒加载、折叠面板、Tabs、向导式表单）。当前是一次性静态抓取。

# * **校验/约束元信息**
#   `pattern/min/max/step/maxlength/autocomplete/inputmode` 等未采集，影响“如何正确填写”的推理。

# * **可见性/遮挡的严格判定**
#   未做 `elementFromPoint` 等命中测试；对浮层覆盖、模态遮挡、z-index 等识别不足。

# * **多选/单选的“同名分组语义”**
#   你能标记 `checked`，但没有把 radio/checkbox 以同 `name` 分组成一项，LLM 要理解“这个问题有多个选项”时会稍费力。

# * **`datalist`**
#   `<input list="...">` 的候选项没抽取。

# ---

# # 4) 几个“性价比高”的后续优化（可分批做）

# 1. **转义与长度控制**：加 `html.escape()`，并对 `abstract_page` 设置全局上限（或分块输出），避免超长页面撑爆内存/上下文。
# 2. **点击元素增强**：为 `<a>/<button>` 增补关键属性与文本回退（`aria-label/title/img@alt`），并去重。
# 3. **选项禁用判定修正**：option 同时检查 `get_attribute('disabled')`。
# 4. **可见性判定升级（轻量版）**：先不滚动，取 `getBoundingClientRect()` 判断是否在视窗内；必要时才滚动；有余力再加 `elementFromPoint`。
# 5. **表单校验属性**：补 `readonly/maxlength/min/max/step/pattern/accept/multiple`（输入正确率会明显提升）。
# 6. **分组摘要**：把同 `name` 的 radio/checkbox 归为一组，列出每个选项及其 label/checked。
# 7. **超长 select 的渐进展开**：超过阈值只列前 N 项 + “…more” 提示（你已经有上限，补一个总开关即可）。

# ---

# 如果你愿意，我可以在不改你 DSL 结构的前提下，给你一版“最小改动”的 patch：

# * 统一 attribute 转义、
# * `option.disabled` 修正、
# * `<a>/<button>` 属性补全 + 文本回退、
# * radio/checkbox 分组的摘要输出（可选）。
#   直接替换几个函数就能用。

