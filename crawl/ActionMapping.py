class ActionsMapping:
    def __init__(self, use_improved_strategy=False):
        """
        Initialize action mapping

        Args:
            use_improved_strategy: Whether to use improved locator strategy (fixes normalization issues with href and other URL attributes)
        """
        self.use_improved_strategy = use_improved_strategy
        self.mapping = {}  # {id: {'locator': str, 'type': str, 'native_attrs': dict}}
        self.id_counter = 0
        self.driver = None
        self._locator_counts = {}  # Record usage count for each locator, for generating unique indices

        # If improved strategy enabled, initialize new implementation
        self._improved_impl = None
        if use_improved_strategy:
            try:
                from .locator_strategy import ImprovedActionsMapping
                self._improved_impl = ImprovedActionsMapping()
                print("[ActionMapping] Using improved locator strategy")
            except ImportError as e:
                print(f"[ActionMapping] Warning: cannot import improved strategy, falling back to old strategy: {e}")
                self.use_improved_strategy = False

    def set_driver(self, driver):
        self.driver = driver
        if self._improved_impl:
            self._improved_impl.set_driver(driver)

    def add_action(self, elem, elem_type):
        """
        Add action mapping - generate locator using native attributes

        Priority:
        1. name attribute (commonly used for form elements)
        2. id attribute
        3. type + other attribute combinations
        4. xpath (fallback)
        """
        # If improved strategy is enabled, use new implementation
        if self._improved_impl:
            action_id = self._improved_impl.add_action(elem, elem_type)
            # Sync mapping to old format (for compatibility)
            improved_info = self._improved_impl.mapping[action_id]
            self.mapping[action_id] = {
                'locator': improved_info['primary'],
                'type': improved_info['type'],
                'native_attrs': improved_info.get('native_attrs', {}),
                '_improved_info': improved_info  # Save complete info
            }
            self.id_counter = self._improved_impl.id_counter
            return action_id

        # Use old strategy
        # Generate native attribute-based locator
        locator, native_attrs = self._generate_native_locator(elem, elem_type)

        self.mapping[self.id_counter] = {
            'locator': locator,
            'type': elem_type,
            'native_attrs': native_attrs  # Save native attributes for cache restoration
        }
        self.id_counter += 1
        return self.id_counter - 1

    def _generate_native_locator(self, elem, elem_type):
        """
        Generate native attribute-based CSS selector

        Returns:
            (locator: str, native_attrs: dict)
        """
        try:
            tag = elem.tag_name.lower()
            native_attrs = {}

            # 1. Prefer name attribute (most stable for form elements)
            name = elem.get_attribute('name')
            if name:
                native_attrs['name'] = name
                locator = f"{tag}[name='{name}']"
                # If duplicates exist, add index
                locator = self._make_unique_locator(locator)
                return locator, native_attrs

            # 2. Use id attribute
            elem_id = elem.get_attribute('id')
            if elem_id:
                native_attrs['id'] = elem_id
                return f"#{elem_id}", native_attrs

            # 3. Form elements: use type attribute
            if tag == 'input':
                input_type = elem.get_attribute('type') or 'text'
                native_attrs['type'] = input_type
                locator = f"input[type='{input_type}']"
                # Add other stable attributes
                placeholder = elem.get_attribute('placeholder')
                if placeholder:
                    native_attrs['placeholder'] = placeholder
                    locator += f"[placeholder='{placeholder}']"
                else:
                    locator = self._make_unique_locator(locator)
                return locator, native_attrs

            # 4. Links: use href
            if tag == 'a':
                href = elem.get_attribute('href')
                if href:
                    native_attrs['href'] = href
                    return f"a[href='{href}']", native_attrs
                # Use text content
                text = elem.text.strip()[:30] if elem.text else None
                if text:
                    native_attrs['text'] = text
                    # Escape special characters
                    text_escaped = text.replace("'", "\\'")
                    xpath = f"//a[normalize-space(text())='{text_escaped}']"
                    return xpath, native_attrs

            # 5. Buttons: use text content or aria-label
            if tag == 'button' or (tag == 'input' and elem.get_attribute('type') in ['submit', 'button']):
                text = elem.text.strip()[:30] if elem.text else None
                aria_label = elem.get_attribute('aria-label')

                if aria_label:
                    native_attrs['aria-label'] = aria_label
                    locator = f"{tag}[aria-label='{aria_label}']"
                    return self._make_unique_locator(locator), native_attrs

                if text:
                    native_attrs['text'] = text
                    text_escaped = text.replace("'", "\\'")
                    xpath = f"//{tag}[normalize-space(text())='{text_escaped}']"
                    return self._make_index_xpath(xpath), native_attrs

            # 6. Use class attribute (Material UI, etc.)
            cls = elem.get_attribute('class')
            if cls:
                classes = cls.split()
                # Filter out stable classes (not dynamically generated)
                stable_classes = [c for c in classes if not any(x in c for x in ['ng-', 'cdk-', '_ngcontent'])]
                if stable_classes:
                    native_attrs['class'] = ' '.join(stable_classes[:2])  # Save at most 2 classes
                    locator = f"{tag}.{'.'.join(stable_classes[:2])}"
                    return self._make_unique_locator(locator), native_attrs

            # 7. Fallback: generate xpath (position-based)
            xpath = self._generate_xpath(elem)
            native_attrs['xpath'] = xpath
            return xpath, native_attrs

        except Exception as e:
            # Final fallback
            xpath = self._generate_simple_xpath(elem)
            return xpath, {'xpath': xpath}

    def _make_unique_locator(self, base_locator):
        """Add index to duplicate locators to make them unique"""
        if base_locator not in self._locator_counts:
            self._locator_counts[base_locator] = 0
            return base_locator
        else:
            self._locator_counts[base_locator] += 1
            index = self._locator_counts[base_locator]
            # CSS selectors don't support indexing, convert to xpath
            if base_locator.startswith('//'):
                # Already xpath
                return f"({base_locator})[{index + 1}]"
            else:
                # Convert to xpath and add index
                # Simplified handling: use nth-of-type directly
                return f"{base_locator}:nth-of-type({index + 1})"

    def _make_index_xpath(self, xpath):
        """Add index to xpath"""
        if xpath not in self._locator_counts:
            self._locator_counts[xpath] = 0
            return xpath
        else:
            self._locator_counts[xpath] += 1
            index = self._locator_counts[xpath]
            return f"({xpath})[{index + 1}]"

    def _generate_xpath(self, elem):
        """Generate position-based xpath"""
        try:
            # Use Selenium's built-in method to generate xpath
            xpath = self.driver.execute_script("""
                function getXPath(element) {
                    if (element.id !== '')
                        return '//*[@id="' + element.id + '"]';
                    if (element === document.body)
                        return '/html/body';

                    var ix = 0;
                    var siblings = element.parentNode.childNodes;
                    for (var i = 0; i < siblings.length; i++) {
                        var sibling = siblings[i];
                        if (sibling === element)
                            return getXPath(element.parentNode) + '/' + element.tagName.toLowerCase() + '[' + (ix + 1) + ']';
                        if (sibling.nodeType === 1 && sibling.tagName === element.tagName)
                            ix++;
                    }
                }
                return getXPath(arguments[0]);
            """, elem)
            return xpath
        except:
            return self._generate_simple_xpath(elem)

    def _generate_simple_xpath(self, elem):
        """Generate simple xpath"""
        try:
            tag = elem.tag_name.lower()
            return f"//{tag}"
        except:
            return "//body"

    def get_action_elem(self, id):
        """Get element by action_id"""
        # If improved strategy enabled, use new implementation (supports fallback)
        if self._improved_impl:
            return self._improved_impl.get_action_elem(id)

        # Use old strategy
        if id not in self.mapping:
            return None
        locator = self.mapping[id]['locator']
        try:
            from selenium.webdriver.common.by import By
            # Determine if it's a CSS selector or XPath
            if locator.startswith('//') or locator.startswith('(//'):
                return self.driver.find_element(By.XPATH, locator)
            else:
                return self.driver.find_element(By.CSS_SELECTOR, locator)
        except:
            return None

    def clear(self):
        """Clear all mappings"""
        self.mapping = {}
        self.id_counter = 0
        self._locator_counts = {}
        if self._improved_impl:
            self._improved_impl.clear()

    def get_action_type(self, id):
        """Get action type"""
        return self.mapping.get(id, {}).get('type')

    def set_mapping(self, id, locator_or_info, elem_type=None, native_attrs=None):
        """
        Directly set mapping (for restoration from cache)

        Args:
            id: action_id
            locator_or_info: Can be a string locator (old format) or dict (new format)
            elem_type: Element type (needed for old format)
            native_attrs: Native attributes (optional for old format)
        """
        # Determine if new format or old format
        if isinstance(locator_or_info, dict):
            # New format: complete locators_info
            locators_info = locator_or_info
            if self._improved_impl:
                self._improved_impl.set_mapping(id, locators_info)
            # Sync to old format
            self.mapping[id] = {
                'locator': locators_info.get('primary', locators_info.get('locator')),
                'type': locators_info.get('type', elem_type),
                'native_attrs': locators_info.get('native_attrs', native_attrs or {}),
                '_improved_info': locators_info
            }
        else:
            # Old format: single locator string
            locator = locator_or_info
            self.mapping[id] = {
                'locator': locator,
                'type': elem_type,
                'native_attrs': native_attrs or {}
            }
            # If using improved strategy, try to convert to new format
            if self._improved_impl:
                # Create minimal new format
                locators_info = {
                    'primary': locator,
                    'secondary': [],
                    'fallback': locator,
                    'type': elem_type,
                    'uniqueness_score': 50,
                    'native_attrs': native_attrs or {}
                }
                self._improved_impl.set_mapping(id, locators_info)

        if id >= self.id_counter:
            self.id_counter = id + 1
