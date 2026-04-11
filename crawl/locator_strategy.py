"""
Improved element locator strategy module

Solved issues:
1. Selenium's get_attribute() returns normalized URLs, causing CSS selectors to not match DOM raw values
2. Duplicate elements cannot be correctly distinguished and indexed
3. Single locator is not robust enough, lacking fallback mechanism
4. Cached locators may become invalid due to DOM changes

Architecture:
- AttributeHelper: Unified attribute access interface
- UniquenessAnalyzer: Evaluate element uniqueness
- LocatorGenerator: Generate multi-level locators
- DuplicateElementHandler: Handle duplicate elements
- ResilientElementFinder: Fault-tolerant element finding
- ImprovedActionsMapping: Integrates all functionality
"""

from selenium.webdriver.common.by import By
from selenium.common.exceptions import NoSuchElementException, StaleElementReferenceException


class AttributeHelper:
    """Unified attribute access tool, distinguishing raw and normalized values"""

    # List of attributes that need DOM raw values (these attributes are auto-normalized by Selenium)
    RAW_VALUE_ATTRS = {
        'href', 'src', 'action', 'formaction',
        'poster', 'data', 'cite', 'background'
    }

    @staticmethod
    def get_attr_for_locator(driver, elem, attr_name):
        """
        Get attribute value for generating locators (DOM raw value)

        Improvement: only returns attribute values that actually exist in the DOM
        - For URL-type attributes, returns raw value instead of normalized absolute URL
        - For other attributes, verifies whether they truly exist in the DOM
        - Returns None if attribute doesn't exist (avoids using Selenium's inferred values)

        Args:
            driver: Selenium WebDriver
            elem: WebElement
            attr_name: Attribute name

        Returns:
            str or None: True DOM value of the attribute, None if not present
        """
        try:
            # Use JavaScript to directly check if DOM attribute exists
            result = driver.execute_script("""
                var elem = arguments[0];
                var attrName = arguments[1];

                // Check if attribute truly exists
                if (!elem.hasAttribute(attrName)) {
                    return null;
                }

                // Return true DOM attribute value
                return elem.getAttribute(attrName);
            """, elem, attr_name)

            return result
        except:
            # Fallback when JavaScript execution fails
            # Still avoid using inferred values
            try:
                selenium_value = elem.get_attribute(attr_name)
                # For certain attributes known to be inferred, returning None is safer
                if attr_name in ['type', 'value'] and selenium_value:
                    # Try again with JS to verify
                    has_attr = driver.execute_script(
                        "return arguments[0].hasAttribute(arguments[1]);",
                        elem, attr_name
                    )
                    if not has_attr:
                        return None
                return selenium_value
            except:
                return None

    @staticmethod
    def get_all_meaningful_attrs(driver, elem):
        """
        Get all meaningful attributes of an element (for uniqueness analysis)

        Returns:
            dict: {attr_name: value}
        """
        # Priority attribute list
        priority_attrs = [
            'id', 'name', 'data-testid', 'data-test', 'data-cy',
            'data-order-id', 'data-id', 'data-key', 'data-value',
            'aria-label', 'aria-labelledby', 'aria-describedby',
            'title', 'alt', 'value', 'placeholder',
            'type', 'role', 'href', 'src', 'action',
            'class', 'for'
        ]

        result = {}
        for attr in priority_attrs:
            val = AttributeHelper.get_attr_for_locator(driver, elem, attr)
            if val and val.strip():
                result[attr] = val

        return result


class UniquenessAnalyzer:
    """Analyze element uniqueness, score and select best locator strategy"""

    # Attribute uniqueness weights (0-100)
    ATTR_WEIGHTS = {
        'id': 100,                    # id should be unique
        'name': 80,                   # name is usually unique (form elements)
        'data-testid': 95,            # Test IDs are usually unique
        'data-test': 95,
        'data-cy': 95,
        'data-order-id': 90,          # Business IDs are usually unique
        'data-id': 85,
        'data-key': 85,
        'aria-label': 70,             # May repeat but has discriminating power
        'placeholder': 60,
        'href': 50,                   # Links may repeat
        'type': 30,                   # Types have high repetition
        'class': 20,                  # Classes have very high repetition
        'role': 15,
    }

    @staticmethod
    def calculate_uniqueness_score(attrs):
        """
        Calculate uniqueness score for attribute combination

        Returns:
            int: Score from 0-100, higher is more unique
        """
        if not attrs:
            return 0

        # Single high-weight attribute
        max_weight = max([
            UniquenessAnalyzer.ATTR_WEIGHTS.get(k, 0)
            for k in attrs.keys()
        ], default=0)

        # Bonus for combining attributes
        combo_bonus = min(len(attrs) * 5, 20)

        return min(max_weight + combo_bonus, 100)

    @staticmethod
    def select_best_attr_combination(all_attrs):
        """
        Select best locator attribute combination from all attributes

        Returns:
            list: [(attr_name, value), ...] sorted by priority
        """
        if not all_attrs:
            return []

        # Sort by weight
        sorted_attrs = sorted(
            all_attrs.items(),
            key=lambda x: UniquenessAnalyzer.ATTR_WEIGHTS.get(x[0], 0),
            reverse=True
        )

        result = []
        current_score = 0

        for attr, value in sorted_attrs:
            weight = UniquenessAnalyzer.ATTR_WEIGHTS.get(attr, 0)

            # If we already have a high-weight attribute, no need to add low-weight ones
            if current_score >= 80 and weight < 50:
                break

            result.append((attr, value))
            current_score = max(current_score, weight)

            # Stop when ideal score reached
            if current_score >= 90:
                break

        return result


class LocatorGenerator:
    """Generate multi-level locator strategies"""

    @staticmethod
    def generate_locators(driver, elem, elem_type):
        """
        Generate multiple candidate locators for an element

        Improvements:
        - Only use attributes that truly exist in the DOM (filter out Selenium inferred values)
        - Use independent class selectors instead of exact class matching
        - Generate more robust XPath
        - Use contains() for text matching instead of exact matching

        Returns:
            {
                'primary': str,           # Primary locator (most reliable)
                'secondary': list[str],   # Backup locators
                'fallback': str,          # Final fallback
                'uniqueness_score': int,  # Uniqueness score
                'native_attrs': dict      # Raw attributes (only those truly present)
            }
        """
        tag = elem.tag_name.lower()

        # Get all meaningful attributes (inferred values filtered out)
        all_attrs = AttributeHelper.get_all_meaningful_attrs(driver, elem)

        # Select best attribute combination
        best_attrs = UniquenessAnalyzer.select_best_attr_combination(all_attrs)

        # Calculate uniqueness score
        score = UniquenessAnalyzer.calculate_uniqueness_score(dict(best_attrs))

        primary = None
        secondary = []

        # === Strategy 1: Use single high-weight attribute ===
        for attr, value in best_attrs:
            weight = UniquenessAnalyzer.ATTR_WEIGHTS.get(attr, 0)

            if weight >= 80:  # High confidence attribute
                if attr == 'id':
                    primary = f"#{value}"
                else:
                    primary = f"{tag}[{attr}='{LocatorGenerator._escape_value(value)}']"
                break

        # === Strategy 2: Use attribute combination ===
        if not primary and len(best_attrs) >= 2:
            # Combine first 2-3 attributes
            attr_parts = [
                f"[{attr}='{LocatorGenerator._escape_value(value)}']"
                for attr, value in best_attrs[:3]
            ]
            primary = f"{tag}{''.join(attr_parts)}"

        # === Strategy 3: Single medium-weight attribute ===
        if not primary and best_attrs:
            attr, value = best_attrs[0]
            primary = f"{tag}[{attr}='{LocatorGenerator._escape_value(value)}']"

        # === Backup strategy: Use stable class combination (independent selectors) ===
        if 'class' in all_attrs:
            classes = all_attrs['class'].split()
            # Filter unstable classes (dynamically generated, state-related)
            stable_classes = [c for c in classes if not any(
                x in c for x in ['ng-', 'cdk-', '_ngcontent', 'active', 'focus', 'hover', 'mat-mdc-']
            )]
            # Prefer semantic classes (e.g. btn-basket)
            semantic_classes = [c for c in stable_classes if 'btn-' in c or 'button-' in c]

            # If semantic classes found, prefer them
            if semantic_classes:
                # Use independent class selector: button.btn-basket
                secondary.append(f"{tag}.{'.'.join(semantic_classes[:2])}")
            elif stable_classes and len(stable_classes) <= 3:
                # Use at most 2 stable classes
                secondary.append(f"{tag}.{'.'.join(stable_classes[:2])}")

        # === Backup strategy: Text content (using contains) ===
        try:
            text = elem.text.strip()[:50] if elem.text else None
            if text and len(text) > 2:
                text_escaped = LocatorGenerator._escape_value(text)
                if tag in ['button', 'a']:
                    # Use contains() instead of exact matching, more robust
                    secondary.append(f"//{tag}[contains(., '{text_escaped}')]")
        except:
            pass

        # === Fallback: Generate unique XPath ===
        fallback = LocatorGenerator._generate_unique_xpath(driver, elem)

        # If no primary locator, use fallback
        if not primary:
            primary = fallback
            fallback = LocatorGenerator._generate_absolute_xpath(driver, elem)

        return {
            'primary': primary,
            'secondary': secondary,
            'fallback': fallback,
            'uniqueness_score': score,
            'native_attrs': all_attrs
        }

    @staticmethod
    def _escape_value(value):
        """Escape special characters in attribute values"""
        if not value:
            return ''
        return str(value).replace("'", "\\'").replace('"', '\\"')

    @staticmethod
    def _generate_unique_xpath(driver, elem):
        """
        Generate relatively unique XPath (using attributes and position)

        Improvements:
        - Prefer element's real attributes (aria-label, name, etc.)
        - If an ancestor has an ID, generate relative path
        - Ensure generated XPath syntax is correct

        Strategy: find nearest ancestor with id, then generate relative path from it
        """
        try:
            return driver.execute_script("""
                function getUniqueXPath(element) {
                    // Priority strategy 1: if element has a unique identifier attribute
                    if (element.id) {
                        return '//*[@id="' + element.id + '"]';
                    }

                    // Priority strategy 2: use aria-label (if exists and short)
                    const ariaLabel = element.getAttribute('aria-label');
                    if (ariaLabel && ariaLabel.length < 50 && ariaLabel.length > 0) {
                        const tagName = element.tagName.toLowerCase();
                        return '//' + tagName + '[@aria-label="' + ariaLabel + '"]';
                    }

                    // Priority strategy 3: use name attribute
                    const name = element.getAttribute('name');
                    if (name && name.length > 0) {
                        const tagName = element.tagName.toLowerCase();
                        return '//' + tagName + '[@name="' + name + '"]';
                    }

                    // Search upward for ancestor with ID
                    let ancestor = element.parentElement;
                    while (ancestor && ancestor !== document.body) {
                        if (ancestor.id) {
                            // Found it, generate relative path
                            const relativePath = getRelativePath(element, ancestor);
                            return '//*[@id="' + ancestor.id + '"]' + relativePath;
                        }
                        ancestor = ancestor.parentElement;
                    }

                    // No ID ancestor found, use positional index
                    return getPositionalXPath(element);
                }

                function getRelativePath(element, ancestor) {
                    const path = [];
                    let current = element;

                    while (current && current !== ancestor) {
                        const index = getElementIndex(current);
                        path.unshift(current.tagName.toLowerCase() + '[' + index + ']');
                        current = current.parentElement;
                    }

                    return '/' + path.join('/');
                }

                function getElementIndex(element) {
                    const siblings = Array.from(element.parentElement.children);
                    const sameTagSiblings = siblings.filter(s => s.tagName === element.tagName);
                    return sameTagSiblings.indexOf(element) + 1;
                }

                function getPositionalXPath(element) {
                    const path = [];
                    let current = element;
                    let depth = 0;
                    const maxDepth = 10; // Limit depth to avoid overly long XPath

                    while (current && current.tagName !== 'HTML' && depth < maxDepth) {
                        const index = getElementIndex(current);
                        path.unshift(current.tagName.toLowerCase() + '[' + index + ']');
                        current = current.parentElement;
                        depth++;
                    }

                    // Ensure valid XPath is returned (even if truncated)
                    return '//' + path.join('/');
                }

                return getUniqueXPath(arguments[0]);
            """, elem)
        except:
            return LocatorGenerator._generate_absolute_xpath(driver, elem)

    @staticmethod
    def _generate_absolute_xpath(driver, elem):
        """Generate absolute positional XPath (last fallback)"""
        try:
            return driver.execute_script("""
                function getAbsoluteXPath(element) {
                    if (element === document.body) {
                        return '/html/body';
                    }

                    const path = [];
                    let current = element;

                    while (current && current !== document.documentElement) {
                        let index = 1;
                        let sibling = current.previousSibling;

                        while (sibling) {
                            if (sibling.nodeType === 1 && sibling.tagName === current.tagName) {
                                index++;
                            }
                            sibling = sibling.previousSibling;
                        }

                        const tagName = current.tagName.toLowerCase();
                        path.unshift(tagName + '[' + index + ']');
                        current = current.parentElement;
                    }

                    return '/' + path.join('/');
                }

                return getAbsoluteXPath(arguments[0]);
            """, elem)
        except:
            return "//body"


class DuplicateElementHandler:
    """Handle indexing for duplicate elements"""

    def __init__(self):
        self._seen_locators = {}  # {locator: count}
        self._element_contexts = {}  # {action_id: context_info}

    def register_element(self, action_id, locators_info, context_info):
        """
        Check for duplicates when registering an element

        Args:
            action_id: Element ID
            locators_info: Result from LocatorGenerator
            context_info: Context info (parent element, siblings, etc.)

        Returns:
            Corrected locators_info
        """
        primary = locators_info['primary']

        # Check if this locator has been seen before
        if primary not in self._seen_locators:
            # First time seeing it, register directly
            self._seen_locators[primary] = 1
            self._element_contexts[action_id] = context_info
            return locators_info

        # Already seen, need to add index
        self._seen_locators[primary] += 1
        index = self._seen_locators[primary]

        # Modify primary locator, add positional index
        indexed_primary = self._add_positional_index(primary, index)

        locators_info_copy = locators_info.copy()
        locators_info_copy['primary'] = indexed_primary
        locators_info_copy['is_duplicate'] = True
        locators_info_copy['duplicate_index'] = index

        self._element_contexts[action_id] = context_info

        return locators_info_copy

    @staticmethod
    def _add_positional_index(locator, index):
        """
        Add positional index to locator

        CSS: a[href='#'] -> (//a[@href='#'])[2]
        XPath: //a[@href='#'] -> (//a[@href='#'])[2]
        """
        if locator.startswith('//') or locator.startswith('(//'):
            # Already XPath
            if locator.startswith('('):
                # Already has parentheses, remove old index
                base = locator.split(')[')[0] + ')'
            else:
                base = f"({locator})"
            return f"{base}[{index}]"
        else:
            # CSS selector, convert to XPath
            xpath = DuplicateElementHandler._css_to_xpath(locator)
            return f"({xpath})[{index}]"

    @staticmethod
    def _css_to_xpath(css):
        """Simple CSS to XPath conversion"""
        # #id -> //*[@id='id']
        if css.startswith('#'):
            return f"//*[@id='{css[1:]}']"

        # tag[attr='value'] -> //tag[@attr='value']
        if '[' in css and ']' in css:
            # Simple parse: button[name='submit']
            parts = css.split('[')
            tag = parts[0] if parts[0] else '*'
            attrs = '['.join(parts[1:]).rstrip(']')

            # Handle multiple attributes
            attr_parts = []
            for attr_str in attrs.split(']['):
                if '=' in attr_str:
                    attr_name, attr_value = attr_str.split('=', 1)
                    attr_value = attr_value.strip("'\"")
                    attr_parts.append(f"@{attr_name}='{attr_value}'")

            if attr_parts:
                attr_xpath = ' and '.join(attr_parts)
                return f"//{tag}[{attr_xpath}]"
            else:
                return f"//{tag}"

        # tag.class -> //tag[contains(@class, 'class')]
        if '.' in css:
            parts = css.split('.')
            tag = parts[0] if parts[0] else '*'
            classes = parts[1:]

            class_conditions = [
                f"contains(concat(' ', normalize-space(@class), ' '), ' {c} ')"
                for c in classes
            ]
            if class_conditions:
                class_xpath = ' and '.join(class_conditions)
                return f"//{tag}[{class_xpath}]"
            else:
                return f"//{tag}"

        # Simple tag
        return f"//{css}"


class ResilientElementFinder:
    """Element finder with fallback and self-healing support"""

    def __init__(self, driver):
        self.driver = driver
        self._cache = {}  # {action_id: last_successful_locator}

    def find_element(self, action_id, locators_info):
        """
        Find element using multi-level fallback strategy

        Args:
            action_id: Element ID
            locators_info: {
                'primary': str,
                'secondary': list[str],
                'fallback': str,
                'uniqueness_score': int
            }

        Returns:
            WebElement or None
        """
        # Strategy 1: Try primary locator
        elem = self._try_locator(locators_info['primary'])
        if elem:
            self._cache[action_id] = locators_info['primary']
            return elem

        # Strategy 2: Try cached successful locator (if different from primary)
        if action_id in self._cache:
            cached_locator = self._cache[action_id]
            if cached_locator != locators_info['primary']:
                elem = self._try_locator(cached_locator)
                if elem:
                    return elem

        # Strategy 3: Try secondary locators
        secondary_locators = locators_info.get('secondary', [])
        if secondary_locators:
            for secondary_locator in secondary_locators:
                elem = self._try_locator(secondary_locator)
                if elem:
                    self._cache[action_id] = secondary_locator
                    return elem

        # Strategy 4: Try fallback locator
        fallback = locators_info.get('fallback')
        if fallback:
            elem = self._try_locator(fallback)
            if elem:
                self._cache[action_id] = fallback
                return elem

        # Strategy 5: Try rescanning page (self-healing)
        if locators_info.get('uniqueness_score', 0) < 50:
            elem = self._attempt_self_healing(action_id, locators_info)
            if elem:
                return elem

        # All strategies failed - print diagnostic info
        print(f"\n[ResilientFinder] Cannot find element action_id={action_id}")
        print(f"  Primary locator: {locators_info['primary']}")
        print(f"  Secondary locator count: {len(secondary_locators)}")
        print(f"  Fallback: {locators_info.get('fallback', 'N/A')[:100]}")
        self._diagnose_failure(action_id, locators_info)

        return None

    def _try_locator(self, locator):
        """Try to find element using a single locator"""
        if not locator:
            return None

        try:
            if locator.startswith('//') or locator.startswith('(//'):
                return self.driver.find_element(By.XPATH, locator)
            else:
                return self.driver.find_element(By.CSS_SELECTOR, locator)
        except:
            return None

    def _diagnose_failure(self, action_id, locators_info):
        """
        Diagnose the reason for element finding failure

        Prints detailed diagnostic info including:
        1. Where Selenium looks for elements (live DOM, not page_source)
        2. Analysis of current page's DOM structure
        3. Whether similar elements exist
        4. Possible reasons for locator failure
        """
        print(f"\n[Diagnostic Info]")
        print(f"  Note: Selenium finds elements in the browser's [live DOM]")
        print(f"       Not in static HTML source (page_source)")
        print(f"       Live DOM is affected by JavaScript rendering, Angular and other frameworks")
        print(f"")

        native_attrs = locators_info.get('native_attrs', {})
        primary_locator = locators_info.get('primary', '')

        # 1. Print element's original attributes
        if native_attrs:
            print(f"[Element original attributes] (at extraction time)")
            for attr, value in list(native_attrs.items())[:10]:
                # Limit value length
                value_str = str(value)
                if len(value_str) > 100:
                    value_str = value_str[:100] + "..."
                print(f"  {attr} = {value_str}")
            print(f"")

        # 2. Try to find similar elements
        print(f"[Similar elements in DOM]")
        similar_found = False

        # Try to find by tag
        if native_attrs:
            try:
                # Get tag (infer from primary locator)
                tag = self._extract_tag_from_locator(primary_locator)
                if tag:
                    elements = self.driver.find_elements(By.TAG_NAME, tag)
                    print(f"  Found {len(elements)} <{tag}> elements")
                    similar_found = True

                    # Try to find elements with similar class
                    if 'class' in native_attrs:
                        target_classes = set(native_attrs['class'].split())
                        print(f"  Target classes: {target_classes}")

                        for i, elem in enumerate(elements[:5]):  # Only check first 5
                            try:
                                elem_classes = set(elem.get_attribute('class').split())
                                overlap = target_classes & elem_classes
                                if overlap:
                                    print(f"    Element {i+1}: class overlap {len(overlap)}/{len(target_classes)}")
                                    print(f"            Overlapping classes: {overlap}")
                            except:
                                continue
            except Exception as e:
                print(f"  Error finding similar elements: {e}")

        if not similar_found:
            print(f"  Unable to find similar elements")
        print(f"")

        # 3. Analyze possible failure reasons
        print(f"[Possible failure reasons]")

        # Check for dynamic classes
        if 'class' in native_attrs:
            classes = native_attrs['class'].split()
            dynamic_classes = [c for c in classes if any(
                keyword in c for keyword in ['ng-', 'cdk-', '_ngcontent', 'mat-', 'active', 'focus']
            )]
            if dynamic_classes:
                print(f"  Warning: Locator contains dynamic classes (these change at runtime):")
                for dc in dynamic_classes:
                    print(f"      - {dc}")
                print(f"      Suggestion: Use more stable attributes (id, data-*, etc.)")
                print(f"")

        # Check for XPath positional index
        if '[' in primary_locator and ']' in primary_locator:
            if primary_locator.count('[') > 1 or ('//' not in primary_locator):
                print(f"  Warning: Locator uses positional index")
                print(f"      Issue: DOM structure changes will invalidate the index")
                print(f"      Suggestion: Use attribute locating instead of positional index")
                print(f"")

        # Check for SPA (Single Page Application)
        current_url = self.driver.current_url
        if '#' in current_url:
            print(f"  Info: Single Page Application (SPA) routing detected")
            print(f"      Issue: SPA DOMs are frequently rebuilt, element references become stale")
            print(f"      Suggestion: Re-find elements before each operation")
            print(f"")

        # Check for iframes
        try:
            iframes = self.driver.find_elements(By.TAG_NAME, 'iframe')
            if iframes:
                print(f"  Warning: Page contains {len(iframes)} iframes")
                print(f"      Issue: Element may be inside an iframe, needs context switch")
                print(f"      Suggestion: Use driver.switch_to.frame()")
                print(f"")
        except:
            pass

        print(f"{'='*70}")

    def _extract_tag_from_locator(self, locator):
        """Extract tag name from locator"""
        if not locator:
            return None

        # CSS selector: button[...], div.class, a#id
        if not locator.startswith('//'):
            # Extract first non-symbol character sequence
            import re
            match = re.match(r'^([a-zA-Z][a-zA-Z0-9-]*)', locator)
            if match:
                return match.group(1)

        # XPath: //button[...], //div[@class=...]
        if locator.startswith('//'):
            parts = locator.split('[')[0].split('/')
            for part in parts:
                if part and part != '*':
                    return part

        return None

    def _attempt_self_healing(self, action_id, old_locators_info):
        """
        Self-healing: re-find based on element characteristics

        Approach: use saved native_attrs to regenerate locator
        """
        native_attrs = old_locators_info.get('native_attrs', {})
        if not native_attrs:
            return None

        print(f"  Attempting attribute-based re-finding: {list(native_attrs.keys())[:5]}")

        # Try finding with each attribute individually
        for attr, value in native_attrs.items():
            if attr in ['id', 'name', 'data-testid', 'data-test', 'data-order-id', 'data-id']:
                locator = f"//*[@{attr}='{value}']"
                elem = self._try_locator(locator)
                if elem:
                    print(f"  Self-healing succeeded using attribute: {attr}={value}")
                    self._cache[action_id] = locator
                    return elem

        return None


class ImprovedActionsMapping:
    """Improved action mapping class - uses multi-level locator strategy"""

    def __init__(self):
        self.mapping = {}  # {id: locators_info}
        self.id_counter = 0
        self.driver = None

        # Sub-modules
        self.duplicate_handler = DuplicateElementHandler()
        self.resilient_finder = None  # Initialized in set_driver

    def set_driver(self, driver):
        self.driver = driver
        self.resilient_finder = ResilientElementFinder(driver)

    def add_action(self, elem, elem_type):
        """
        Add action mapping - using improved multi-level locator strategy

        Returns:
            action_id: int
        """
        # Generate multiple candidate locators
        locators_info = LocatorGenerator.generate_locators(self.driver, elem, elem_type)

        # Add element type
        locators_info['type'] = elem_type

        # Extract context info (for duplicate element handling)
        context_info = self._extract_context(elem)

        # Handle duplicate elements
        locators_info = self.duplicate_handler.register_element(
            self.id_counter,
            locators_info,
            context_info
        )

        # Save mapping
        self.mapping[self.id_counter] = locators_info

        action_id = self.id_counter
        self.id_counter += 1

        # Debug output
        if locators_info.get('is_duplicate'):
            print(f"[ImprovedMapping] Element {action_id} is a duplicate, using indexed locating")
        # if locators_info.get('uniqueness_score', 0) < 60:
        #     print(f"[ImprovedMapping] Warning: element {action_id} has low uniqueness score: {locators_info['uniqueness_score']}")

        return action_id

    def _extract_context(self, elem):
        """Extract element's context info"""
        try:
            parent_tag = elem.find_element(By.XPATH, '..').tag_name.lower()
            parent_class = elem.find_element(By.XPATH, '..').get_attribute('class') or ''

            return {
                'parent_tag': parent_tag,
                'parent_class': parent_class[:50]
            }
        except:
            return {}

    def get_action_elem(self, action_id):
        """
        Get element by action_id - using fault-tolerant finding

        Returns:
            WebElement or None
        """
        if action_id not in self.mapping:
            print(f"[ImprovedMapping] Error: action_id={action_id} not in mapping")
            return None

        locators_info = self.mapping[action_id]

        # Use fault-tolerant finder
        return self.resilient_finder.find_element(action_id, locators_info)

    def clear(self):
        """Clear all mappings"""
        self.mapping = {}
        self.id_counter = 0
        self.duplicate_handler = DuplicateElementHandler()
        if self.resilient_finder:
            self.resilient_finder._cache.clear()

    def set_mapping(self, action_id, locator_or_info, elem_type=None, native_attrs=None):
        """
        Directly set mapping (for restoration from cache)

        Improvement: compatible with three formats
        1. New format: complete locators_info dict (contains 'primary' key)
        2. Old format: dict containing 'locator' key (needs conversion)
        3. String: single locator string (backward compatible)

        Args:
            action_id: int
            locator_or_info: str (single locator) or dict (locators_info structure)
            elem_type: str (optional, only needed when passing single locator)
            native_attrs: dict (optional, only needed when passing single locator)
        """
        if isinstance(locator_or_info, dict):
            # Check if new or old format
            if 'primary' in locator_or_info:
                # New format: contains 'primary' key, use directly
                locators_info = locator_or_info
            elif 'locator' in locator_or_info:
                # Old format: contains 'locator' key, needs conversion to new format
                old_locator = locator_or_info.get('locator')
                old_type = locator_or_info.get('type')
                old_attrs = locator_or_info.get('native_attrs', {})

                # Convert to new format
                locators_info = {
                    'primary': old_locator,
                    'secondary': [],
                    'fallback': old_locator,
                    'uniqueness_score': 50,  # Default medium score
                    'native_attrs': old_attrs,
                    'type': old_type
                }
            else:
                # Unrecognized dict format, try fallback
                print(f"[ImprovedMapping] Warning: unrecognized mapping format: action_id={action_id}, keys={list(locator_or_info.keys())}")
                # Try to use first value as locator
                first_value = next(iter(locator_or_info.values()), None)
                locators_info = {
                    'primary': str(first_value) if first_value else '//body',
                    'secondary': [],
                    'fallback': '//body',
                    'uniqueness_score': 0,
                    'native_attrs': {},
                    'type': 'clickable'
                }
        else:
            # String: build locators_info from single locator
            locators_info = {
                'primary': locator_or_info,
                'secondary': [],
                'fallback': locator_or_info,
                'uniqueness_score': 50,  # Default medium score
                'native_attrs': native_attrs or {},
                'type': elem_type
            }

        self.mapping[action_id] = locators_info
        if action_id >= self.id_counter:
            self.id_counter = action_id + 1

    def get_action_type(self, action_id):
        """Get action type"""
        return self.mapping.get(action_id, {}).get('type')
