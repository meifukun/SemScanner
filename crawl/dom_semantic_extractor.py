from urllib.parse import urlparse
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.common.exceptions import NoSuchElementException, StaleElementReferenceException
from crawl.ActionMapping import ActionsMapping
from crawl.EventMapping import EventMapping
import time
import re

class DOMSemanticExtractor:
    # Meaningful event types (whitelist)
    # Note: submit is not in this list, form submission should be handled via SUBMIT FORM command (clicking submit button)
    MEANINGFUL_EVENTS = {
        # Mouse events
        'click', 'dblclick', 'contextmenu', 'mouseover',
        # Keyboard events
        'keydown',
        # Form events (excluding submit)
        'change', 'input', 'focus', 'blur','submit',
        # UI events
        'scroll',
        # Drag events
        'dragstart', 'drop',
    }

    # Event priority (when a container has multiple events, choose the highest priority)
    EVENT_PRIORITY = {
        'select_node': 1,  # jsTree select node
        'click': 2,
        'dblclick': 3,
        'mouseover': 4,
        'open_node': 5,  # jsTree expand
        'change': 6,
    }

    # Quantity limit constants
    MAX_ELEMENTS = 500      # Maximum number of DOM elements to process
    MAX_EVENTS = 100        # Maximum number of events to process
    MAX_FORM_FIELDS = 50    # Maximum number of fields per form

    def __init__(self, driver, use_improved_locator=False):
        """
        Initialize DOMSemanticExtractor

        Args:
            driver: Selenium WebDriver
            use_improved_locator: Whether to use improved locator strategy (fixes normalization issues with href and other URL attributes)
        """
        self.driver = driver
        self.abstract_page = ''
        self.actions_mapping = ActionsMapping(use_improved_strategy=use_improved_locator)
        self.actions_mapping.set_driver(driver)  # Inject driver

        # Event mapping (independent from element mapping)
        self.event_mapping = EventMapping()

        # Cache to avoid redundant computation
        self._visibility_cache = {}
        self._processed_elements = set()  # Track processed elements using element ID
        self._text_cache = {}  # Text cache
        self._processed_text_elements = {}  # Record element type and count for processed text

        # Counters
        self._element_count = 0
        self._event_count = 0


    def get_abstract_page(self):
        return self.abstract_page

    def get_actions_mapping(self):
        return self.actions_mapping

    def get_event_mapping(self):
        """Get event mapping (independent from element mapping)"""
        return self.event_mapping

    def update_abstract_page(self):
        start_time = time.time()

        self.actions_mapping.clear()
        self.abstract_page = ''
        self._visibility_cache.clear()
        self._processed_elements.clear()
        self._text_cache.clear()
        self._processed_text_elements.clear()
        # Reset counters
        self._element_count = 0
        self._event_count = 0

        # Time recording points
        t1 = time.time()

        # Optimized selectors - reduce div selection, only select specific divs
        js_script = """
        const selectors = [
        // Interactive elements - highest priority
        'a','button','input','select','textarea',
        '[onclick]','[role="button"]','[role="combobox"]',

        // Material UI buttons - ensure capture
        '.mat-raised-button','.mat-button','.mat-icon-button',
        '.mat-flat-button','.mat-stroked-button','.mat-fab','.mat-mini-fab',

        // Material other components
        'mat-icon','mat-select','mat-option',
        'mat-checkbox','mat-radio-button','mat-slide-toggle',

        // Semantic blocks/lists/forms
        'h1, h2, h3, h4, h5, h6',
        'p','ul','ol',
        'form',

        // Hint/status containers
        '[role="alert"]','[role="dialog"]',

        // Specific class divs
        'div.error','div.warning','div.message','div.alert',
        'div.notification','div.info','div.status',
        'div.item-name','div.item-price','div.info-box',
        'div.product','div.desc','div.description',
        // Elements with special attributes
        '[aria-label]','[aria-describedby]',
        'span.item-price', 'span.ng-star-inserted',
        // Generalized "inline semantic text"
        'code','label','small','strong','em','mark','abbr','cite','kbd','samp','time','data',
        'span[translate]'
        ].join(',');

        // First collect by selectors
        let elements = Array.from(document.querySelectorAll(selectors));

        // Additionally include elements with data-* attributes
        try {
        const withData = Array.from(document.querySelectorAll('*')).filter(el => {
            const names = el.getAttributeNames ? el.getAttributeNames() : [];
            return names.some(n => n.startsWith('data-') && n !== 'data-sensor-id');
        });
        elements.push(...withData);
        } catch (e) {}

        // Handle overlay
        const overlayContainers = document.querySelectorAll('.cdk-overlay-container, .cdk-overlay-pane');
        overlayContainers.forEach(container => {
        elements.push(...Array.from(container.querySelectorAll(selectors)));
        });

        // Deduplicate and sort by DOM order
        const seen = new WeakSet();
        const unique = [];
        elements.forEach(el => {
        if (!seen.has(el)) { seen.add(el); unique.push(el); }
        });

        // Removed data-sensor-id injection code, using native attributes for locating
        return unique;
        """

        try:
            elements = self.driver.execute_script(js_script)
        except Exception as e:
            print(f"Error executing JS script: {e}")
            elements = []

        t2 = time.time()
        print(f"  JS execution and element collection: {t2 - t1:.4f} sec ({len(elements)} elements)")

        # Batch check visibility for all elements
        t3 = time.time()
        self._batch_check_visibility(elements)
        t4 = time.time()
        print(f"  Batch visibility check: {t4 - t3:.4f} sec")

        # Get current page domain
        current_url = self.driver.current_url
        current_domain = urlparse(current_url).netloc

        # Batch process elements
        lines = []

        t5 = time.time()
        for idx, elem in enumerate(elements):
            # Check if element limit reached
            if self._element_count >= self.MAX_ELEMENTS:
                print(f"  Warning: Element limit reached ({self.MAX_ELEMENTS}), stopping processing")
                break
            try:
                # Use index instead of sensor_id
                elem_key = str(idx)

                # Check if already processed
                if elem_key in self._processed_elements:
                    continue

                # Check visibility (read from cache)
                if not self._visibility_cache.get(elem_key, False):
                    self._processed_elements.add(elem_key)
                    continue

                tag_name = elem.tag_name.lower()

                # Process form immediately when encountered:
                if tag_name == 'form':
                    try:
                        form_lines = self._process_form_optimized(elem, elem_key)
                        if form_lines:
                            lines.append(form_lines)
                            self._element_count += 1  # Count
                        self._processed_elements.add(elem_key)
                    except:
                        continue
                    continue  # Skip to next element

                # Process link elements (<a> tag)
                if tag_name == 'a':
                    href = elem.get_attribute('href')
                    # Parse href link
                    if href:
                        parsed_href = urlparse(href)
                        # Check if link is same-origin as current page
                        if parsed_href.netloc and parsed_href.netloc != current_domain:
                            continue  # Skip cross-origin links

                # Skip ALL form children (they'll be handled when form is processed)
                if self._is_inside_form(elem):
                    continue

                # Process non-form elements
                line = self._process_non_form_element(elem, elem_key)
                if line:
                    lines.append(line)
                    self._processed_elements.add(elem_key)
                    self._element_count += 1  # Count

            except StaleElementReferenceException:
                continue
            except Exception as e:
                # Debug output
                print(f"Error processing element: {e}")
                continue

        t6 = time.time()
        print(f"  Processing non-form elements: {t6 - t5:.4f} sec (actually processed: {self._element_count}/{self.MAX_ELEMENTS})")

        # Extract event abstractions (independent system)
        t9 = time.time()
        try:
            event_abstractions = self.extract_events_abstraction()
            if event_abstractions:
                lines.append('\n<!-- Events Captured via addEventListener -->')
                lines.append(event_abstractions)
                print(f"  Extracted event abstractions: {len(self.event_mapping)} events")
            else:
                print(f"  Extracted event abstractions: 0 events")
        except Exception as e:
            print(f"  Failed to extract event abstractions: {e}")

        t10 = time.time()
        print(f"  Event abstraction extraction: {t10 - t9:.4f} sec")

        self.abstract_page = '\n'.join(lines)

        end_time = time.time()
        print(f"Total execution time: {end_time - start_time:.4f} sec")

    def _batch_check_visibility(self, elements):
        """Batch check element visibility, using index instead of sensor_id"""
        js_visibility_script = """
        return arguments[0].map((el, idx) => {
            // Use index instead of sensor_id

            // Basic visibility check, only depends on display property
            const is_displayed = el.offsetParent !== null || getComputedStyle(el).display !== 'none';

            return {index: idx, visible: is_displayed};
        });
        """

        try:
            # Process in batches to avoid processing too many elements at once
            batch_size = 100
            for i in range(0, len(elements), batch_size):
                batch = elements[i:i+batch_size]
                results = self.driver.execute_script(js_visibility_script, batch)
                for result in results:
                    if result and 'index' in result:
                        # Use global index
                        global_idx = i + result['index']
                        self._visibility_cache[str(global_idx)] = result['visible']
        except Exception as e:
            # Fall back to individual checking
            for idx, elem in enumerate(elements):
                try:
                    self._visibility_cache[str(idx)] = elem.is_displayed()
                except:
                    pass

    def _is_inside_form(self, elem):
        """Check if element is inside a form (optimized version)"""
        try:
            # Using JS execution is faster than Python's find_elements
            return self.driver.execute_script(
                "return arguments[0].closest('form') !== null;", elem
            )
        except:
            return False

    def _is_button_like_input(self, elem):
        """Check if input is a button type"""
        if elem.tag_name.lower() != 'input':
            return False
        input_type = (elem.get_attribute('type') or 'text').lower()
        return input_type in ['submit', 'button', 'reset', 'image']

    def _should_process_text(self, text, elem_type='text'):
        """
        Decide whether this text should be processed.
        For interactive elements (buttons, links), process even if text is duplicated.
        For pure text elements, perform deduplication.
        """
        if not text:
            return False

        # # Filter out Material icon text
        # icon_texts = ['menu', 'account_circle', 'shopping_cart', 'language',
        #              'feedback', 'sentiment_dissatisfied', 'chat', 'business_center',
        #              'camera', 'card_membership', 'school', 'power_settings_new',
        #              'expand_more', 'close', 'search']
        # if text.strip() in icon_texts:
        #     return False

        # For interactive elements, always process (regardless of text duplication)
        if elem_type in ['button', 'link', 'clickable', 'input']:
            return True

        # For pure text elements, check if already processed
        if text in self._processed_text_elements:
            # If same type element already processed, skip
            if self._processed_text_elements[text]['type'] == elem_type:
                return False

        return True

    def _record_processed_text(self, text, elem_type='text'):
        """Record processed text"""
        if text:
            if text not in self._processed_text_elements:
                self._processed_text_elements[text] = {'type': elem_type, 'count': 0}
            self._processed_text_elements[text]['count'] += 1

    def _get_native_attrs_str(self, elem_id):
        """Get native attribute string from actions_mapping"""
        if elem_id not in self.actions_mapping.mapping:
            return ''

        native_attrs = self.actions_mapping.mapping[elem_id].get('native_attrs', {})
        attrs_list = []

        # Only output common native attributes (for locating during restoration)
        for key in ['name', 'id', 'type', 'placeholder', 'href', 'aria-label']:
            if key in native_attrs and native_attrs[key]:
                value = native_attrs[key]
                # Escape quotes
                value = str(value).replace('"', '&quot;')
                attrs_list.append(f'{key}="{value}"')

        return ' '.join(attrs_list)

    def _process_non_form_element(self, elem, elem_key=None):
        """Process non-form elements"""
        try:
            tag_name = elem.tag_name.lower()
            role = self.safe_attr(elem, 'role')
            cls = self.safe_attr(elem, 'class')
            text = self._get_element_text_cached(elem, elem_key, include_children=False)

            # Material components
            if tag_name == 'mat-option':
                return self._process_mat_option(elem)

            if tag_name == 'mat-select' or role == 'combobox':
                return self._process_mat_select(elem)

            # Material components
            if tag_name == 'mat-list-item':
                return self._process_clickable(elem)

            # Standard form elements (not inside a form)
            if tag_name in ['input', 'select', 'textarea']:
                return self._process_form_field(elem)

            # Buttons - process first, including Material buttons
            if self._is_clickable(elem):
                return self._process_clickable(elem)

            # Images (only process interactive ones)
            if tag_name == 'img' and role == 'button':
                return self._process_clickable_image(elem)

            # Semantic text elements
            if self._is_semantic_text_element(elem):
                return self._process_semantic_text(elem)

            # Lists
            if tag_name in ['ul', 'ol']:
                return self._process_list(elem)

            # Specific divs (with clear semantics) - stricter filtering
            if tag_name == 'div':
                return self._process_semantic_div(elem)

            return None

        except:
            return None

    def _process_clickable_image(self, elem):
        """Process clickable images"""
        alt_text = self.safe_attr(elem, 'alt')
        if not alt_text:
            return None

        elem_id = self.actions_mapping.add_action(elem, 'clickable:image')

        # Build attribute list (using native attributes)
        attrs = [f'id={elem_id}', 'role="button"']
        attrs.append('data-type="clickable:image"')

        # Add native attributes for locating
        native_attrs = self.actions_mapping.mapping[elem_id].get('native_attrs', {})
        for key, value in native_attrs.items():
            if key in ['name', 'id', 'alt']:
                attrs.append(f'{key}="{value}"')

        attrs_str = ' '.join(attrs)

        return f'<img {attrs_str}>{alt_text}</img>'

    def _process_semantic_div(self, elem):
        """Process semantic div elements (stricter rules)"""
        cls = (self.safe_attr(elem, 'class') or '').lower()
        role = (self.safe_attr(elem, 'role') or '').lower()

        # Check if it's a pure layout container (by checking for specific content classes)
        content_indicators = ['item', 'product', 'price', 'name', 'info', 'desc', 'text']
        is_content_container = any(ind in cls for ind in content_indicators)

        if any(k in cls for k in ['container', 'wrapper', 'grid', 'tile']) and not is_content_container:
            # If it's a pure layout container with no content indicators, skip
            if not any(k in cls for k in ['error', 'warning', 'message', 'alert', 'info']):
                return None

        # Only process divs with clear semantics
        semantic_keywords = ['error', 'warning', 'message', 'alert', 'notification',
                   'info', 'status', 'ribbon', 'heading', 'title',
                   'price', 'name', 'desc', 'description', 'text',
                   'content', 'label', 'value', 'item']
        has_semantic = any(keyword in cls for keyword in semantic_keywords) or role in ['alert', 'status']

        if not has_semantic:
            return None

        text = self._get_element_text_cached(elem, include_children=False)

        # Check if this text should be processed
        if not self._should_process_text(text, 'div'):
            return None

        self._record_processed_text(text, 'div')

        # Add appropriate tags based on class name or role
        if 'error' in cls:
            return f'<div class="error">{text}</div>'
        elif 'warning' in cls:
            return f'<div class="warning">{text}</div>'
        elif role == 'alert':
            return f'<div role="alert">{text}</div>'
        else:
            return f'<div>{text}</div>'

    def _process_form_optimized(self, form_elem, elem_key=None):
        """Optimized form processing"""
        lines = []

        # Mark the form itself and all child elements as processed
        if elem_key:
            self._processed_elements.add(elem_key)

        # Form header
        name = self.safe_attr(form_elem, 'name') or self.safe_attr(form_elem, 'id')
        action = self.safe_attr(form_elem, 'action')
        method = (self.safe_attr(form_elem, 'method') or 'GET').upper()
        lines.append(f'<form name="{name}" action="{action}" method="{method}">')

        # Batch get form fields
        try:
            fields = form_elem.find_elements(By.CSS_SELECTOR, 'input, select, textarea, button')

            for field in fields:
                try:
                    # Check visibility (simple check)
                    if not field.is_displayed():
                        continue

                    tag = field.tag_name.lower()

                    # Process buttons - even inside forms
                    if tag == 'button' or self._is_button_like_input(field):
                        field_line = self._process_clickable(field)
                    else:
                        field_line = self._process_form_field(field)

                    if field_line:
                        lines.append('  ' + field_line)
                except:
                    continue
        except:
            pass

        lines.append('</form>')
        return '\n'.join(lines) if len(lines) > 2 else None

    def _get_element_text_cached(self, elem, elem_key=None, include_children=True):
        """Element text retrieval with caching"""
        if elem_key is None:
            # No key, get text directly
            return self._get_element_text(elem, include_children)

        cache_key = f"{elem_key}_{include_children}"

        if cache_key in self._text_cache:
            return self._text_cache[cache_key]

        text = self._get_element_text(elem, include_children)
        self._text_cache[cache_key] = text
        return text

    def _is_clickable(self, elem):
        """Determine if element is clickable - improved version"""
        tag = elem.tag_name.lower()
        cls = (elem.get_attribute('class') or '').lower()

        # Explicitly clickable elements
        # mat-icon may be clickable - especially search related. This is a special case though
        if tag == 'mat-icon':
            # Check if it's a search-related icon
            if 'mat-search_icon' in cls:
                return True  # Search icon should be identified as clickable

        if tag in ['a', 'button'] or tag == 'mat-list-item':
            return True

        if tag == 'input':
            return self._is_button_like_input(elem)

        # Material UI button classes - important improvement
        material_button_classes = ['mat-raised-button', 'mat-button', 'mat-icon-button',
                                  'mat-flat-button', 'mat-stroked-button',
                                  'mat-fab', 'mat-mini-fab', 'btn-basket']
        if any(btn_class in cls for btn_class in material_button_classes):
            return True

        # Role or attribute check
        if self.safe_attr(elem, 'role') == 'button':
            return True

        if self.safe_attr(elem, 'onclick'):
            return True

        if self.safe_attr(elem, 'routerlink'):
            return True

        # mat-icon may be clickable
        if tag == 'mat-icon':
            # Check if it has a clickable ancestor
            try:
                has_clickable_parent = self.driver.execute_script("""
                    const el = arguments[0];
                    let parent = el.parentElement;
                    while (parent && parent !== document.body) {
                        if (parent.tagName === 'BUTTON' || parent.tagName === 'A' ||
                            parent.getAttribute('role') === 'button' ||
                            parent.onclick ||
                            (parent.className && parent.className.includes('mat-button'))) {
                            return true;
                        }
                        parent = parent.parentElement;
                    }
                    return false;
                """, elem)
                return not has_clickable_parent  # Only consider self clickable if no clickable parent
            except:
                pass

        return False

    def _is_semantic_text_element(self, elem):
        tag = elem.tag_name.lower()
        # Block-level/preformatted/code
        if tag in ['h1','h2','h3','h4','h5','h6','p','blockquote','pre','code']:
            return True
        # Inline semantic text
        if tag in ['label','small','strong','em','mark','abbr','cite','kbd','samp','time','data']:
            return True
        # With semantic attributes
        if tag == 'span':
            return True
        if self.safe_attr(elem, 'aria-label') or self.safe_attr(elem, 'aria-describedby'):
            return True
        # Class contains common "copy/title/description/help" keywords
        cls = (elem.get_attribute('class') or '').lower()
        if tag != 'div' and any(k in cls for k in ['heading','title','subtitle','description','desc','help','hint','note','caption']):
            return True
        # Class contains content-related keywords
        content_keywords = ['price', 'name', 'item', 'product', 'value']
        if any(k in cls for k in content_keywords):
            return True
        return False

    def _is_inline_semantic(self, elem) -> bool:
        tag = elem.tag_name.lower()
        if tag in {'code','label','small','strong','em','mark','abbr','cite','kbd','samp','time','data'}:
            return True
        # Span or any element with semantic attributes
        if tag == 'span' and (self.safe_attr(elem, 'translate')):
            return True
        if self.safe_attr(elem, 'aria-label') or self.safe_attr(elem, 'aria-describedby'):
            return True
        # Elements with data-* are also considered semantic (e.g. data-hint / data-help / data-desc)
        attrs = (elem.get_attribute('outerHTML') or '')
        if re.search(r'\sdata-[a-zA-Z0-9_-]+=', attrs):
            return True
        return False

    def _process_clickable(self, elem):
        """Process clickable elements - fix text retrieval issue"""
        # Fix: changed to True here to ensure text inside <span>Login</span> can be retrieved
        text = self._get_element_text_cached(elem, include_children=True)

        # Special handling for search icon
        if elem.tag_name.lower() == 'mat-icon':
            icon_text = text.strip()
            if icon_text == 'search':
                elem_id = self.actions_mapping.add_action(elem, 'clickable')
                sensor_id = elem.get_attribute('data-sensor-id')

                attrs = [f'id={elem_id}']
                if sensor_id:
                    attrs.append(f'data-sensor-id="{sensor_id}"')
                attrs.append('data-type="clickable"')
                attrs_str = ' '.join(attrs)

                return f'<button {attrs_str}>Activate Search</button>'
            elif icon_text == 'close':
                elem_id = self.actions_mapping.add_action(elem, 'clickable')
                sensor_id = elem.get_attribute('data-sensor-id')

                attrs = [f'id={elem_id}']
                if sensor_id:
                    attrs.append(f'data-sensor-id="{sensor_id}"')
                attrs.append('data-type="clickable"')
                attrs_str = ' '.join(attrs)

                return f'<button {attrs_str}>Close Search</button>'

        # For buttons, process even if text is duplicated
        elem_id = self.actions_mapping.add_action(elem, 'clickable')
        tag = elem.tag_name.lower()
        sensor_id = elem.get_attribute('data-sensor-id')

        # Record processed text (but don't block processing)
        if text:
            self._record_processed_text(text, 'button')

        attrs = []
        if elem_id is not None:
            attrs.append(f'id={elem_id}')

        if sensor_id:
            attrs.append(f'data-sensor-id="{sensor_id}"')
        attrs.append('data-type="clickable"')

        # Use safe_attr_for_locator to get DOM raw href value
        href = self.safe_attr_for_locator(elem, 'href')
        if href:
            attrs.append(f'href="{href}"')
            if not text:
                text = href

        role = self.safe_attr(elem, 'role')
        if role == 'button':
            attrs.append('role="button"')

        routerlink = self.safe_attr(elem, 'routerlink')
        if routerlink:
            attrs.append(f'routerlink="{routerlink}"')

        # If button tag but no text, try to get aria-label
        if tag == 'button' and not text:
            text = self.safe_attr(elem, 'aria-label')
            if not text:
                # Last resort: if it's input type=submit/button, try getting value
                if tag == 'input':
                    text = self.safe_attr(elem, 'value')

                if not text:
                    # If really no text, we could print a warning, but better not return None unless certain it's useless
                    # Since an Action ID has already been assigned, returning a button with empty content is better than it disappearing
                    # But to maintain original logic, return None here - changing include_children to True above should solve 99% of cases
                    return None

        attrs_str = ' '.join(attrs) if attrs else ''

        # For button tags, use button instead of original tag name
        if tag in ['button', 'input']:
            return f'<button {attrs_str}>{text}</button>'.strip()
        else:
            return f'<{tag} {attrs_str}>{text}</{tag}>'.strip()

    def _process_form_field(self, elem):
        """Process form fields"""
        tag = elem.tag_name.lower()

        if tag == 'input':
            subtype = (elem.get_attribute('type') or 'text').lower()
            field_id = self.actions_mapping.add_action(elem, f'input:{subtype}')
            return self._format_input(elem, field_id)

        elif tag == 'select':
            field_id = self.actions_mapping.add_action(elem, 'select')
            return self._format_select(elem, field_id)

        elif tag == 'textarea':
            field_id = self.actions_mapping.add_action(elem, 'textarea')
            return self._format_textarea(elem, field_id)

        return None

    def _process_semantic_text(self, elem):
        """Process semantic text elements"""
        text = self._get_element_text_cached(elem, include_children=False)

        if not self._should_process_text(text, 'semantic'):
            return None

        self._record_processed_text(text, 'semantic')

        tag = elem.tag_name.lower()
        return f'<{tag}>{text}</{tag}>'

    def _process_list(self, elem):
        """Process list elements"""
        tag = elem.tag_name.lower()
        items = elem.find_elements(By.TAG_NAME, 'li')

        if not items:
            return None

        lines = [f'<{tag}>']
        max_items = 10
        processed_count = 0

        for item in items[:max_items]:
            try:
                text = self._get_element_text_cached(item, include_children=False)
                if text and self._should_process_text(text, 'list-item'):
                    lines.append(f'  <li>{text}</li>')
                    self._record_processed_text(text, 'list-item')
                    processed_count += 1
            except:
                continue

        if len(items) > max_items:
            lines.append(f'  <!-- {len(items) - max_items} more items not shown -->')

        lines.append(f'</{tag}>')

        # Only return if items were actually processed
        return '\n'.join(lines) if processed_count > 0 else None

    def _process_mat_option(self, elem):
        """Process Material Option"""
        text = self._get_element_text_cached(elem)
        sensor_id = elem.get_attribute('data-sensor-id')

        opt_id = self.actions_mapping.add_action(elem, 'option:mat')

        # Build attribute list
        attrs = [f'id={opt_id}']

        # Add data-sensor-id and data-type
        if sensor_id:
            attrs.append(f'data-sensor-id="{sensor_id}"')
        attrs.append('data-type="option:mat"')

        attrs_str = ' '.join(attrs)

        return f'<option-mat {attrs_str}>{text}</option-mat>'

    def _process_mat_select(self, elem):
        """Process Material Select"""
        field_id = self.actions_mapping.add_action(elem, 'select:mat')
        sensor_id = elem.get_attribute('data-sensor-id')

        # Get currently selected value
        selected = ''
        try:
            selected = elem.find_element(By.CSS_SELECTOR, '.mat-mdc-select-min-line').text.strip()
        except:
            selected = self._get_element_text_cached(elem)

        disabled = ' disabled' if self.safe_attr(elem, 'aria-disabled') == 'true' else ''

        # Build attribute list
        attrs = [f'id={field_id}', 'name="mat-select"', f'value="{selected}"']

        # Add data-sensor-id and data-type
        if sensor_id:
            attrs.append(f'data-sensor-id="{sensor_id}"')
        attrs.append('data-type="select:mat"')

        attrs_str = ' '.join(attrs)

        return f'<select {attrs_str}{disabled}></select>'

    def _format_input(self, elem, field_id):
        """Format input element"""
        input_type = (elem.get_attribute('type') or 'text').lower()

        # If button type, convert to button handling
        if input_type in ['submit', 'button', 'reset']:
            return self._process_clickable(elem)

        sensor_id = elem.get_attribute('data-sensor-id')

        name = self.safe_attr(elem, 'name')
        placeholder = self.safe_attr(elem, 'placeholder')
        value = self.safe_attr(elem, 'value')

        attrs = [f'id={field_id}', f'type="{input_type}"']

        # Add data-sensor-id and data-type
        if sensor_id:
            attrs.append(f'data-sensor-id="{sensor_id}"')
        attrs.append(f'data-type="input:{input_type}"')

        min_v = self.safe_attr(elem, 'min')
        max_v = self.safe_attr(elem, 'max')
        step = self.safe_attr(elem, 'step')
        if min_v:
            attrs.append(f'min="{min_v}"')
        if max_v:
            attrs.append(f'max="{max_v}"')
        if step:
            attrs.append(f'step="{step}"')

        if name:
            attrs.append(f'name="{name}"')
        if placeholder:
            attrs.append(f'placeholder="{placeholder}"')
        if value:
            attrs.append(f'value="{value}"')
        if elem.get_attribute('required') is not None:
            attrs.append('required')
        if not elem.is_enabled():
            attrs.append('disabled')

        if input_type in ['checkbox', 'radio']:
            try:
                if elem.is_selected():
                    attrs.append('checked')
            except:
                pass

        label = self._get_label_for_input(elem)
        attrs_str = ' '.join(attrs)

        return f'<input {attrs_str}>{label}</input>'

    def _format_select(self, elem, field_id):
        """Format select element"""
        sensor_id = elem.get_attribute('data-sensor-id')

        name = self.safe_attr(elem, 'name')
        attrs = [f'id={field_id}']

        # Add data-sensor-id and data-type
        if sensor_id:
            attrs.append(f'data-sensor-id="{sensor_id}"')
        attrs.append('data-type="select"')

        if name:
            attrs.append(f'name="{name}"')
        if elem.get_attribute('required') is not None:
            attrs.append('required')
        if elem.get_attribute('multiple') is not None:
            attrs.append('multiple')
        if not elem.is_enabled():
            attrs.append('disabled')

        options = elem.find_elements(By.TAG_NAME, 'option')
        attrs.append(f'options="{len(options)}"')

        label = self._get_label_for_input(elem)
        attrs_str = ' '.join(attrs)

        lines = [f'<select {attrs_str}>{label}']

        # Limit displayed options
        max_options = 10
        for i, opt in enumerate(options[:max_options]):
            try:
                opt_value = self.safe_attr(opt, 'value')
                opt_text = opt.text.strip()
                opt_attrs = []

                if opt_value:
                    opt_attrs.append(f'value="{opt_value}"')
                if opt.is_selected():
                    opt_attrs.append('selected')
                if not opt.is_enabled():
                    opt_attrs.append('disabled')

                opt_attrs_str = ' '.join(opt_attrs) if opt_attrs else ''
                lines.append(f'  <option {opt_attrs_str}>{opt_text}</option>')
            except:
                continue

        if len(options) > max_options:
            lines.append(f'  <!-- {len(options) - max_options} more options not shown -->')

        lines.append('</select>')
        return '\n'.join(lines)

    def _format_textarea(self, elem, field_id):
        """Format textarea element"""
        sensor_id = elem.get_attribute('data-sensor-id')

        name = self.safe_attr(elem, 'name')
        placeholder = self.safe_attr(elem, 'placeholder')
        value = elem.text.strip() or elem.get_attribute('value') or ''

        attrs = [f'id={field_id}']

        # Add data-sensor-id and data-type
        if sensor_id:
            attrs.append(f'data-sensor-id="{sensor_id}"')
        attrs.append('data-type="textarea"')

        if name:
            attrs.append(f'name="{name}"')
        if placeholder:
            attrs.append(f'placeholder="{placeholder}"')
        if value:
            attrs.append(f'value="{value}"')
        if elem.get_attribute('required') is not None:
            attrs.append('required')
        if not elem.is_enabled():
            attrs.append('disabled')

        label = self._get_label_for_input(elem)
        attrs_str = ' '.join(attrs)

        return f'<textarea {attrs_str}>{label}</textarea>'

    def _get_element_text(self, elem, include_children=True):
        """Get element text - improved version"""
        try:
            if include_children:
                # Get full text
                text = elem.text.strip()
            else:
                # Only get direct text nodes, not including child elements
                text = self.driver.execute_script("""
                    const el = arguments[0];
                    let text = '';
                    for (let node of el.childNodes) {
                        if (node.nodeType === Node.TEXT_NODE) {
                            text += node.textContent;
                        }
                    }
                    return text.trim();
                """, elem)

            # If no text, try other attributes
            if not text:
                tag = elem.tag_name.lower()

                # input elements use value
                if tag == 'input':
                    input_type = (elem.get_attribute('type') or 'text').lower()
                    if input_type in ['submit', 'button', 'reset']:
                        text = elem.get_attribute('value') or ''

                # Try aria-label
                if not text:
                    text = self.safe_attr(elem, 'aria-label')

                # Try title
                if not text:
                    text = self.safe_attr(elem, 'title')

                # img uses alt
                if not text and tag == 'img':
                    text = self.safe_attr(elem, 'alt')

            # Clean text - filter Material icon text
            text = re.sub(r'\s+', ' ', text).strip()

            return text[:500] if text else ''  # Limit length

        except:
            return ''

    def _get_label_for_input(self, elem):
        """Get label for input field"""
        # Associate via for attribute
        elem_id = self.safe_attr(elem, 'id')
        if elem_id:
            try:
                label = self.driver.find_element(By.CSS_SELECTOR, f'label[for="{elem_id}"]')
                text = label.text.strip()
                if text:
                    return text
            except:
                pass

        # Find parent label
        try:
            label = elem.find_element(By.XPATH, 'ancestor::label[1]')
            text = label.text.strip()
            if text:
                return text
        except:
            pass

        # aria-label
        aria_label = self.safe_attr(elem, 'aria-label')
        if aria_label:
            return aria_label

        # placeholder as fallback
        placeholder = self.safe_attr(elem, 'placeholder')
        if placeholder:
            return placeholder

        return ''

    def safe_attr(self, elem, name):
        """Safely get attribute (may return normalized value, e.g. absolute URL for href)"""
        try:
            return elem.get_attribute(name) or ''
        except:
            return ''

    def safe_attr_for_locator(self, elem, name):
        """
        Safely get attribute for generating locator (returns DOM raw value)

        For href, src, action and other URL attributes, returns DOM raw value instead of normalized absolute URL.
        This way the generated CSS selector can correctly match the DOM.
        """
        # URL-type attributes need DOM raw values
        url_attrs = {'href', 'src', 'action', 'formaction', 'poster', 'data', 'cite', 'background'}

        try:
            if name in url_attrs:
                # Use JavaScript to get DOM raw attribute value
                try:
                    return self.driver.execute_script(
                        "return arguments[0].getAttribute(arguments[1]);",
                        elem,
                        name
                    ) or ''
                except:
                    # Fallback to regular method
                    return elem.get_attribute(name) or ''
            else:
                # Other attributes are fetched directly
                return elem.get_attribute(name) or ''
        except:
            return ''

    # ============================================================
    # Event capture and abstraction
    # ============================================================

    def _is_meaningful_event(self, event_type: str) -> bool:
        """
        Determine if an event is meaningful (worth capturing)

        Args:
            event_type: Event type (e.g. "click", "mousemove", etc.)

        Returns:
            bool: Whether it's meaningful
        """
        # 1. In whitelist
        if event_type in self.MEANINGFUL_EVENTS:
            return True

        # 2. Custom events (containing . or :, e.g. "select_node.jstree")
        if '.' in event_type or ':' in event_type:
            return True

        return False

    def _normalize_event_type(self, event_type: str) -> str:
        """
        Normalize event type (for execution and display)

        Args:
            event_type: Original event type

        Returns:
            str: Normalized event type
        """
        # jQuery namespace -> remove suffix
        if '.jstree' in event_type:
            return event_type.replace('.jstree', '')  # "select_node.jstree" -> "select_node"

        if '.bs.' in event_type:  # Bootstrap
            return event_type.split('.')[0]  # "show.bs.modal" -> "show"

        # Mouse event normalization
        if event_type in ['mousedown', 'mouseup']:
            return 'click'

        return event_type

    def _get_xpath_for_element(self, elem) -> str:
        """
        Generate XPath for an element

        Args:
            elem: Selenium WebElement

        Returns:
            str: XPath string
        """
        try:
            return self.driver.execute_script("""
                function getXPath(element) {
                    if (!element) return '';

                    // Prefer using id
                    if (element.id) {
                        return '//*[@id="' + element.id + '"]';
                    }

                    // Otherwise build path
                    if (element === document.body) {
                        return '/html/body';
                    }

                    var ix = 0;
                    var siblings = element.parentNode ? element.parentNode.childNodes : [];
                    for (var i = 0; i < siblings.length; i++) {
                        var sibling = siblings[i];
                        if (sibling === element) {
                            var parentPath = getXPath(element.parentNode);
                            return parentPath + '/' + element.tagName.toLowerCase() + '[' + (ix + 1) + ']';
                        }
                        if (sibling.nodeType === 1 && sibling.tagName === element.tagName) {
                            ix++;
                        }
                    }
                    return '';
                }
                return getXPath(arguments[0]);
            """, elem) or ''
        except:
            return ''

    def _is_container_tag(self, tag: str) -> bool:
        """Determine if a tag is a container type (needs to traverse child elements)"""
        return tag.upper() in ['DIV', 'UL', 'OL', 'TABLE', 'TBODY', 'THEAD', 'NAV', 'SECTION', 'ASIDE']

    def extract_events_abstraction(self) -> str:
        """
        Generate abstract representation from captured events

        Returns:
            str: Multi-line string of event abstractions
        """
        # Clear event mapping (regenerated each scan)
        self.event_mapping.clear()

        # Get max ID from element mapping, event IDs offset from this
        # This avoids event ID and element ID conflicts
        max_element_id = -1
        if self.actions_mapping.mapping:
            max_element_id = max(self.actions_mapping.mapping.keys())

        # Event ID start value (element max ID + 1, ensuring no conflict)
        event_id_offset = max_element_id + 1
        # Set event_mapping start ID
        self.event_mapping.id_counter = event_id_offset
        print(f"[DOMSemanticExtractor] Event ID start value: {event_id_offset} (element max ID: {max_element_id})")

        try:
            # 1. Read event data
            events_data = self.driver.execute_script("return window.added_events || [];")

            if not events_data:
                print(f"[DOMSemanticExtractor] No events captured")
                return ""

            print(f"[DOMSemanticExtractor] Captured {len(events_data)} raw events")

            # 2. Filter meaningless events
            events_data = [e for e in events_data if self._is_meaningful_event(e.get('event', ''))]
            print(f"[DOMSemanticExtractor] {len(events_data)} meaningful events after filtering")

            # 3. Group by container (choose highest priority event for same container)
            container_events = {}
            for evt in events_data:
                addr = evt.get('addr', '')
                if not addr:
                    continue

                if addr not in container_events:
                    container_events[addr] = evt
                else:
                    # Compare priority
                    existing_priority = self.EVENT_PRIORITY.get(
                        self._normalize_event_type(container_events[addr].get('event', '')), 999
                    )
                    new_priority = self.EVENT_PRIORITY.get(
                        self._normalize_event_type(evt.get('event', '')), 999
                    )
                    if new_priority < existing_priority:
                        container_events[addr] = evt

            # 4. Process each container's events
            abstracts = []
            seen_texts = set()  # Text deduplication

            for addr, evt in container_events.items():
                # Check if event limit reached
                if self._event_count >= self.MAX_EVENTS:
                    print(f"  Warning: Event limit reached ({self.MAX_EVENTS}), stopping processing")
                    break
                try:
                    # Locate element
                    elem = self.driver.find_element(By.XPATH, addr)
                    tag = evt.get('tag', '').upper()
                    event_type = self._normalize_event_type(evt.get('event', 'click'))

                    # Determine if it's a container
                    if self._is_container_tag(tag):
                        # Container: traverse child elements
                        self._process_container_events(
                            elem, event_type, abstracts, seen_texts,
                            evt.get('id', ''), evt.get('class', '')
                        )
                    else:
                        # Regular element: process directly
                        self._process_single_event(
                            elem, addr, event_type, abstracts, seen_texts,
                            evt.get('id', ''), evt.get('class', '')
                        )

                except NoSuchElementException:
                    print(f"[DOMSemanticExtractor] XPath locating failed: {addr[:50]}...")
                    continue
                except Exception as e:
                    print(f"[DOMSemanticExtractor] Failed to process event: {e}")
                    continue

            print(f"[DOMSemanticExtractor] Generated {len(abstracts)} event abstractions")
            return '\n'.join(abstracts)

        except Exception as e:
            print(f"[DOMSemanticExtractor] Failed to extract events: {e}")
            import traceback
            traceback.print_exc()
            return ""

    def _process_container_events(self, container, event_type: str, abstracts: list,
                                   seen_texts: set, original_id: str, original_class: str):
        """
        Process container-type events (traverse child elements)

        Args:
            container: Container element
            event_type: Event type
            abstracts: Abstractions list (for appending)
            seen_texts: Seen text set (for deduplication)
            original_id: Original container ID
            original_class: Original container class
        """
        # Child element selectors (for different container types)
        container_class = self.safe_attr(container, 'class') or ''

        if 'jstree' in container_class:
            # jsTree: find node anchors, exclude expand icons
            selector = 'a.jstree-anchor'
        elif 'dropdown' in container_class or 'menu' in container_class:
            # Dropdown menu
            selector = 'a, button, li'
        else:
            # Generic container
            selector = 'a, button, span[class*="btn"], div[class*="btn"], li[role="button"], li[role="treeitem"]'

        try:
            children = container.find_elements(By.CSS_SELECTOR, selector)
        except:
            children = []

        for child in children:
            # Check if event limit reached
            if self._event_count >= self.MAX_EVENTS:
                break
            try:
                # Check visibility
                if not child.is_displayed():
                    continue

                # Get text
                text = child.text.strip()
                if not text:
                    text = self.safe_attr(child, 'title') or self.safe_attr(child, 'aria-label')
                if not text:
                    continue

                # Truncate long text
                text = text[:50]

                # Deduplication
                if text in seen_texts:
                    continue
                seen_texts.add(text)

                # Generate XPath
                child_xpath = self._get_xpath_for_element(child)
                if not child_xpath:
                    continue

                # Add to mapping
                event_id = self.event_mapping.add_event(
                    xpath=child_xpath,
                    event_type=event_type,
                    text=text,
                    original_id=self.safe_attr(child, 'id'),
                    original_class=self.safe_attr(child, 'class')
                )

                # Generate abstraction
                abstracts.append(f'<event id={event_id} type="{event_type}">{text}</event>')
                self._event_count += 1  # Count

            except StaleElementReferenceException:
                continue
            except Exception as e:
                continue

    def _process_single_event(self, elem, xpath: str, event_type: str, abstracts: list,
                               seen_texts: set, original_id: str, original_class: str):
        """
        Process a single element's event

        Args:
            elem: Element
            xpath: Element XPath
            event_type: Event type
            abstracts: Abstractions list (for appending)
            seen_texts: Seen text set (for deduplication)
            original_id: Original ID
            original_class: Original class
        """
        # Check if event limit reached
        if self._event_count >= self.MAX_EVENTS:
            return

        try:
            # Check visibility
            if not elem.is_displayed():
                return

            # Get text
            text = elem.text.strip()
            if not text:
                text = self.safe_attr(elem, 'title') or self.safe_attr(elem, 'aria-label')
            if not text:
                text = self.safe_attr(elem, 'value')  # Button value
            if not text:
                return

            # Truncate long text
            text = text[:50]

            # Deduplication
            if text in seen_texts:
                return
            seen_texts.add(text)

            # Add to mapping
            event_id = self.event_mapping.add_event(
                xpath=xpath,
                event_type=event_type,
                text=text,
                original_id=original_id,
                original_class=original_class
            )

            # Generate abstraction
            abstracts.append(f'<event id={event_id} type="{event_type}">{text}</event>')
            self._event_count += 1  # Count

        except Exception as e:
            pass
