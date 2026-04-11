"""
EventMapping - Event mapping management

Responsible for managing the mapping between events captured from addEventListener and elements
"""

from typing import Dict, Optional


class EventMapping:
    """Event mapping class: stores mapping from event ID to element locator info"""

    def __init__(self):
        self.mapping: Dict[int, Dict] = {}  # {id: {'xpath': ..., 'event_type': ..., 'text': ..., ...}}
        self.id_counter: int = 0

    def add_event(self, xpath: str, event_type: str, text: str,
                  original_id: str = "", original_class: str = "") -> int:
        """
        Add event mapping

        Args:
            xpath: XPath locator for the element
            event_type: Event type (e.g. "click", "select_node", etc., already normalized)
            text: Visible text of the element
            original_id: Original element ID (for fallback)
            original_class: Original element class (for fallback)

        Returns:
            int: Assigned event ID
        """
        self.mapping[self.id_counter] = {
            'xpath': xpath,
            'event_type': event_type,
            'text': text,
            'original_id': original_id,
            'original_class': original_class
        }

        event_id = self.id_counter
        self.id_counter += 1
        return event_id

    def get_event(self, event_id: int) -> Optional[Dict]:
        """
        Get event info

        Args:
            event_id: Event ID

        Returns:
            Event info dict, or None if not found
        """
        return self.mapping.get(event_id)

    def has_event(self, event_id: int) -> bool:
        """Check if event ID exists"""
        return event_id in self.mapping

    def clear(self):
        """Clear all mappings"""
        self.mapping = {}
        self.id_counter = 0

    def __len__(self):
        """Return event count"""
        return len(self.mapping)
