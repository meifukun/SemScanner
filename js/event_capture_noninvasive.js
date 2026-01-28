/*
 * 非侵入式事件捕获 - 不拦截addEventListener，使用事件委托
 *
 * 原理：
 * 1. 不替换Element.prototype.addEventListener（不破坏Angular Zone.js）
 * 2. 在document级别监听所有事件（事件冒泡）
 * 3. 记录事件触发时的目标元素信息
 */

(function() {
    // ==================== 全局变量 ====================
    window.captured_events = [];
    let event_counter = 0;

    // ==================== 辅助函数 ====================
    function getElementSelector(element) {
        // 尝试生成简单的选择器
        if (element.id) {
            return '#' + element.id;
        }

        if (element.getAttribute('aria-label')) {
            return element.tagName.toLowerCase() + '[aria-label="' + element.getAttribute('aria-label') + '"]';
        }

        if (element.className) {
            var firstClass = element.className.split(' ')[0];
            return element.tagName.toLowerCase() + '.' + firstClass;
        }

        return element.tagName.toLowerCase();
    }

    // ==================== 事件委托监听器 ====================
    var eventsToCapture = [
        'click', 'dblclick', 'mousedown', 'mouseup',
        'focus', 'blur', 'input', 'change', 'submit',
        'keydown', 'keyup', 'keypress'
    ];

    eventsToCapture.forEach(function(eventType) {
        // 在捕获阶段监听（useCapture = true）
        // 这样即使Angular阻止了事件，我们也能捕获到
        document.addEventListener(eventType, function(event) {
            try {
                var target = event.target;

                // 记录事件信息
                var eventInfo = {
                    counter: event_counter++,
                    event_type: eventType,
                    tag: target.tagName || '',
                    id: target.id || '',
                    selector: getElementSelector(target),
                    timestamp: Date.now()
                };

                window.captured_events.push(eventInfo);

                // 限制数组大小，避免内存溢出
                if (window.captured_events.length > 1000) {
                    window.captured_events.shift();
                }
            } catch (e) {
                console.error('[EventCapture] Error:', e);
            }
        }, true);  // ← useCapture = true，在捕获阶段监听
    });

    console.log('[EventCapture] Non-invasive event capturing initialized');
})();
