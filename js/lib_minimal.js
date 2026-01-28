/*
 * 极简版wrapper - 用于验证性能假设
 *
 * 只记录最基本信息，不做任何DOM遍历或复杂计算
 */

// ==================== 全局变量 ====================
window.added_events = [];
window.wrapper_errors = [];
// ====================================================================

function callbackWrap(object, property, argumentIndex, wrapperFactory) {
	var original = object[property];
	object[property] = function() {
		try {
			wrapperFactory(this, arguments);
		} catch (e) {
			console.error('[Wrapper Error]', e);
			window.wrapper_errors.push({
				property: property,
				error: e.message
			});
		}
		return original.apply(this, arguments);
	}
	return original;
}

// ==================== 极简版 addEventListenerWrapper ====================
// 只记录最基本信息，不做DOM遍历和MD5计算
let event_counter = 0;

function addEventListenerWrapper(elem, args) {
	try {
		// 只记录最基本信息
		var resp = {
			"event": args[0],
			"tag": elem.tagName || '',
			"id": elem.id || '',
			"counter": event_counter++  // 用计数器代替MD5
		};

		window.added_events.push(resp);
	} catch (e) {
		console.error('[addEventListenerWrapper Error]', e);
	}
}

// 导出到全局
if (typeof window !== 'undefined') {
	window.Simulate = {
		event: function(element, eventName) {
			if (document.createEvent) {
				var evt = document.createEvent("HTMLEvents");
				evt.initEvent(eventName, true, true);
				element.dispatchEvent(evt);
			}
		}
	};
}
