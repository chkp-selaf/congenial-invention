// ai-traffic-interceptor – Electron renderer preload shim
// This script is injected into Electron renderer processes to intercept
// network calls made via fetch() and WebSocket.send(). The captured
// metadata is forwarded to the native hook layer through a custom
// window.aiTrafficInterceptor bridge if present, or falls back to
// window.postMessage so that the native DLL can listen from the host.

(function () {
    if (window.__aiTrafficInterceptorHooked) return; // idempotent
    window.__aiTrafficInterceptorHooked = true;

    //--------------------------------------------------------------
    // Utility: emit event that native side can capture.
    //--------------------------------------------------------------
    function emit(event) {
        if (window.aiTrafficInterceptor && typeof window.aiTrafficInterceptor.emit === 'function') {
            // Preferred: bridge provided by C++ side (e.g. via contextBridge)
            window.aiTrafficInterceptor.emit(event);
        } else {
            // Fallback: postMessage to the renderer; the DLL can hook this.
            window.postMessage({ __aiti: true, payload: event }, '*');
        }
    }

    //--------------------------------------------------------------
    // Patch fetch()
    //--------------------------------------------------------------
    const originalFetch = window.fetch;
    window.fetch = async function (...args) {
        const start = performance.now();
        try {
            const response = await originalFetch.apply(this, args);
            const duration = performance.now() - start;
            emit({
                type: 'fetch',
                url: args[0]?.toString?.() || '',
                method: (args[1] && args[1].method) || 'GET',
                status: response.status,
                duration,
            });
            return response;
        } catch (err) {
            emit({ type: 'fetch-error', message: err?.message || String(err) });
            throw err;
        }
    };

    //--------------------------------------------------------------
    // Patch WebSocket.send()
    //--------------------------------------------------------------
    const OriginalWebSocket = window.WebSocket;
    function WrappedWebSocket(url, protocols) {
        const ws = new OriginalWebSocket(url, protocols);
        const originalSend = ws.send;
        ws.send = function (data) {
            try {
                emit({ type: 'ws-send', url: ws.url, payloadPreview: String(data).slice(0, 200) });
            } catch (_) {}
            return originalSend.apply(ws, arguments);
        };
        return ws;
    }
    WrappedWebSocket.prototype = OriginalWebSocket.prototype;
    WrappedWebSocket.CONNECTING = OriginalWebSocket.CONNECTING;
    WrappedWebSocket.OPEN = OriginalWebSocket.OPEN;
    WrappedWebSocket.CLOSING = OriginalWebSocket.CLOSING;
    WrappedWebSocket.CLOSED = OriginalWebSocket.CLOSED;
    window.WebSocket = WrappedWebSocket;

    //--------------------------------------------------------------
    // Log for visibility (can be removed in production)
    //--------------------------------------------------------------
    console.debug('[ai-traffic-interceptor] preload hooks installed');
})();
