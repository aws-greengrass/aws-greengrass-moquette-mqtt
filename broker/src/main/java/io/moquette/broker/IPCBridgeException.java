package io.moquette.broker;

public class IPCBridgeException extends Exception {
    static final long serialVersionUID = -3387516993124229948L;

    public IPCBridgeException(String message, Throwable e) {
        super(message, e);
    }

    public IPCBridgeException(String message) {
        super(message);
    }

    public IPCBridgeException(Throwable e) {
        super(e);
    }
}
