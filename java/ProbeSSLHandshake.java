import org.openjdk.btrace.core.annotations.BTrace;
import org.openjdk.btrace.core.annotations.OnMethod;
import org.openjdk.btrace.core.annotations.Location;
import org.openjdk.btrace.core.annotations.BTrace;
import org.openjdk.btrace.core.annotations.Kind;
import org.openjdk.btrace.core.annotations.Location;
import org.openjdk.btrace.core.annotations.OnMethod;
import org.openjdk.btrace.core.annotations.Return;

import java.lang.reflect.Field;
import static org.openjdk.btrace.core.BTraceUtils.*;
import javax.net.ssl.*;

@BTrace
public class ProbeSSLHandshake {
    private static Field certField = field("sun.security.ssl.SSLSessionImpl", "peerCerts");
    private static java.lang.Object[] peerCerts;
    @OnMethod(clazz = "javax.net.ssl.HandshakeCompletedEvent", method = "getSession", location = @Location(Kind.RETURN))
    public static void methodReturn(@Return SSLSession session) {
        peerCerts = (java.lang.Object[])get(certField, session);
        printArray(peerCerts);
    }
}
