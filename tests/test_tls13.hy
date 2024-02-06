(require
  dash *)

(import
  unittest [IsolatedAsyncioTestCase]
  dash *
  ssl
  asyncio
  iotools *
  iotools.proto.ssl *
  iotools-tls13 *)

;; openssl req -new -x509 -days 365 -nodes -out cert.pem -keyout key.pem
(setv COMMONNAME "localhost"
      CERTFILE   "tests_resources/cert.pem"
      KEYFILE    "tests_resources/key.pem")

(defn server-context []
  (doto (ssl.create-default-context ssl.Purpose.CLIENT-AUTH)
        (.load-cert-chain :certfile CERTFILE :keyfile KEYFILE)))

(defn/a run-tls-server [[host "localhost"] [port 4433]]
  (defn/a handler [reader writer]
    (with/a [tcp-stream (AsyncTCPStream :reader reader :writer writer)]
      (with/a [ssl-stream (await (.handshake (AsyncSSLAcceptor :ssl-context (server-context)) tcp-stream))]
        (let [data (await (.read ssl-stream))]
          (print "server recv data:" data)
          (await (.write ssl-stream data))
          (await (.flush ssl-stream))))))
  (with/a [server (await (asyncio.start-server handler host port))]
    (print "start tls server ...")
    (try
      (await (.serve-forever server))
      (except [_ asyncio.CancelledError]
        (print "shutdown tls server ...")
        (raise))
      (except [e Exception]
        (print "error while serving:" e)
        (raise)))))

(defn/a run-tls-client [[data b"hello"] [host "localhost"] [port 4433]]
  (with/a [tcp-stream (await (AsyncTCPStream.open host port))]
    (let [context (TLS13Context :server-hostname "localhost" :server-cafile CERTFILE)]
      (with/a [tls13-stream (await (.handshake (AsyncTLS13Connector context) tcp-stream))]
        (await (.tls13-write-key-update tls13-stream))
        (await (.write tls13-stream data))
        (await (.flush tls13-stream))
        (await (.read tls13-stream))))))

(defclass TestTLS13 [IsolatedAsyncioTestCase]
  (setv port 4433)

  (defn/a asyncSetUp [self]
    (let [task (asyncio.create-task (run-tls-server :port self.port))]
      (setv self.task task)))

  (defn/a asyncTearDown [self]
    (.cancel self.task))

  (defn/a test-tls13 [self]
    (.assertEqual self (await (run-tls-client :data b"hello" :port self.port)) b"hello")))

(export
  :objects [TestTLS13])
