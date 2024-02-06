(require
  dash *)

(import
  dash *
  iotools.proto.base *
  iotools-tls13.struct *
  iotools-tls13.context *)

(do/a!
  (defclass (name/a! TLS13Stream) [(name/a! LayeredStream)]
    (defn __init__ [self context #** kwargs]
      (.__init__ (super) #** kwargs)
      (setv self.context context))

    (defn/a! tls13-read-record [self]
      (let [#(opaque-type legacy-record-version encrypted-record) (wait/a! (.read-loop self.next-layer Ciphertext.read))]
        (.decrypt-record self.context.server-application-decryptor encrypted-record)))

    (defn/a! tls13-write-key-update [self [request False]]
      (ignore
        (setv self.context.application-key-update-requested False)
        (wait/a! (.write self.next-layer (.encrypt-key-update self.context.client-application-encryptor request)))))

    (defn/a! tls13-write-record [self type content]
      (ignore
        (when self.context.application-key-update-requested
          (.tls13-write-key-update self))
        (wait/a! (.write self.next-layer (.encrypt-record self.context.client-application-encryptor type content)))))

    (defn/a! real-read [self]
      (while True
        (let [#(type content) (wait/a! (.tls13-read-record self))]
          (match type
                 ContentType.application-data (return content)
                 ContentType.alert (let [#(level description) (Alert.unpack content)]
                                     (if (= #(level description) #(AlertLevel.warning AlertDescription.close-notify))
                                         (return b"")
                                         (raise (RuntimeError description.name))))
                 ContentType.handshake (let [#(msg-type msg-data) (Handshake.unpack content)]
                                         (match msg-type
                                                HandshakeType.new-session-ticket (.recv-new-session-ticket self.context msg-data)
                                                HandshakeType.key-update         (.recv-key-update         self.context msg-data)
                                                _ (raise RuntimeError)))
                 _ (raise RuntimeError)))))

    (defn/a! real-write [self b]
      (ignore (wait/a! (.tls13-write-record self ContentType.application-data b))))

    (defn/a! shutdown [self]
      (ignore (wait/a! (.tls13-write-record self ContentType.alert (Alert.pack #(AlertLevel.warning AlertDescription.close-notify))))))))

(do/a!
  (defclass (name/a! TLS13Connector) [(name/a! Handshaker)]
    (defn __init__ [self context #** kwargs]
      (.__init__ (super) #** kwargs)
      (setv self.context context))

    (defn/a! flush-handshake-write-buffer [self next-stream]
      (ignore
        (when self.context.handshake-write-buffer
          (wait/a! (.write next-stream (.readall self.context.handshake-write-buffer)))
          (wait/a! (.flush next-stream)))))

    (defn/a! real-handshake [self next-stream]
      (.send-client-hello self.context)
      (wait/a! (.flush-handshake-write-buffer self next-stream))
      (while (!= self.context.status TLS13Status.CONNECTED)
        (let [#(type version content) (wait/a! (.read-loop next-stream Record.read))]
          (.recv-record self.context type version content))
        (wait/a! (.flush-handshake-write-buffer self next-stream)))
      ((name/a! TLS13Stream) :context self.context :next-layer next-stream))))

(export
  :objects [SyncTLS13Stream AsyncTLS13Stream SyncTLS13Connector AsyncTLS13Connector])
