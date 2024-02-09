(require
  dash *
  iotools *)

(import
  dash *
  dash.strtools :as s
  enum
  functools [cache]
  random [randbytes]
  time
  datetime
  cryptography [x509]
  cryptography.hazmat.primitives.hashes [Hash SHA256 SHA384 SHA512]
  cryptography.hazmat.primitives.hmac [HMAC]
  cryptography.hazmat.primitives.kdf.hkdf [HKDFExpand]
  cryptography.hazmat.primitives.ciphers.aead [ChaCha20Poly1305 AESGCM AESCCM]
  cryptography.hazmat.primitives.asymmetric.rsa [RSAPublicKey RSAPrivateKey]
  cryptography.hazmat.primitives.asymmetric.ec [ECDH ECDSA EllipticCurvePublicKey EllipticCurvePrivateKey
                                                SECP256R1 SECP384R1 SECP521R1 generate-private-key :as ec-generate-private-key]
  cryptography.hazmat.primitives.asymmetric.ed25519 [Ed25519PrivateKey Ed25519PublicKey]
  cryptography.hazmat.primitives.asymmetric.ed448 [Ed448PrivateKey Ed448PublicKey]
  cryptography.hazmat.primitives.asymmetric.x25519 [X25519PrivateKey X25519PublicKey]
  cryptography.hazmat.primitives.asymmetric.x448 [X448PrivateKey X448PublicKey]
  cryptography.hazmat.primitives.asymmetric.padding [PSS PKCS1v15 MGF1]
  cryptography.hazmat.primitives.serialization [Encoding PublicFormat]
  certifi
  iotools *
  iotools-tls13.struct *)



(defn [cache] load-cafile [[cafile None]]
  (unless cafile
    (setv cafile (certifi.where)))
  (with [f (open cafile "rb")]
    (let [certificates (x509.load-pem-x509-certificates (.read f))]
      #((frozenset certificates) (x509.verification.Store certificates)))))

(defclass ServerVerifier []
  (defn __init__ [self hostname [store None] [time None]]
    (when (or (none? store) (str? store) (bytes? store))
      (setv store (load-cafile store)))
    (unless time
      (setv time (datetime.datetime.now datetime.timezone.utc)))
    (let [#(certificates store) store]
      (setv self.certificates certificates
            self.chain-verifier (-> (x509.verification.PolicyBuilder)
                                    (.store store)
                                    (.time time)
                                    (.build-server-verifier (x509.DNSName hostname))))))

  (defn verify [self leaf intermediates]
    (when (and (not intermediates) (in leaf self.certificates)) ; self signed certificate
      (return [leaf]))
    (.verify self.chain-verifier leaf intermediates)))



(defclass SignatureVerifier []
  (setv public-key-type None)

  (defn __init__ [self public-key]
    (unless (isinstance public-key self.public-key-type)
      (raise RuntimeError))
    (setv self.public-key public-key))

  (defn verify [self signature data]
    (raise NotImplementedError)))

(defclass EdSignatureVerifier [SignatureVerifier]
  (defn verify [self signature data]
    (.verify self.public-key signature data)))

(defclass Ed25519SignatureVerifier [EdSignatureVerifier] (setv public-key-type Ed25519PublicKey))
(defclass Ed448SignatureVerifier   [EdSignatureVerifier] (setv public-key-type Ed448PublicKey))

(defclass ECSignatureVerifier [SignatureVerifier]
  (setv public-key-type EllipticCurvePublicKey)
  (setv algorithm None)

  (defn verify [self signature data]
    (.verify self.public-key signature data self.algorithm)))

(defclass SECP256R1SignatureVerifier [ECSignatureVerifier] (setv algorithm (ECDSA (SHA256))))
(defclass SECP384R1SignatureVerifier [ECSignatureVerifier] (setv algorithm (ECDSA (SHA384))))
(defclass SECP521R1SignatureVerifier [ECSignatureVerifier] (setv algorithm (ECDSA (SHA512))))

(defclass RSASignatureVerifier [SignatureVerifier]
  (setv public-key-type RSAPublicKey)
  (setv #(padding algorithm) #(None None))

  (defn verify [self signature data]
    (.verify self.public-key signature data self.padding self.algorithm)))

(defclass RSAPSSSHA256SignatureVerifier [RSASignatureVerifier]
  (setv #(padding algorithm) #((PSS :mgf (MGF1 (SHA256)) :salt-length PSS.DIGEST-LENGTH) (SHA256))))
(defclass RSAPSSSHA384SignatureVerifier [RSASignatureVerifier]
  (setv #(padding algorithm) #((PSS :mgf (MGF1 (SHA384)) :salt-length PSS.DIGEST-LENGTH) (SHA384))))
(defclass RSAPSSSHA512SignatureVerifier [RSASignatureVerifier]
  (setv #(padding algorithm) #((PSS :mgf (MGF1 (SHA512)) :salt-length PSS.DIGEST-LENGTH) (SHA512))))

(defclass RSAPKCS1SHA256SignatureVerifier [RSASignatureVerifier] (setv #(padding algorithm) #((PKCS1v15) (SHA256))))
(defclass RSAPKCS1SHA384SignatureVerifier [RSASignatureVerifier] (setv #(padding algorithm) #((PKCS1v15) (SHA384))))
(defclass RSAPKCS1SHA512SignatureVerifier [RSASignatureVerifier] (setv #(padding algorithm) #((PKCS1v15) (SHA512))))

(setv signature-algorithm-dict
      {SignatureScheme.ed25519                Ed25519SignatureVerifier
       SignatureScheme.ed448                  Ed448SignatureVerifier
       SignatureScheme.ecdsa-secp256r1-sha256 SECP256R1SignatureVerifier
       SignatureScheme.ecdsa-secp384r1-sha384 SECP384R1SignatureVerifier
       SignatureScheme.ecdsa-secp521r1-sha512 SECP521R1SignatureVerifier
       SignatureScheme.rsa-pss-rsae-sha256    RSAPSSSHA256SignatureVerifier
       SignatureScheme.rsa-pss-rsae-sha384    RSAPSSSHA384SignatureVerifier
       SignatureScheme.rsa-pss-rsae-sha512    RSAPSSSHA512SignatureVerifier
       SignatureScheme.rsa-pkcs1-sha256       RSAPKCS1SHA256SignatureVerifier
       SignatureScheme.rsa-pkcs1-sha384       RSAPKCS1SHA384SignatureVerifier
       SignatureScheme.rsa-pkcs1-sha512       RSAPKCS1SHA512SignatureVerifier})



(setv AESCCM8 (-partial AESCCM :tag-length 8))

;;; [hash-algorithm hash-block-size hash-digest-size aead-algorithm aead-key-size aead-iv-size aead-tag-size]
(setv cipher-suite-dict
      {CipherSuite.TLS-AES-128-GCM-SHA256       [(SHA256)  64 32 AESGCM           16 12 16]
       CipherSuite.TLS-AES-256-GCM-SHA384       [(SHA384) 128 48 AESGCM           32 12 16]
       CipherSuite.TLS-CHACHA20-POLY1305-SHA256 [(SHA256)  64 32 ChaCha20Poly1305 32 12 16]
       CipherSuite.TLS-AES-128-CCM-SHA256       [(SHA256)  64 32 AESCCM           16 12 16]
       CipherSuite.TLS-AES-128-CCM-8-SHA256     [(SHA256)  64 32 AESCCM8          16 12  8]})

(defstruct HKDFLabel
  [[length [int :len 2]]
   [label [vbytes :len 1]]
   [context [vbytes :len 1]]])

(defclass CipherSuiteContextMixin []
  (defn init-cipher-suite-context [self cipher-suite]
    (let [#(hash-algorithm hash-block-size hash-digest-size aead-algorithm aead-key-size aead-iv-size aead-tag-size)
          (get cipher-suite-dict cipher-suite)]
      (setv self.hash-algorithm   hash-algorithm
            self.hash-block-size  hash-block-size
            self.hash-digest-size hash-digest-size
            self.aead-algorithm   aead-algorithm
            self.aead-key-size    aead-key-size
            self.aead-iv-size     aead-iv-size
            self.aead-tag-size    aead-tag-size)))

  (defn hash [self data]
    (let [h (Hash self.hash-algorithm)]
      (if (bytes? data)
          (.update h data)
          (--each data (.update h it)))
      (.finalize h)))

  (defn hmac [self key data]
    (let [h (HMAC key self.hash-algorithm)]
      (if (bytes? data)
          (.update h data)
          (--each data (.update h it)))
      (.finalize h)))

  (defn hkdf-extract [self salt ikm]
    (.hmac self salt ikm))

  (defn hkdf-expand [self prk info length]
    (-> (HKDFExpand self.hash-algorithm length info)
        (.derive prk)))

  (defn hkdf-expand-label [self secret label context length]
    (.hkdf-expand self secret (HKDFLabel.pack #(length label context)) length))

  (defn hkdf-derive-secret [self secret label messages]
    (.hkdf-expand-label self secret label (.hash self messages) self.hash-digest-size)))



(defclass Cryptor []
  (defn __init__ [self context secret]
    (setv self.context context
          self.secret secret)
    (.expand-key self))

  (defn update-key [self]
    (setv self.secret (.hkdf-expand-label self.context self.secret KeyUpdateLabel b"" self.context.hash-digest-size))
    (.expand-key self))

  (defn expand-key [self]
    (setv self.key (.hkdf-expand-label self.context self.secret KeyLabel b"" self.context.aead-key-size)
          self.iv (.hkdf-expand-label self.context self.secret IVLabel  b"" self.context.aead-iv-size)
          self.aead (self.context.aead-algorithm self.key)
          self.sequence 0))

  (defn next-iv [self]
    (let [iv (bytes (gfor #(c1 c2) (zip self.iv (int-pack self.sequence self.context.aead-iv-size)) (^ c1 c2)))]
      (+= self.sequence 1)
      iv))

  (defn encrypt [self plaintext aad]
    (.encrypt self.aead (.next-iv self) plaintext aad))

  (defn decrypt [self ciphertext aad]
    (.decrypt self.aead (.next-iv self) ciphertext aad))

  (defn encrypt-record [self type content]
    (let [inner-plaintext (InnerPlaintext.pack #(type content))
          header (RecordHeader.pack #(ContentType.application-data ProtocolVersion.TLS12 (+ (len inner-plaintext) self.context.aead-tag-size)))
          encrypted-record (.encrypt self inner-plaintext header)]
      (+ header encrypted-record)))

  (defn decrypt-record [self encrypted-record]
    (let [header (RecordHeader.pack #(ContentType.application-data ProtocolVersion.TLS12 (len encrypted-record)))
          inner-plaintext (.decrypt self encrypted-record header)
          #(type content) (InnerPlaintext.unpack inner-plaintext)]
      #(type content)))

  (defn encrypt-key-update [self [request False]]
    (let [key-update-request (if request KeyUpdateRequest.update-requested KeyUpdateRequest.update-not-request)
          key-update (Handshake.pack #(HandshakeType.key-update (KeyUpdate.pack key-update-request)))
          encrypted-key-update (.encrypt-record self ContentType.handshake key-update)]
      (.update-key self)
      encrypted-key-update)))



(defclass KeyExchanger []
  (defn [property] public-key [self]
    (raise NotImplementedError))

  (defn exchange [self pk]
    (raise NotImplementedError)))

(defclass XKeyExchanger [KeyExchanger]
  (setv algorithm #(None None))

  (defn __init__ [self]
    (let [#(PrivateKey _) self.algorithm]
      (setv self.private-key (PrivateKey.generate))))

  (defn [property] public-key [self]
    (.public-bytes-raw (.public-key self.private-key)))

  (defn exchange [self pk]
    (let [#(_ PublicKey) self.algorithm]
      (.exchange self.private-key (PublicKey.from-public-bytes pk)))))

(defclass X25519KeyExchanger [XKeyExchanger] (setv algorithm #(X25519PrivateKey X25519PublicKey)))
(defclass X448KeyExchanger   [XKeyExchanger] (setv algorithm #(X448PrivateKey   X448PublicKey)))

(defclass ECKeyExchanger [KeyExchanger]
  (setv #(algorithm curve) #((ECDH) None))

  (defn __init__ [self]
    (setv self.private-key (ec-generate-private-key self.curve)))

  (defn [property] public-key [self]
    (-> self.private-key
        (.public-key)
        (.public-bytes :encoding Encoding.X962 :format PublicFormat.UncompressedPoint)))

  (defn exchange [self pk]
    (->> (EllipticCurvePublicKey.from-encoded-point self.curve pk)
         (.exchange self.private-key self.algorithm))))

(defclass SECP256R1KeyExchanger [ECKeyExchanger] (setv curve (SECP256R1)))
(defclass SECP384R1KeyExchanger [ECKeyExchanger] (setv curve (SECP384R1)))
(defclass SECP521R1KeyExchanger [ECKeyExchanger] (setv curve (SECP521R1)))

(setv named-group-dict
      {NamedGroup.x25519    X25519KeyExchanger
       NamedGroup.x448      X448KeyExchanger
       NamedGroup.secp256r1 SECP256R1KeyExchanger
       NamedGroup.secp384r1 SECP384R1KeyExchanger
       NamedGroup.secp521r1 SECP521R1KeyExchanger})

(defclass ClientShares []
  (defn __init__ [self named-groups]
    (setv self.shares (dict (--map #(it ((get named-group-dict it))) named-groups))))

  (defn [property] public-keys [self]
    (->> (-items self.shares)
         (--map (let [#(group ke) it] #(group ke.public-key)))
         list))

  (defn exchange [self selected-named-group server-share]
    (.exchange (get self.shares selected-named-group) server-share)))



(defclass TLS13Ticket []
  (setv binder-label None)

  (defn __init__ [self identity pre-shared-key [max-early-data-size None]]
    (when (str? identity)
      (setv identity (s.encode identity)))
    (setv self.identity identity
          self.pre-shared-key pre-shared-key
          self.max-early-data-size max-early-data-size))

  (defn [property] obfuscated-ticket-age [self] 0)

  (defn [property] expired [self] False))

(defclass TLS13ExternalTicket [TLS13Ticket]
  (setv binder-label ExternalBinderLabel))

(defclass TLS13ResumptionTicket [TLS13Ticket]
  (setv binder-label ResumptionBinderLabel)

  (defn __init__ [self identity pre-shared-key create-time expire-time obfuscated-ticket-age-add [max-early-data-size None]]
    (.__init__ (super) identity pre-shared-key max-early-data-size)
    (setv self.create-time create-time
          self.expire-time expire-time
          self.obfuscated-ticket-age-add obfuscated-ticket-age-add))

  (defn [property] ticket-time [self]
    (- (time.time) self.create-time))

  (defn [property] obfuscated-ticket-age [self]
    (& (+ (int (* self.ticket-time 1000)) self.obfuscated-ticket-age-add) 0xffffffff))

  (defn [property] expired [self]
    (> (time.time) self.expire-time)))



(defclass TLS13Status [enum.Enum]
  (setv START         (enum.auto)
        WAIT-SH       (enum.auto)
        WAIT-CCS-EE   (enum.auto)
        WAIT-EE       (enum.auto)
        WAIT-CERT-CR  (enum.auto)
        WAIT-CERT     (enum.auto)
        WAIT-CV       (enum.auto)
        WAIT-FINISHED (enum.auto)
        CONNECTED     (enum.auto)))

(defclass TLS13Context [CipherSuiteContextMixin]
  (defn __init__ [self
                  server-hostname
                  [ticket None]
                  [early-data b""]
                  [server-cafile None]
                  [server-verify True]
                  [application-protocols None]
                  [signature-algorithms (list signature-algorithm-dict)]
                  [cipher-suites (list cipher-suite-dict)]
                  [named-groups (list named-group-dict)]]
    (setv self.status TLS13Status.START
          self.server-hostname server-hostname
          self.ticket ticket
          self.early-data early-data
          self.server-cafile server-cafile
          self.server-verify server-verify
          self.application-protocols application-protocols
          self.signature-algorithms signature-algorithms
          self.cipher-suites cipher-suites
          self.named-groups named-groups
          self.client-random (randbytes 32)
          self.client-shares (ClientShares self.named-groups)
          self.handshake-messages (list)
          self.handshake-read-encrypted False
          self.handshake-write-buffer (Buffer)
          self.handshake-ticket-accepted False
          self.handshake-early-data-accepted False
          self.application-key-update-requested False))

  ;;; record

  (defn recv-record [self type version content]
    (when (and self.handshake-read-encrypted (!= type ContentType.change-cipher-spec))
      (unless (and (= type ContentType.application-data) (= version ProtocolVersion.TLS12))
        (raise RuntimeError))
      (setv #(type content) (.decrypt-record self.server-handshake-decryptor content)))
    (match type
           ContentType.handshake          (.recv-handshakes         self content)
           ContentType.change-cipher-spec (.recv-change-cipher-spec self content)
           ContentType.alert              (.recv-alert              self content)
           _ (raise RuntimeError)))

  ;; client hello, change cipher spec
  (defn send-plaintext [self type version content]
    (.write self.handshake-write-buffer (Plaintext.pack #(type version content))))

  ;; client finished
  (defn send-ciphertext [self type content]
    (.write self.handshake-write-buffer (.encrypt-record self.client-handshake-encryptor type content)))

  ;; early data, end of early data
  (defn send-early-ciphertext [self type content]
    (.write self.handshake-write-buffer (.encrypt-record self.client-early-encryptor type content)))

  ;; post handshake early data
  (defn send-application-ciphertext [self type content]
    (.write self.handshake-write-buffer (.encrypt-record self.client-application-encryptor type content)))

  ;;; alert

  (defn recv-alert [self alert]
    (let [#(level description) (Alert.unpack alert)]
      (raise (RuntimeError description.name))))

  ;;; change cipher spec

  (defn recv-change-cipher-spec [self change-cipher-spec]
    (unless (and (= self.status TLS13Status.WAIT-CCS-EE)
                 (= (ChangeCipherSpec.unpack change-cipher-spec) ChangeCipherSpec.change-cipher-spec))
      (raise RuntimeError))
    (setv self.status TLS13Status.WAIT-EE))

  (defn send-change-cipher-spec [self]
    (let [change-cipher-spec (ChangeCipherSpec.pack ChangeCipherSpec.change-cipher-spec)]
      (.send-plaintext self ContentType.change-cipher-spec ProtocolVersion.TLS12 change-cipher-spec)))

  ;;; handshake

  (defn recv-handshakes [self handshakes]
    (--each (Handshake.unpack-many handshakes)
            (let [#(msg-type msg-data) it]
              (.append self.handshake-messages (Handshake.pack #(msg-type msg-data)))
              ((match msg-type
                      HandshakeType.server-hello         self.recv-server-hello
                      HandshakeType.encrypted-extensions self.recv-encrypted-extensions
                      HandshakeType.certificate          self.recv-certificate
                      HandshakeType.certificate-verify   self.recv-certificate-verify
                      HandshakeType.finished             self.recv-finished
                      _ (raise RuntimeError))
                msg-data))))

  (defn [property] supported-versions-extension [self]
    #(ExtensionType.supported-versions (SupportedVersionsClientHello.pack [ProtocolVersion.TLS13])))

  (defn [property] signature-algorithms-extension [self]
    #(ExtensionType.signature-algorithms (SignatureSchemeList.pack self.signature-algorithms)))

  (defn [property] supported-groups-extension [self]
    #(ExtensionType.supported-groups (NamedGroupList.pack self.named-groups)))

  (defn [property] key-share-extension [self]
    #(ExtensionType.key-share (KeyShareClientHello.pack self.client-shares.public-keys)))

  (defn [property] server-name-extension [self]
    #(ExtensionType.server-name (ServerNameHostList.pack [#(NameType.host-name self.server-hostname)])))

  (defn [property] application-layer-protocol-negotiation-extension [self]
    #(ExtensionType.application-layer-protocol-negotiation (ProtocolNameList.pack self.application-protocols)))

  (defn [property] early-data-extension [self]
    #(ExtensionType.early-data b""))

  (defn [property] psk-key-exchange-modes-extension [self]
    #(ExtensionType.psk-key-exchange-modes (PskKeyExchangeModes.pack #(PskKeyExchangeMode.psk-dhe-ke))))

  (defn [property] pre-shared-key-extension [self]
    #(ExtensionType.pre-shared-key (PreSharedKeyExtensionClientHello.pack
                                     #([#(self.ticket.identity self.ticket.obfuscated-ticket-age)]
                                        [(bytes self.hash-digest-size)]))))

  (defn [property] extensions [self]
    (let [extensions (list)]
      (.append extensions self.supported-versions-extension)
      (.append extensions self.signature-algorithms-extension)
      (.append extensions self.supported-groups-extension)
      (.append extensions self.key-share-extension)
      (.append extensions self.server-name-extension)
      (when self.application-protocols
        (.append extensions self.application-layer-protocol-negotiation-extension))
      (when self.ticket
        (when self.early-data
          (.append extensions self.early-data-extension))
        (.append extensions self.psk-key-exchange-modes-extension)
        (.append extensions self.pre-shared-key-extension))
      extensions))

  (defn send-client-hello [self]
    (unless (= self.status TLS13Status.START)
      (raise RuntimeError))
    (setv self.status TLS13Status.WAIT-SH)

    (when self.ticket
      (setv self.selected-cipher-suite (get self.cipher-suites 0))
      (.init-cipher-suite-context self self.selected-cipher-suite)
      (setv self.early-secret (.hkdf-extract self (bytes self.hash-digest-size) self.ticket.pre-shared-key)))

    (let [client-hello (Handshake.pack
                         #(HandshakeType.client-hello
                            (ClientHello.pack
                              #(ProtocolVersion.TLS12      ; legacy version
                                 self.client-random        ; random
                                 b""                       ; legacy session id
                                 self.cipher-suites        ; cipher suites
                                 #(CompressionMethod.null) ; legacy compression method
                                 self.extensions           ; extensions
                                 ))))]
      (when self.ticket
        (let [truncated-client-hello (cut client-hello (- (+ self.hash-digest-size 3)))]
          (setv self.binder-key (.hkdf-derive-secret self self.early-secret self.ticket.binder-label b"")
                self.binder-verify-key (.hkdf-expand-label self self.binder-key FinishedLabel b"" self.hash-digest-size)
                self.binder-verify-data (.hmac self self.binder-verify-key (.hash self truncated-client-hello)))
          (setv client-hello (+ truncated-client-hello (PskBinderEntryList.pack [self.binder-verify-data])))))
      (.append self.handshake-messages client-hello)
      (.send-plaintext self ContentType.handshake ProtocolVersion.TLS12 client-hello))

    (when (and self.ticket self.early-data)
      (when (and self.ticket.max-early-data-size (> (len self.early-data) self.ticket.max-early-data-size))
        (raise RuntimeError))
      (setv self.client-early-secret (.hkdf-derive-secret self self.early-secret ClientEarlyLabel self.handshake-messages)
            self.client-early-encryptor (Cryptor self self.client-early-secret))
      (.send-early-data self)))

  (defn send-early-data [self]
    (.send-early-ciphertext self ContentType.application-data self.early-data))

  (defn recv-server-hello [self server-hello]
    (unless (= self.status TLS13Status.WAIT-SH)
      (raise RuntimeError))
    (setv self.status TLS13Status.WAIT-CCS-EE)

    (let [#(legacy-version random legacy-session-id-echo cipher-suite legacy-compression-method extensions) (ServerHello.unpack server-hello)
          extensions (dict extensions)
          selected-version (SupportedVersionsServerHello.unpack (get extensions ExtensionType.supported-versions))
          #(selected-named-group server-share) (KeyShareServerHello.unpack (get extensions ExtensionType.key-share))]
      (unless (and (= legacy-session-id-echo b"")
                   (= selected-version ProtocolVersion.TLS13)
                   (!= random HelloRetryRequestRandom)
                   (in cipher-suite self.cipher-suites)
                   (in selected-named-group self.named-groups))
        (raise RuntimeError))
      (when self.ticket
        (when-let [it (-get extensions ExtensionType.pre-shared-key)]
          (let [selected-identity (PreSharedKeyExtensionServerHello.unpack it)]
            (unless (and (= selected-identity 0) (= cipher-suite self.selected-cipher-suite))
              (raise RuntimeError))
            (setv self.handshake-ticket-accepted True))))
      (unless self.handshake-ticket-accepted
        (setv self.selected-cipher-suite cipher-suite)
        (.init-cipher-suite-context self self.selected-cipher-suite)
        (setv self.early-secret (.hkdf-extract self (bytes self.hash-digest-size) (bytes self.hash-digest-size))))
      (setv self.selected-named-group selected-named-group
            self.server-random random
            self.server-share server-share
            self.server-extensions extensions))

    (setv self.shared-secret (.exchange self.client-shares self.selected-named-group self.server-share)
          self.handshake-secret (.hkdf-extract self (.hkdf-derive-secret self self.early-secret DerivedLabel b"") self.shared-secret)
          self.client-handshake-secret (.hkdf-derive-secret self self.handshake-secret ClientHandshakeLabel self.handshake-messages)
          self.server-handshake-secret (.hkdf-derive-secret self self.handshake-secret ServerHandshakeLabel self.handshake-messages)
          self.client-handshake-encryptor (Cryptor self self.client-handshake-secret)
          self.server-handshake-decryptor (Cryptor self self.server-handshake-secret))

    (setv self.handshake-read-encrypted True))

  (defn recv-encrypted-extensions [self encrypted-extensions]
    (unless (in self.status #(TLS13Status.WAIT-CCS-EE TLS13Status.WAIT-EE))
      (raise RuntimeError))
    (setv self.status (if self.handshake-ticket-accepted TLS13Status.WAIT-FINISHED TLS13Status.WAIT-CERT-CR))
    (let [extensions (EncryptedExtensions.unpack encrypted-extensions)]
      (setv self.server-encrypted-extensions (dict extensions)))
    (when self.application-protocols
      (when-let [it (-get self.server-encrypted-extensions ExtensionType.application-layer-protocol-negotiation)]
        (let [#(selected-application-protocol) (ProtocolNameList.unpack it)]
          (unless (in selected-application-protocol self.application-protocols)
            (raise RuntimeError))
          (setv self.selected-application-protocol selected-application-protocol))))
    (when (and self.handshake-ticket-accepted self.early-data)
      (when (in ExtensionType.early-data self.server-encrypted-extensions)
        (setv self.handshake-early-data-accepted True))))

  (defn recv-certificate [self certificate]
    (unless (in self.status #(TLS13Status.WAIT-CERT-CR TLS13Status.WAIT-CERT))
      (raise RuntimeError))
    (setv self.status TLS13Status.WAIT-CV)
    (let [#(certificate-request-context certificate-list) (Certificate.unpack certificate)]
      (setv self.server-raw-certificates certificate-list
            self.server-certificates (->> self.server-raw-certificates
                                          (--map (let [#(cert-data extensions) it]
                                                   (x509.load-der-x509-certificate cert-data)))
                                          list))))

  (defn recv-certificate-verify [self certificate-verify]
    (unless (= self.status TLS13Status.WAIT-CV)
      (raise RuntimeError))
    (setv self.status TLS13Status.WAIT-FINISHED)
    (let [#(algorithm signature) (CertificateVerify.unpack certificate-verify)]
      (unless (in algorithm self.signature-algorithms)
        (raise RuntimeError))
      (setv self.server-signature-algorithm algorithm
            self.server-signature signature
            self.server-signature-context (.hash self (cut self.handshake-messages -1))
            self.server-signature-data (+ ServerContextPrefix self.server-signature-context)))
    (when self.server-verify
      (.verify-server self)))

  (defn verify-server [self]
    (let [#(leaf #* intermediates) self.server-certificates]
      (let [signature-verifier ((get signature-algorithm-dict self.server-signature-algorithm) (.public-key leaf))]
        (.verify signature-verifier self.server-signature self.server-signature-data))
      (let [server-verifier (ServerVerifier self.server-hostname :store self.server-cafile)]
        (.verify server-verifier leaf intermediates))))

  (defn recv-finished [self finished]
    (unless (= self.status TLS13Status.WAIT-FINISHED)
      (raise RuntimeError))
    (setv self.status TLS13Status.CONNECTED)

    (setv self.server-verify-key (.hkdf-expand-label self self.server-handshake-secret FinishedLabel b"" self.hash-digest-size)
          self.server-verify-data (.hmac self self.server-verify-key (.hash self (cut self.handshake-messages -1))))
    (unless (= finished self.server-verify-data)
      (raise RuntimeError))

    (setv self.master-secret (.hkdf-extract self (.hkdf-derive-secret self self.handshake-secret DerivedLabel b"") (bytes self.hash-digest-size))
          self.client-application-secret (.hkdf-derive-secret self self.master-secret ClientApplicationLabel self.handshake-messages)
          self.server-application-secret (.hkdf-derive-secret self self.master-secret ServerApplicationLabel self.handshake-messages)
          self.client-application-encryptor (Cryptor self self.client-application-secret)
          self.server-application-decryptor (Cryptor self self.server-application-secret))

    (when self.handshake-early-data-accepted
      (.send-end-of-early-data self))

    (setv self.client-verify-key (.hkdf-expand-label self self.client-handshake-secret FinishedLabel b"" self.hash-digest-size)
          self.client-verify-data (.hmac self self.client-verify-key (.hash self self.handshake-messages)))

    (.send-change-cipher-spec self)
    (.send-finished self)
    (when (and self.early-data (not self.handshake-early-data-accepted))
      (.send-post-handshake-early-data self)))

  (defn send-finished [self]
    (let [finished (Handshake.pack #(HandshakeType.finished self.client-verify-data))]
      (.append self.handshake-messages finished)
      (.send-ciphertext self ContentType.handshake finished)))

  (defn send-end-of-early-data [self]
    (let [end-of-early-data (Handshake.pack #(HandshakeType.end-of-early-data b""))]
      (.append self.handshake-messages end-of-early-data)
      (.send-early-ciphertext self ContentType.handshake end-of-early-data)))

  (defn send-post-handshake-early-data [self]
    (.send-application-ciphertext self ContentType.application-data self.early-data))

  (defn recv-key-update [self key-update]
    (unless (= self.status TLS13Status.CONNECTED)
      (raise RuntimeError))
    (let [key-update-request (KeyUpdate.unpack key-update)]
      (.update-key self.server-application-decryptor)
      (when (= key-update-request KeyUpdateRequest.update-requested)
        (setv self.application-key-update-requested True))))

  (defn recv-new-session-ticket [self new-session-ticket]
    (unless (= self.status TLS13Status.CONNECTED)
      (raise RuntimeError))
    (setv self.resumption-master-secret (.hkdf-derive-secret self self.master-secret ResumptionMasterLabel self.handshake-messages))
    (let [#(ticket-lifetime ticket-age-add ticket-nonce ticket extensions) (NewSessionTicket.unpack new-session-ticket)
          extensions (dict extensions)
          pre-shared-key (.hkdf-expand-label self self.resumption-master-secret ResumptionLabel ticket-nonce self.hash-digest-size)
          create-time (time.time)
          expire-time (+ (/ ticket-lifetime 1000) create-time)
          max-early-data-size None]
      (when-let [it (-get extensions ExtensionType.early-data)]
        (setv max-early-data-size (EarlyDataIndicationNewSessionTicket.unpack it)))
      (setv self.new-session-ticket (TLS13ResumptionTicket
                                      :identity ticket
                                      :pre-shared-key pre-shared-key
                                      :create-time create-time
                                      :expire-time expire-time
                                      :obfuscated-ticket-age-add ticket-age-add
                                      :max-early-data-size max-early-data-size)))))



(defclass TLS13Session []
  (defn __init__ [self
                  server-hostname
                  [ticket None]
                  [server-cafile None]
                  [server-verify True]
                  [application-protocol None]
                  [signature-algorithms (list signature-algorithm-dict)]
                  [cipher-suite CipherSuite.TLS-AES-128-GCM-SHA256]
                  [named-group NamedGroup.x25519]]
    (setv self.server-hostname server-hostname
          self.ticket ticket
          self.server-cafile server-cafile
          self.server-verify server-verify
          self.application-protocol application-protocol
          self.signature-algorithms signature-algorithms
          self.cipher-suite cipher-suite
          self.named-group named-group))

  (defn [classmethod] from-external [cls
                                     server-hostname
                                     [pre-shared-key-identity "psk"]
                                     [pre-shared-key None]
                                     #** kwargs]
    (cls :server-hostname server-hostname
         :ticket (when pre-shared-key (TLS13ExternalTicket pre-shared-key-identity pre-shared-key))
         #** kwargs))

  (defn [classmethod] from-context [cls context]
    (cls :server-hostname context.server-hostname
         :ticket (when (hasattr context "new_session_ticket") context.new-session-ticket)
         :server-cafile context.server-cafile
         :server-verify context.server-verify
         :application-protocol (when (hasattr context "selected_application_protocol") context.selected-application-protocol)
         :signature-algorithms context.signature-algorithms
         :cipher-suite context.selected-cipher-suite
         :named-group context.selected-named-group))

  (defn create-context [self #** kwargs]
    (TLS13Context
      :server-hostname self.server-hostname
      :ticket (when (and self.ticket (not self.ticket.expired)) self.ticket)
      :server-cafile self.server-cafile
      :server-verify self.server-verify
      :application-protocols (when self.application-protocol [self.application-protocol])
      :signature-algorithms self.signature-algorithms
      :cipher-suites [self.cipher-suite]
      :named-groups [self.named-group]
      #** kwargs)))



(export
  :objects [TLS13Status TLS13Context TLS13Session])
