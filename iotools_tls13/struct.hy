;;; RFC 8446 TLS 1.3
;;; RFC 6066 TLS Extensions
;;; RFC 7301 TLS ALPN Extensions

(require
  dash *
  iotools *)

(import
  dash *
  dash.strtools :as s
  enum [IntEnum]
  iotools *
  iotools.proto.base *)

(defclass IntEnumStruct [Struct IntEnum]
  (defn [classmethod] read [cls reader]
    (let [v (int-unpack (.readexactly reader cls.len))]
      (try (cls v) (except [ValueError] v))))
  (defn [classmethod] write [cls writer it]
    (.write writer (int-pack it cls.len))))

(defclass ByteEnum [IntEnumStruct]
  (defn __init-subclass__ [cls #* args #** kwargs]
    (.__init-subclass__ (super) #* args #** kwargs)
    (setv cls.len 1)))

(defclass ShortEnum [IntEnumStruct]
  (defn __init-subclass__ [cls #* args #** kwargs]
    (.__init-subclass__ (super) #* args #** kwargs)
    (setv cls.len 2)))


;;; consts

(setv HelloRetryRequestRandom
      (bytes.fromhex "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C"))

(setv ServerContextString b"TLS 1.3, server CertificateVerify"
      ClientContextString b"TLS 1.3, client CertificateVerify"
      ServerContextPrefix (+ (* 64 b"\x20") ServerContextString b"\x00")
      ClientContextPrefix (+ (* 64 b"\x20") ClientContextString b"\x00"))

(setv DerivedLabel           b"tls13 derived"
      ClientHandshakeLabel   b"tls13 c hs traffic"
      ServerHandshakeLabel   b"tls13 s hs traffic"
      ClientApplicationLabel b"tls13 c ap traffic"
      ServerApplicationLabel b"tls13 s ap traffic"
      FinishedLabel          b"tls13 finished"
      KeyUpdateLabel         b"tls13 traffic upd"
      KeyLabel               b"tls13 key"
      IVLabel                b"tls13 iv")


;;; compatibility

(defclass ProtocolVersion [ShortEnum]
  (setv SSL30 0x0300
        TLS10 0x0301
        TLS11 0x0302
        TLS12 0x0303
        TLS13 0x0304))

(defstruct ProtocolVersionList
  [vbytes :len 1 :struct ProtocolVersion :many True])

(defclass ChangeCipherSpec [ByteEnum]
  (setv change-cipher-spec 1))

(defclass CompressionMethod [ByteEnum]
  (setv null 0))

(defstruct CompressionMethodList
  [vbytes :len 1 :struct CompressionMethod :many True])


;;; B.1 record layer

(defclass ContentType [ByteEnum]
  (setv invalid             0
        change-cipher-spec 20
        alert              21
        handshake          22
        application-data   23
        heartbeat          24))

(defstruct Plaintext
  [[type ContentType]
   [legacy-record-version ProtocolVersion]
   [fragment [vbytes :len 2]]])

(defstruct Ciphertext
  [[opaque-type [struct
                 :spec ContentType
                 :to-validate (= it ContentType.application-data)]]
   [legacy-record-version [struct
                           :spec ProtocolVersion
                           :to-validate (= it ProtocolVersion.TLS12)]]
   [encrypted-record [vbytes :len 2]]])

(defstruct RecordHeader
  [[type ContentType]
   [version ProtocolVersion]
   [length [int :len 2]]])

(defstruct Record
  [[type ContentType]
   [version ProtocolVersion]
   [content [vbytes :len 2]]])

(defclass InnerPlaintext [Struct]
  (defn [staticmethod] read [reader]
    (let [data (doto (.readall reader :clear False)
                     (s.rstrip b"\x00"))
          #(content type) #((cut data -1) (get data -1))]
      (try
        (setv type (ContentType type))
        (except [ValueError]))
      #(type content)))

  (defn [staticmethod] write [writer it]
    (let [#(type content) it]
      (.write writer content)
      (.write writer (int-pack type 1)))))


;;; B.2 alert messages

(defclass AlertLevel [ByteEnum]
  (setv warning 1 fatal 2))

(defclass AlertDescription [ByteEnum]
  (setv close-notify                          0
        unexpected-message                   10
        bad-record-mac                       20
        decryption-failed-RESERVED           21
        record-overflow                      22
        decompression-failure-RESERVED       30
        handshake-failure                    40
        no-certificate-RESERVED              41
        bad-certificate                      42
        unsupported-certificate              43
        certificate-revoked                  44
        certificate-expired                  45
        certificate-unknown                  46
        illegal-parameter                    47
        unknown-ca                           48
        access-denied                        49
        decode-error                         50
        decrypt-error                        51
        export-restriction-RESERVED          60
        protocol-version                     70
        insufficient-security                71
        internal-error                       80
        inappropriate-fallback               86
        user-canceled                        90
        no-renegotiation-RESERVED           100
        missing-extension                   109
        unsupported-extension               110
        certificate-unobtainable-RESERVED   111
        unrecognized-name                   112
        bad-certificate-status-response     113
        bad-certificate-hash-value-RESERVED 114
        unknown-psk-identity                115
        certificate-required                116
        no-application-protocol             120))

(defstruct Alert
  [[level AlertLevel]
   [description AlertDescription]])


;;; B.3 handshake protocol

(defclass HandshakeType [ByteEnum]
  (setv hello-request-RESERVED          0
        client-hello                    1
        server-hello                    2
        hello-verify-request-RESERVED   3
        new-session-ticket              4
        end-of-early-data               5
        hello-retry-request-RESERVED    6
        encrypted-extensions            8
        certificate                    11
        server-key-exchange-RESERVED   12
        certificate-request            13
        server-hello-done-RESERVED     14
        certificate-verify             15
        client-key-exchange-RESERVED   16
        finished                       20
        certificate-url-RESERVED       21
        certificate-status-RESERVED    22
        supplemental-data-RESERVED     23
        key-update                     24
        message-hash                  254))

(defstruct Handshake
  [[msg-type HandshakeType]
   [msg-data [vbytes :len 3]]])


;;; B.3.1. key exchange messages

(defstruct ClientHello
  [[legacy-version [struct
                    :spec ProtocolVersion
                    :to-validate (= it ProtocolVersion.TLS12)]]
   [random [bytes :len 32]]
   [legacy-session-id [vbytes :len 1]]
   [cipher-suites CipherSuiteList]
   [legacy-compression-methods CompressionMethodList]
   [extensions ExtensionList]])

(defstruct ServerHello
  [[legacy-version [struct
                    :spec ProtocolVersion
                    :to-validate (= it ProtocolVersion.TLS12)]]
   [random [bytes :len 32]]
   [legacy-session-id-echo [vbytes :len 1]]
   [cipher-suite CipherSuite]
   [legacy-compression-method [struct
                               :spec CompressionMethod
                               :to-validate (= it CompressionMethod.null)]]
   [extensions ExtensionList]])

(defstruct Extension
  [[extension-type ExtensionType]
   [extension-data [vbytes :len 2]]])

(defstruct ExtensionList
  [vbytes :len 2 :struct Extension :many True])

(defclass ExtensionType [ShortEnum]
  (setv server-name                             0
        max-fragment-length                     1
        status-request                          5
        supported-groups                       10
        signature-algorithms                   13
        use-srtp                               14
        heartbeat                              15
        application-layer-protocol-negotiation 16
        signed-certificate-timestamp           18
        client-certificate-type                19
        server-certificate-type                20
        padding                                21
        pre-shared-key                         41
        early-data                             42
        supported-versions                     43
        cookie                                 44
        psk-key-exchange-modes                 45
        certificate-authorities                47
        oid-filters                            48
        post-handshake-auth                    49
        signature-algorithms-cert              50
        key-share                              51))

(defstruct KeyShareEntry
  [[group NamedGroup]
   [key-exchange [vbytes :len 2]]])

(defstruct KeyShareEntryList
  [vbytes :len 2 :struct KeyShareEntry :many True])

(defstruct KeyShareClientHello KeyShareEntryList)
(defstruct KeyShareHelloRetryRequest NamedGroup)
(defstruct KeyShareServerHello KeyShareEntry)

(defstruct UncompressedPointRepresentationP256
  [[legacy-form [int :len 1 :to-validate (= it 4)]]
   [#(X Y) [list :len 2 :spec [bytes :len 32]]]])

(defstruct UncompressedPointRepresentationP384
  [[legacy-form [int :len 1 :to-validate (= it 4)]]
   [#(X Y) [list :len 2 :spec [bytes :len 48]]]])

(defstruct UncompressedPointRepresentationP512
  [[legacy-form [int :len 1 :to-validate (= it 4)]]
   [#(X Y) [list :len 2 :spec [bytes :len 66]]]])

(defclass PskKeyExchangeMode [ByteEnum]
  (setv psk-ke 0 psk-dhe-ke 1))

(defstruct PskKeyExchangeModeList
  [vbytes :len 1 :struct PskKeyExchangeMode :many True])

(defstruct PskKeyExchangeModes PskKeyExchangeModeList)

(defstruct EarlyDataIndicationNewSessionTicket [int :len 4])
(defstruct EarlyDataIndicationClientHello [const :const None])
(defstruct EarlyDataIndicationEncryptedExtensions [const :const None])

(defstruct PskIdentity
  [[identity [vbytes :len 2]]
   [obfuscated-ticket-age [int :len 4]]])

(defstruct PskIdentityList
  [vbytes :len 2 :struct PskIdentity :many True])

(defstruct PskBinderEntry [vbytes :len 1])

(defstruct PskBinderEntryList
  [vbytes :len 1 :struct PskBinderEntry :many True])

(defstruct OfferedPsks
  [[identities PskIdentityList]
   [binders PskBinderEntryList]])

(defstruct PreSharedKeyExtensionClientHello OfferedPsks)
(defstruct PreSharedKeyExtensionServerHello [int :len 2])


;;; B.3.1.1. version extension

(defstruct SupportedVersionsClientHello ProtocolVersionList)
(defstruct SupportedVersionsServerHello ProtocolVersion)


;;; B.3.1.2. cookie extension

(defstruct Cookie [vbytes :len 2])


;;; B.3.1.3. signature algorithm extension

(defclass SignatureScheme [ShortEnum]
  (setv rsa-pkcs1-sha256       0x0401
        rsa-pkcs1-sha384       0x0501
        rsa-pkcs1-sha512       0x0601
        ecdsa-secp256r1-sha256 0x0403
        ecdsa-secp384r1-sha384 0x0503
        ecdsa-secp521r1-sha512 0x0603
        rsa-pss-rsae-sha256    0x0804
        rsa-pss-rsae-sha384    0x0805
        rsa-pss-rsae-sha512    0x0806
        ed25519                0x0807
        ed448                  0x0808
        rsa-pss-pss-sha256     0x0809
        rsa-pss-pss-sha384     0x080a
        rsa-pss-pss-sha512     0x080b
        rsa-pkcs1-sha1         0x0201
        ecdsa-sha1             0x0203))

(defstruct SignatureSchemeList
  [vbytes :len 2 :struct SignatureScheme :many True])


;;;  B.3.1.4. supported groups extension

(defclass NamedGroup [ShortEnum]
  (setv secp256r1 0x0017
        secp384r1 0x0018
        secp521r1 0x0019
        x25519    0x001d
        x448      0x001e
        ffdhe2048 0x0100
        ffdhe3072 0x0101
        ffdhe4096 0x0102
        ffdhe6144 0x0103
        ffdhe8192 0x0104))

(defstruct NamedGroupList
  [vbytes :len 2 :struct NamedGroup :many True])


;;; B.3.2. server parameters messages

(defstruct DistinguishedName [vbytes :len 2])

(defstruct DistinguishedNameList
  [vbytes :len 2 :struct DistinguishedName :many True])

(defstruct CertificateAuthoritiesExtension DistinguishedNameList)

(defstruct OIDFilter
  [[certificate-extension-oid [vbytes :len 1]]
   [certificate-extension-values [vbytes :len 2]]])

(defstruct OIDFilterList
  [vbytes :len 2 :struct OIDFilter :many True])

(defstruct OIDFilerExtension OIDFilterList)

(defstruct PostHandshakeAuth [const :const None])

(defstruct EncryptedExtensions ExtensionList)

(defstruct CertificateRequest
  [[certificate-request-context [vbytes :len 1]]
   [extensions ExtensionList]])


;;; B.3.3. authentication messages

(defclass CertificateType [ByteEnum]
  (setv X509             0
        OpenPGP-RESERVED 1
        RawPublicKey     2))

(defstruct CertificateEntry
  [[cert-data [vbytes :len 3]]
   [extensions ExtensionList]])

(defstruct CertificateEntryList
  [vbytes :len 3 :struct CertificateEntry :many True])

(defstruct Certificate
  [[certificate-request-context [vbytes :len 1]]
   [certificate-list CertificateEntryList]])

(defstruct CertificateVerify
  [[algorithm SignatureScheme]
   [signature [vbytes :len 2]]])

(defstruct Finished [all])


;;; B.3.4. ticket establishment

(defstruct NewSessionTicket
  [[ticket-lifetime [int :len 4]]
   [ticket-age-add [int :len 4]]
   [ticket-nonce [vbytes :len 1]]
   [ticket [vbytes :len 2]]
   [extensions ExtensionList]])


;;; updating keys

(defstruct EndOfEarlyData [const :const None])

(defclass KeyUpdateRequest [ByteEnum]
  (setv update-not-request 0 update-requested 1))

(defstruct KeyUpdate KeyUpdateRequest)


;;; B.4. cipher suites

(defclass CipherSuite [ShortEnum]
  (setv TLS-AES-128-GCM-SHA256       0x1301
        TLS-AES-256-GCM-SHA384       0x1302
        TLS-CHACHA20-POLY1305-SHA256 0x1303
        TLS-AES-128-CCM-SHA256       0x1304
        TLS-AES-128-CCM-8-SHA256     0x1305))

(defstruct CipherSuiteList
  [vbytes :len 2 :struct CipherSuite :many True])


;;; 6066.3. server name indication

(defclass NameType [ByteEnum]
  (setv host-name 0))

(defstruct HostName
  [vbytes :len 2 :from (s.encode it) :to (s.decode it)])

(defstruct ServerNameHost
  [[name-type [struct
               :spec NameType
               :to-validate (= it NameType.host-name)]]
   [name HostName]])

(defstruct ServerNameHostList
  [vbytes :len 2 :struct ServerNameHost :many True])


;;; 7301.3.1. the alpn extension

(defstruct ProtocolName
  [vbytes
   :len 1
   :from (s.encode it)
   :to (s.decode it)])

(defstruct ProtocolNameList
  [vbytes :len 2 :struct ProtocolName :many True])
