(ns herd-node.circ
  (:require [cljs.core :as cljs]
            [cljs.nodejs :as node]
            [cljs.core.async :refer [chan <! >!]]
            [herd-node.log :as log]
            [herd-node.buf :as b]
            [herd-node.ntor :as hs]
            [herd-node.conns :as c]
            [herd-node.parse :as conv]
            [herd-node.crypto :as crypto]
            [herd-node.conn-mgr :as conn]
            [herd-node.dtls-comm :as dtls])
  (:require-macros [cljs.core.async.macros :as m :refer [go]]))

(declare from-relay-cmd from-cmd to-cmd
         create relay-begin relay-extend
         recv-destroy
         process)

;; General API FIXME:
;;  - should get rid of most conn/sockets in prototypes because explicitly using :f-hop & :b-hop ensures we are doing the right thing --> give direction instead.

;; * Notes from tor spec:
;;  - see section 5 for circ creation.
;;  - create2 will be used for ntor hs.
;;  - circ id: msb set to 1 when created on current node. otherwise 0.
;;  - will not be supporting create fast: tor spec: 221-stop-using-create-fast.txt
;;
;; * Extensions to tor spec:
;;
;;  - adding forward cell: ignores circ id, reads host & address from header and forwards.
;;
;;  - we will be using the following link specifiers:
;;   - 03 = ip4 4 | port 2 -> reliable (tcp) routed over udp & dtls
;;   - 04 = ip6 16 | port 2 -> reliable (tcp) routed over udp & dtls
;;   - 05 = ip6 16 | port 2 -> unreliable (udp) routed over dtls
;;   - 06 = ip6 16 | port 2 -> unreliable (udp) routed over dtls


;; role helpers ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn is? [role circ]
  (some #(= % role) (:roles circ)))

(defn is-not? [role circ]
  (every? #(not= % role) (:roles circ)))


;; circuit state management ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(def circuits (atom {}))

;; Functions to keep track of current circuits: adding, updating, removing.
;;
;; Circuit data description:
;;
;;
;; {:conn          The socket the circuit is attached to.
;;  :forward-hop   The next hop forward in the circuit. Another mix, or the
;;                 destination if we are the endpoint.
;;  :backward-hop  The previous hop in the circuit. Another mix, or a local
;;                 socket if we are the origin of the circuit.
;;  :path          The list of secrets we handshaked with nodes which we need
;;                 to use to encrypt data before sending it.
;;  :roles         Our role in the circuit. can be origin, mix, exit.
;;  :ctrl          A control channel used by path. used to know when
;;                 transaction are finished (send extend, receive extended:
;;                 notify on :ctrl)
;;  :dest-ctrl     A control channel for circuits, used to give the final
;;                 hop. subject to change. See create-* in path for usage.
;;  :mk-path-fn    A function to be called after a transaction. In pratice, it
;;                 usually just updates the :ctrl channel, see path.
;;  :path-dest     The destination of the path.
;;  :rdv           Optional, only if path is a rdv, contains rdv node data.}

(defn add [circ-id socket & [state]]
  ;; FIXME remove socket from there. this shall become :forward-hop.
  (assert (nil? (@circuits circ-id)) (str "could not create circuit, " circ-id " already exists"))
  (let [circs     (-> socket c/get-data :circuits)]
    (c/update-data socket [:circuits] (cons circ-id circs)))
  (swap! circuits merge {circ-id (merge state {:conn socket})}))

(defn update-data [circ keys subdata]
  (swap! circuits assoc-in (cons circ keys) subdata)
  circ)

(defn rm [circ]
  (let [circs (-> circ :conn c/get-data :circuits)]
    (c/update-data (:conn circ) [:circuits] (remove #(= % circ) circs)))
  (swap! circuits dissoc circ)
  circ)

(defn destroy [config circ]
  (when-let [c   (@circuits circ)]
    (recv-destroy config nil circ (b/new "because reasons"))
    (dtls/send-rm-mix-fp circ)
    (log/info "destroying circuit" circ)
    (rm circ)))

(defn destroy-from-socket [config s]
  (js/clearInterval (-> s c/get-data :rate-timer))
  (doseq [circ-id (-> s c/get-data :circuits)]
    (destroy config circ-id))
  (c/destroy s))

(defn get-all []
  @circuits)

(defn get-data [id]
  (@circuits id))

(defn gen-id [] ;; FIXME temporary, it might be interesting to use something that guarantees an answer instead of an infinite loop. yeah.
  (let [i (-> (node/require "crypto") (.randomBytes 4) (.readUInt32BE 0) (bit-clear 31))]
    (if (@circuits i)
      (recur)
      i)))


;; path management ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn get-path-enc [circ-data direction] ;; FIXME unused
  "Returns all the layers of encryption to be done on a
  circuit in the given direction."
  (filter identity (map #(-> % direction) (:path circ-data)))) ;; FIXME may need to reverse order with mux

(defn add-path-auth [id circ-data auth]
  "Add a new authentication for that circuit: handshake not yet completed"
  (update-data id [:path] (concat (:path circ-data) [{:auth auth}])))

(defn add-path-secret-to-last [config id circ-data secret]
  "After obtaining the shared secret, add it to complete the info
  added by add-path-auth."
  (let [l        (last (:path circ-data))
        ls       (drop-last (:path circ-data))
        enc      [(partial crypto/create-tmp-enc secret) (partial crypto/create-tmp-dec secret)]
        [f b]    (if (is? :origin circ-data)
                   enc
                   (reverse enc))]
    (update-data id [:path] (concat ls [(merge l {:f-enc f :b-enc b :secret secret})]))))


;; send cell ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn cell-send [config socket circ-id cmd payload & [len]]
  ;; FIXME: fix cell size.
  "Add cell header before finally sending a packet."
  (let [len          (or len (.-length payload))
        packet-sz    (:herd-packet-size config)
        buf          (b/new (+ 5 packet-sz)) ;; 5 for cmd type & socket index (dtls-handler), 9 for len circ-id & cmd
        [w8 w16 w32] (b/mk-writers buf)]
    (if (> len packet-sz)
      (log/error "cell-send: dropping too big cell, circ-id:" circ-id "cmd:" cmd "size:" len)
      (do (w32 (+ 9 len) 5)
          (w32 circ-id 9)
          (w8 (from-cmd cmd) 13)
          (.copy payload buf 14)
          (log/debug :circ :sendingon socket cmd)
          (if-let [send-fn (-> socket c/get-data :send-fn)]
            (send-fn buf) ;; FIXME: might make this a chan
            (do (.trace js/console "who called me? badsock")
                (log/error "Cell-Send: circ:" circ-id "we were asked to send a cell on a non herd socket, dropping.")))))))


;; make requests: circuit level ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn mk-create [config srv-auth circ-id]
  "Make the create2 payload with the initialisation of the nTor handshake."
  (let [[auth create] (hs/client-init config srv-auth)
        header   (b/new 4)]
    (.writeUInt16BE header 2 0)
    (.writeUInt16BE header (.-length create) 2)
    [auth (b/cat header create)]))

(defn create [config socket srv-auth]
  "Send a create2 packet, sent from the last circuit in a path (can be app-proxy)
  to extend a circuit."
  (let [circ-id        (gen-id) ;; FIXME may remove this. seems to make more sense to be path logic.
        [auth create]  (mk-create config srv-auth circ-id)]
    (add circ-id socket nil)
    (update-data circ-id [:forward-hop] socket)
    (add-path-auth circ-id nil auth) ;; FIXME: PATH: mk pluggable
    (cell-send config socket circ-id :create2 create)
    circ-id))

(defn create-mux [config socket circ-id srv-auth]
  "Part of the multipath prototype"
  (let [[auth create]  (mk-create config srv-auth circ-id)
        dest           (conv/dest-to-tor-str (:dest srv-auth))
        create         (b/cat (b/new dest) (b/new (cljs/clj->js [0])) create)]
    (update-data circ-id [:mux :auth] auth)
    (update-data circ-id [:mux :fhop] (conv/dest-to-tor-str dest))
    (update-data circ-id [:roles] (cons :mux (:roles (circ-id @circuits))))
    (cell-send config socket circ-id :create-mux create)))

(defn- enc-send [config socket circ-id circ-cmd direction msg & [iv]]
  "Add all onion skins before sending the packet."
  ;; (assert (@circuits circ-id) "circuit does not exist") ;; FIXME this assert will probably be done elsewhere (process?)
  ;; FIXME assert state.
  (when-let [circ  (@circuits circ-id)]
    (let [c        (node/require "crypto")
          encs     (get-path-enc circ direction) ;; FIXME: PATH: mk pluggable
          iv       (or iv (.randomBytes c (-> config :enc :iv-len)))
          _ (log/error :iv (.readUInt8 iv 0)(.readUInt8 iv 1)(.readUInt8 iv 2)(.readUInt8 iv 3))
          _ (log/error :before (.readUInt8 msg 0)(.readUInt8 msg 1)(.readUInt8 msg 2)(.readUInt8 msg 3))
          msg      (b/copycat2 iv (reduce #(%2 iv %1) msg encs))
          _ (log/error :after (.readUInt8 msg 16)(.readUInt8 msg 17)(.readUInt8 msg 18)(.readUInt8 msg 19))]
      (cell-send config socket circ-id circ-cmd msg))))

(defn- enc-noiv-send [config socket circ-id circ-cmd direction msg]
  "Add all onion skins before sending the packet."
  (assert (@circuits circ-id) "circuit does not exist") ;; FIXME this assert will probably be done elsewhere (process?)
  ;; FIXME assert state.
  (let [circ     (@circuits circ-id)
        encs     (get-path-enc circ direction) ;; FIXME: PATH: mk pluggable
        msg      (reduce #(.update %2 %1) msg encs)] ;; FIXME: new iv for each? seems overkill...
    (cell-send config socket circ-id circ-cmd msg)))

(defn- relay [config socket circ-id relay-cmd direction msg]
  "Helper to add relay header to a relay message."
  (let [data         (b/new (+ (.-length msg) 11))
        [w8 w16 w32] (b/mk-writers data)]
    (w8 (from-relay-cmd relay-cmd) 0)
    (w16 0 1) ;; Recognized
    (w16 101 3) ;; StreamID
    (w32 101 5) ;; Digest
    (w16 101 9) ;; Length
    (.copy msg data 11)
    (enc-send config socket circ-id :relay direction data)))

;; see tor spec 6.2. 160 = ip6 ok & prefered.
(defn relay-begin [config circ-id dest]
  "Send a request to begin relaying data: last mix in the circuit will become
  an exit mix & will open a socket to given dest."
  (let [socket (:forward-hop (@circuits circ-id))
        dest   (conv/dest-to-tor-str dest)
        dest   (b/cat (b/new dest) (b/new (cljs/clj->js [0 160 0 0 0])))]
    (relay config socket circ-id :begin :f-enc dest)))

(defn relay-connected [config circ-id local]
  "Send an acknowledgement to a relay begin: when exit socket is ready."
  (let [socket (:backward-hop (@circuits circ-id))
        local  (conv/dest-to-tor-str local)
        local  (b/cat (b/new local) (b/new (cljs/clj->js [0 160 0 0 0])))]
    (relay config socket circ-id :connected :b-enc local)))

(defn relay-data [config circ-id msg]
  "Send data to be relayed: cut it up to fit in multiple 360 bytes packets."
  (loop [m msg]
    (let [data (b/new 360)]
      (if (> (.-length m) 358)
        ;; if current message is too long, take the first chunk, send it, loop on the remainder.
        (do (.writeUInt16BE data 358 0)
            (.copy m data 2 0 358)
            (relay config (:forward-hop (@circuits circ-id)) circ-id :data :f-enc data)
            (recur (.slice m 358)))
        ;; last (or only) packet to be sent.
        (do (.writeUInt16BE data (.-length m) 0)
            (.copy m data 2)
            (relay config (:forward-hop (@circuits circ-id)) circ-id :data :f-enc data))))))

;; Instead of individual functions, make relay extendable from outside.
(defn relay-rdv [config circ-id]
  "Relay rdv command to the last hop"
  (relay config (:forward-hop (@circuits circ-id)) circ-id :rdv :f-enc (b/new 0)))

(defn relay-sip [config circ-id direction payload]
  "Relay a sip command (like a register to a sip dir). Meant to be used from a RDV circ."
  (relay config ((if (= direction :f-enc) :forward-hop :backward-hop)
                 (@circuits circ-id))
         circ-id :sip direction payload))

(defn relay-ping [config circ-id]
  "Send a ping to circuit destination to measure roundtrip delay."
  (let [now (-> js/Date .now .toString)]
    (relay config (:forward-hop (@circuits circ-id)) circ-id :ping :f-enc (b/new now))))

(defn padding [config socket]
  "Send padding message. Will be dropped."
  (cell-send config socket 0 :padding (b/new 369))) ;; FIXME no enc on circ 0.

;; see tor spec 5.1.2.
(defn relay-extend [config circ-id {nh-auth :auth nh-dest :dest}]
  "Send a relay extend message to given next hop."
  (let [data          (@circuits circ-id)
        socket        (:forward-hop data)
        [auth create] (mk-create config nh-auth circ-id) ;; FIXME id should be changed at each hop. keeping it this way for debugging for now.
        ;; nspec         (condp = (:type nh-dest)
        ;;                 :ip4 (b/cat (b/new (cljs/clj->js [1 3 6]))  (conv/ip4-to-bin (:host nh-dest)) (conv/port-to-bin (:port nh-dest)))
        ;;                 :ip6 (b/cat (b/new (cljs/clj->js [1 4 16])) (conv/ip6-to-bin (:host nh-dest)) (conv/port-to-bin (:port nh-dest)))
        ;;                 (assert nil "unsupported next hop address type"))
        nspec         (b/cat (-> [1 6 (-> config :ntor-values :node-id-len)] cljs/clj->js b/new) (:srv-id nh-auth))]
    (log/debug "Sending extend to:" (-> nh-auth :srv-id b/hx) "at:" (select-keys (c/get-data socket) [:host :port :role]) "id:" (b/hx (or (-> socket c/get-data :auth :srv-id) "0")) "on circ:" circ-id)
    (add-path-auth circ-id data auth) ;; FIXME: PATH: mk pluggable
    (relay config socket circ-id :extend2 :f-enc (b/cat nspec create))))

;; FIXME merge with relay-extend
(defn relay-extend-sip-user [config circ-id {nh-auth :auth name :name}]
  "Send a relay extend message to given next hop."
  (let [data          (@circuits circ-id)
        socket        (:forward-hop data)
        [auth create] (mk-create config nh-auth circ-id)]
    (add-path-auth circ-id data auth)
    (relay config socket circ-id :sip-extend :f-enc (b/cat (b/new name) b/zero create))))

(defn forward [config circ-id dest-str cell]
  "Part of the multipath prototype"
  (comment (let [socket  (c/find-by-dest {})
                 ;;iv      (.randomBytes c 16)
                 key     (-> (@circuits circ-id) :mux :auth :secret)
                 cell    (b/cat iv (crypto/enc-aes key iv cell))
                 payload (b/cat (b/new dest-str) (b/new (cljs/clj->js [0])) cell)]
             (cell-send config socket 0 :forward payload))))

(defn send-destroy [config dest circ-id reason]
  "Send a destroy packet to tear down a circuit."
  (cell-send config dest circ-id :destroy reason))

(defn send-id [config socket]
  "Send id to next hop."
  (cell-send config socket 0 :id (b/cat (-> config :roles first conv/role-to-int b/new1)
                                        (-> config :auth :herd-id :id))))

(defn send-sp [config socket payload]
  "Send a superpeer signaling message."
  (cell-send config socket 0 :sp payload))

;; process recv ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn recv-id [config socket circ-id payload]
  "Recv client's public ID & attach to socket"
  (let [role (-> payload (.readUInt8 0) conv/int-to-role)
        id   (.slice payload 1)]
    (c/add-id socket id)
    (log/debug "recvd client ID" (b/hx id) "on socket index" (:index socket) "with role" role)
    (c/update-data socket [:role] role)
    (c/update-data socket [:auth] {:srv-id id})
    (dtls/send-role socket role)
    (when (and (= role :app-proxy) (= :mix (-> config :roles first)))
      (go (>! (-> config :sp-chans first) {:cmd :new-client
                                           :data id
                                           :socket socket})))))

(defn recv-sp [config socket circ-id payload]
  "Recv super-peer sig. Forward to sp chan."
  (let [[sp-ctrl]  (:sp-chans config)]
    (log/debug (.-length payload) (-> payload (.slice 1) .-length))
    (go (>! sp-ctrl {:cmd    (.readUInt8 payload 0)
                     :data   (.slice payload 1)
                     :socket socket}))))

(defn recv-create2 [config socket circ-id payload]
  "Parse message, perform handshake server reply."
  (add circ-id socket {:roles [:mix]})
  (let [{pub-B :pub node-id :id sec-b :sec} (-> config :auth :herd-id) ;; FIXME: renaming the keys is stupid.
        hs-type                             (.readUInt16BE payload 0)
        len                                 (.readUInt16BE payload 2)
        [shared-sec created]                (hs/server-reply config {:pub-B pub-B :node-id node-id :sec-b sec-b} (.slice payload 4) (-> config :enc :key-len))
        header                              (b/new 2)]
    (assert (= hs-type 2) "unsupported handshake type")
    (.writeUInt16BE header (.-length created) 0)
    (add-path-secret-to-last config circ-id (@circuits circ-id) shared-sec) ;; FIXME: PATH: mk pluggable
    (update-data circ-id [:backward-hop] socket)
    (c/update-data socket [:on-destroy] (cons #(destroy config circ-id) (-> socket c/get-data :on-destroy)))
    (cell-send config socket circ-id :created2 (b/cat header created))))

(defn recv-created2 [config socket circ-id payload]
  "Process created2, add the resulting shared secret to the path, call
  the path's :mk-path-fn to proceed to the next step."
  (let [circ       (@circuits circ-id)]
    (assert circ "circuit does not exist") ;; FIXME this assert will probably be done elsewhere (process?)
    (if (is? :mix circ)
      ;; we are a mix, so relay created2 as an extended2 message:
      (relay config (:backward-hop circ) circ-id :extended2 :b-enc payload)
      ;; we are the origin, add shared secret with add-path-secret-to-last
      (let [mux?       (is? :mux circ)
            auth       (if mux? (-> circ :mux :auth) (-> circ :path last :auth))
            len        (.readUInt16BE payload 0)
            shared-sec (hs/client-finalise auth (.slice payload 2) (-> config :enc :key-len))]
        (if mux?
          (update-data circ-id [:mux :auth :secret] shared-sec) ;; broken but unused on noiv.
          (add-path-secret-to-last config circ-id circ shared-sec))
        (when (:mk-path-fn circ)
          ((:mk-path-fn circ) config circ-id))))))

(defn recv-create-mux [config socket circ-id payload] ;; FIXME this will be a sub function of the actual recv create2
  "Part of the multipath prototype"
  (add circ-id socket {:roles [:mix]})
  (let [{pub-B :pub node-id :id sec-b :sec} (-> config :auth :herd-id) ;; FIXME: renaming the keys is stupid.
        [dest payload]                      (conv/parse-addr payload)
        hs-type                             (.readUInt16BE payload 0)
        len                                 (.readUInt16BE payload 2)
        [shared-sec created]                (hs/server-reply config {:pub-B pub-B :node-id node-id :sec-b sec-b} (.slice payload 4) 32)
        header                              (b/new 2)]
    (assert (= hs-type 2) "unsupported handshake type")
    (.writeUInt16BE header (.-length created) 0)
    (update-data circ-id [:mux :auth] {:secret shared-sec}) ;; FIXME: PATH: mk pluggable
    (update-data circ-id [:mux :bhop] (conv/dest-to-tor-str dest))
    (cell-send config socket circ-id :created2 (b/cat header created))))

(defn recv-forward [config socket circ-id payload]
  "Part of the multipath prototype"
  (let [circ       (@circuits circ-id)
        [dest pl]  (conv/parse-addr payload)]
    (if (and (= (:port dest) (.-localPort socket)) (= (:host dest) (.-localAddress socket)))
      (let [k      (-> circ :mux :auth :secret)
            [iv m] (b/cut payload 16)
            ;cell   (crypto/dec-aes k iv m)
            cell   nil]
        (process config socket cell))
      (let [socket (c/find-by-dest dest)]
        (assert socket "could not find next hop for forwarding")
        (.write socket payload)))))

(defn recv-destroy [config socket circ-id payload]
  "Destroys the given circuit, forwards the message if needed."
  (when-let [circ              (@circuits circ-id)]
    (let [[fhop bhop :as hops] (map circ [:forward-hop :backward-hop])
          dest                 (if (= socket fhop) bhop fhop)
          d                    #(send-destroy config % circ-id payload)
          sip                  (:sip-ctrl circ)]
      (log/info "Recieved: destroy on circuit" circ-id)
      (when sip
        (go (>! sip :bye)))
      (when (or (nil? socket) (and (some (partial = socket) hops)))
        (cond (is? :origin circ) (do (c/destroy bhop)
                                     (when-not socket
                                       (d fhop)))
              (is? :exit circ)   (do (c/destroy fhop)
                                     (when-not socket
                                       (d bhop)))
              :else              (do (if socket
                                       (d dest)
                                       (doall (map d hops)))))
        (rm circ-id)))))

(defn process-relay [config socket circ-id relay-data]
  "Process an incoming relay message: parse header, and dispatch to appropriate relay processing function."
  (let [circ         (@circuits circ-id)
        r-payload    (:payload relay-data)
        add-role     #(->> circ :roles (cons %) distinct)
        answering-machine (some #(= % :answering-machine) (:roles config))

        ;; FIXME begin & data are bad and I should feel bad. everything that was "temporary".
        ;; process data packet: forward payload as rtp, udp to destination socket.
        p-data-old   (fn [] ;; this has accumulated complexity as we experimented. only rtp-exit is used today.
                       (let [[fhop bhop :as hops] (map circ [:forward-hop :backward-hop])
                             dest                 (if (= socket fhop) bhop fhop)
                             dest-data            (c/get-data dest)]
                         (assert (some (partial = socket) hops) "relay data came from neither forward or backward hop.")
                         (if-not dest
                           (when (not answering-machine)
                             (log/error "No destination, dropping on circuit" circ-id))
                           (condp = (:type dest-data)
                             :udp-exit  (if (:send-udp circ) ;; FIXME this is tmp, for rtp only, single path would crash things
                                          (let [real-sz (.readUInt16BE r-payload 0)
                                                msg     (.slice r-payload 2 (+ real-sz 2))]
                                            ((:send-udp circ) msg))
                                          (let [[r1 r2]    (b/mk-readers r-payload)
                                                type       (r1 3)
                                                [h p data] (condp = type
                                                             1 [(conv/ip4-to-str (.slice r-payload 4 8)) (r2 8) (.slice r-payload 10)]
                                                             4 [(conv/ip6-to-str (.slice r-payload 4 20)) (r2 20) (.slice r-payload 22)]
                                                             3 (let [len  (.-length r-payload)
                                                                     ml?  (>= len 5)
                                                                     alen (when ml? (r1 4))
                                                                     aend (when ml? (+ alen 5))]
                                                                 [(.toString r-payload "utf8" 5 aend) (r2 aend) (.slice r-payload (inc aend))])
                                                             (assert false "bad socks5 header"))]
                                            (.send dest data 0 (.-length data) p h)))
                             :udp-ap    (.send dest r-payload 0 (.-length r-payload) (-> dest-data :from :port) (-> dest-data :from :host))
                             :rtp-exit  (let [real-len (.readUInt16BE r-payload 0)
                                              msg      (.slice r-payload 2 (+ real-len 2))]
                                          ;(.send dest msg 0 real-len (-> dest-data :rtp-dest :port) (-> dest-data :rtp-dest :host))
                                          (let [rtp-seq          (.readUInt16BE msg 2)
                                                [total prev]     (:rtp-stats dest-data)]
                                            (if (nil? prev)
                                              (c/update-data dest [:rtp-stats] [0 rtp-seq])
                                              (c/update-data dest [:rtp-stats] [(+ total (- rtp-seq prev 1)) rtp-seq]))))
                             :rtp-ap    (.send dest r-payload 0 (.-length r-payload) (-> circ :local-dest :port) (-> circ :local-dest :host)) ;; FIXME quick and diiiirty
                             (.write dest r-payload)))))
        p-data       #(log/error "Received relay data, dtls-handler should have processed it, circ:" circ-id)

        ;; we are being asked to begin relaying data -> we are the exit mix.
        p-begin      (fn []
                       (assert (is-not? :origin circ) "relay begin command makes no sense") ;; FIXME this assert is good, but more like these are needed. roles are not inforced.
                       (log/info "Relay exit for circuit" circ-id)
                       (update-data circ-id [:roles] (cons :exit (:roles circ)))
                       (let [dest         (first (conv/parse-addr r-payload))
                             sock-connect (chan)
                             get-sock     #(go (>! sock-connect {:host (-> % .address .-address) :port (-> % .address .-port)}))
                             cbs          {:connect get-sock
                                           :error   #(do (log/debug "closed:" dest)
                                                         (destroy config circ-id))}
                             sock         (condp = (:proto dest) ;; FIXME -> this should be set by each transport/tunnel type. -> call backs from socks, rtpp, etc.
                                            :tcp (conn/new :tcp :client dest config (merge cbs {:data (fn [config soc b] ;; FIXME -> mk this a fn used in roles?
                                                                                                        (doall (map (fn [b] (js/setImmediate #(relay config socket circ-id :data :b-enc b)))
                                                                                                                    (apply (partial b/cut b) (range 1350 (.-length b) 1350)))))}))
                                            :udp (conn/new :udp :client nil config (merge cbs {:data (fn [config soc msg rinfo]
                                                                                                       (relay config socket circ-id :data :b-enc msg))}))
                                            :rtp (conn/new :rtp :client nil config (merge cbs {:data #(relay config %1 circ-id :data :b-enc %2)})))]
                         (when (= :udp (:proto dest)) ;; FIXME tmp
                           (update-data circ-id [:send-udp] #(.send sock % 0 (.-length %) (:port dest) (:host dest))))
                         (c/update-data sock [:circuit] circ-id)
                         (update-data circ-id [:forward-hop] sock)
                         (go (relay-connected config circ-id (merge dest (<! sock-connect))))))

        ;; we are an app-proxy, and our relay begin has been acknowledged: we may start relaying data, notify on control channel.
        p-connected  (fn []
                       (let [proxy-dest (first (conv/parse-addr r-payload))]
                         (assert (is? :origin circ) "Connected message makes no sense")
                         (update-data circ-id [:proxy-local] proxy-dest)
                         (go (>! (:ctrl circ) proxy-dest))))

        ;; we are being asked to extend the circuit: send create2 to the next hop.
        p-extend     (fn []
                       (let [[r1 r2 r4] (b/mk-readers r-payload)
                             nb-lspec   (r1 0) ;; FIXME we're assuming 1 for now.
                             ls-type    (r1 1)
                             ls-len     (r1 2)
                             dest       (condp = ls-type
                                          6 {:id (.slice r-payload 3 (+ 3 (-> config :ntor-values :node-id-len))) :create (.slice r-payload (+ 3 (-> config :ntor-values :node-id-len)))}
                                          3 {:type :ip4 :host (conv/ip4-to-str (.slice r-payload 3 7))  :port (r2 7)  :create (.slice r-payload 9)}
                                          4 {:type :ip6 :host (conv/ip6-to-str (.slice r-payload 3 19)) :port (r2 19) :create (.slice r-payload 21)})
                             ctrl       (chan)
                             sock       (c/find-by-id (:id dest))
                             fhop       (:forward-hop circ)]
                         (assert sock (str "Could not find destination " (b/hx (or (:id dest) "0"))))
                         (when (and (is? :rdv circ) fhop)
                           (send-destroy config fhop circ-id (b/new "because reasons")))
                         (log/debug "Relay extend to:" (-> dest :id b/hx) "at:" (select-keys (c/get-data sock) [:host :port :role]) "on circ:" circ-id)
                         (update-data circ-id [:forward-hop] sock)
                         (update-data circ-id [:roles] (add-role :mix))
                         (dtls/send-new-mix-fp (merge (@circuits circ-id) {:id circ-id})
                                               (merge (@circuits circ-id) {:id circ-id}))
                         (cell-send config sock circ-id :create2 (:create dest))))

        ;; our relay extend has been acknowledged. Process as a created2 message.
        p-extended   #(recv-created2 config socket circ-id r-payload)

        ;; we are asked to be RDV:
        p-rdv        (fn []
                       (log/info "Acting as RDV for" circ-id)
                       (update-data circ-id [:roles] (add-role :rdv)))

        p-sip        #(if-let [sip-ch (or (:sip-chan circ) (:sip-chan config))] ;; sip dir servers use a global chan so it is stored in config, clients use a per circ chan.
                        (go (>! sip-ch {:circ circ :circ-id circ-id :sip-rq r-payload}))
                        (log/error "SIP uninitialised, dropping request on circuit:" circ-id))

        p-ping       #(relay config socket circ-id :pong :b-enc r-payload)

        p-pong       #(let [now   (.now js/Date)
                            sent  (-> r-payload .toString js/parseInt)]
                        (log/debug "Ping: Circuit:" circ-id "roundtrip delay:" (- now sent) "ms"))

        p-sp         #(let [[sp-ctrl] (:sp-chans config)
                            cmd       (.readUInt8 r-payload)]
                        (>! sp-ctrl {:cmd cmd :data (.slice r-payload 1) :socket socket}))]

    ;; dispatch the relay command to appropriate function.
    (condp = (:relay-cmd relay-data)
      0  :drop-padding
      1  (p-begin)
      2  (p-data)
      3  (log/error :relay-end "is an unsupported relay command")
      4  (p-connected)
      5  (log/error :relay-sendme "is an unsupported relay command")
      6  (log/error :relay-extend "is an unsupported relay command")
      7  (log/error :relay-extended "is an unsupported relay command")
      8  (log/error :relay-truncate "is an unsupported relay command")
      9  (log/error :relay-truncated "is an unsupported relay command")
      10 (log/error :relay-drop "is an unsupported relay command")
      11 (log/error :relay-resolve "is an unsupported relay command")
      12 (log/error :relay-resolved "is an unsupported relay command")
      13 (log/error :relay-begin_dir "is an unsupported relay command")
      14 (p-extend)
      15 (p-extended)
      ;; herd specific:
      16 (p-sip)
      ;; 17 (p-extend-sip)
      18 (p-rdv)
      19 (p-ping)
      20 (p-pong)
      21 (p-sp)
      (log/error "unsupported relay command"))))

;; see tor spec 6.
(defn recv-relay [config socket circ-id payload]
  "If relay message is going backward add an onion skin and send.
  Otherwise, take off the onion skins we can, process it if we can or forward."

  (if (nil? (@circuits circ-id))
    (when nil (send-destroy config socket circ-id (b/new "because reasons")))
    (let [circ        (@circuits circ-id)
          mux?        (is? :mux circ)
          direction   (if (= (:forward-hop circ) socket) :b-enc :f-enc)
          [iv msg]    (b/cut payload (-> config :enc :iv-len))]

      (if (and (is-not? :origin circ) (= direction :b-enc))
        ;; then message is going back to origin -> add enc & forwad
        (if (and mux? (-> circ :mux :fhop))
          (forward config circ-id (-> circ :mux :fhop) payload)
          (enc-send config (:backward-hop circ) circ-id :relay :b-enc msg iv))

        ;; message going towards exit -> rm our enc layer. OR message @ origin, peel of all layers.
        (let [msg         (reduce #(%2 iv %1) msg (get-path-enc circ direction))
              [r1 r2 r4]  (b/mk-readers msg)
              recognised? (and (= 101 (r2 3) (r4 5) (r2 9)) (zero? (r2 1))) ;; FIXME -> add digest
              relay-data  {:relay-cmd    (r1 0)
                           :recognised   recognised?
                           :stream-id    (r2 3)
                           :digest       (r4 5)
                           :relay-len    (r2 9)
                           :payload      (when recognised? (.slice msg 11))}]

          (cond (:recognised relay-data)        (process-relay config socket circ-id relay-data)
                (and mux? (-> circ :mux :bhop)) (forward config circ-id (-> circ :mux :bhop) msg)
                :else                           (cell-send config (:forward-hop circ) circ-id :relay (b/copycat2 iv msg))))))))


;; cell management (no state logic here) ;;;;;;;;;;;;;;;;;;;;;;;;;

(def to-cmd
  {0   {:name :padding         :fun nil}
   1   {:name :create          :fun nil}
   2   {:name :created         :fun nil}
   3   {:name :relay           :fun recv-relay}
   4   {:name :destroy         :fun recv-destroy}
   5   {:name :create_fast     :fun nil}
   6   {:name :created_fast    :fun nil}
   8   {:name :netinfo         :fun nil}
   9   {:name :relay_early     :fun nil}
   10  {:name :create2         :fun recv-create2}
   11  {:name :created2        :fun recv-created2}
   ;; herd only <--
   20  {:name :id              :fun recv-id}
   21  {:name :sp              :fun recv-sp}
   ;; herd only -->
   7   {:name :versions        :fun nil}
   128 {:name :vpadding        :fun nil}
   129 {:name :certs           :fun nil}
   130 {:name :auth_challenge  :fun nil}
   131 {:name :authenticate    :fun nil}
   132 {:name :authorize       :fun nil}
   256 {:name :forward         :fun recv-forward}
   257 {:name :create-mux      :fun recv-create-mux}})

(def from-cmd
  (apply merge (for [k (keys to-cmd)]
                 {((to-cmd k) :name) k})))

(def from-relay-cmd
  {:begin      1
   :data       2
   :end        3
   :connected  4
   :sendme     5
   :extend     6
   :extended   7
   :truncate   8
   :truncated  9
   :drop       10
   :resolve    11
   :resolved   12
   :begin_dir  13
   :extend2    14
   :extended2  15
   ;; extended 
   :sip        16
   :sip-extend 17
   :rdv        18
   :ping       19
   :pong       20})

(def wait-buffer (atom nil)) ;; FIXME we need one per socket

(defn reset-keep-alive [config socket]
  (c/update-data socket [:rate-count-dw] (-> socket c/get-data :rate-count-dw inc))
  (c/update-data socket [:keep-alive-date] (.now js/Date)))

(defn process [config socket data-orig]
  "Takes received data from a socket, checks if there is enough data,
  parses the header and calls the appropriate function to process it."
  ;; FIXME check len first -> match with fix buf size
  (let [data         (if @wait-buffer (b/copycat2 @wait-buffer data-orig) data-orig)
        [r8 r16 r32] (b/mk-readers data)
        len          (.-length data)   ;; actual length
        cell-len     (r32 0)           ;; length the packet should have
        circ-id      (r32 4)           ;; circuit id
        command      (to-cmd (r8 8))   ;; what kind of packet command (relay, extend, etc)
        circ         (@circuits circ-id)]
    (identity (when (or true (not= :padding (:name command))) ;; only print debug if the message isn't padding
               (log/debug "recv cell: id:" circ-id "cmd:" (:name command) "len:" len "cell-len:" cell-len "id:" (if-let [id (-> socket c/get-data :auth :srv-id)]
                                                                                              (b/hx id)
                                                                                              "unknown"))))
    (if (and false (not= len (:herd-packet-size config))) ;; FIXME SP manifest
      (log/error "Circ:" circ-id "received cell with bad length:" len "or cell length:" cell-len)
      (when (:fun command)
        (try
          ((:fun command) config socket circ-id (.slice data 9 cell-len))
          (catch js/Object e (log/c-info e (str "Killed circuit " circ-id)) (destroy config circ-id)))))))
