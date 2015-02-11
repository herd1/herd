(ns herd-node.path
  (:require [cljs.core :as cljs]
            [cljs.nodejs :as node]
            [cljs.core.async :refer [chan <! >! sub pub unsub close!] :as a]
            [herd-node.log :as log]
            [herd-node.buf :as b]
            [herd-node.parse :as conv]
            [herd-node.dtls-comm :as dtls]
            [herd-node.conn-mgr :as conn]
            [herd-node.conns :as c]
            [herd-node.circ :as circ]
            [herd-node.geo :as geo]
            [herd-node.dir :as dir])
  (:require-macros [cljs.core.async.macros :as m :refer [go-loop go]]))

;; Overview;
;;
;; This makes use of circ.cljs to create circuits. This is where the logic for
;; choosing the nodes of a circuit lives.
;;
;; init-path calls create-rt (create real time circuits, for rtp) and
;; create-single (TOR like circuits, for the socks proxy). create-rt will be
;; executed up to: (go (<! ctrl).  When a circuit is needed (say for an
;; outgoing call) we get one with get-path, feed the rest of our destination
;; (the callee and his mix) to the circuit's ctrl channel and create-rt will
;; resume and complete the circuit.  (and this is a nice example of what async
;; is useful for, instead of having create logic broken up in multiple
;; callbacks, it is all in one place).


;; make requests: path level ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; Create a single path circuit (TOR like).
(defn create-single [config [n & nodes :as all-nodes]]
  "Creates a single path. Assumes a connection to the first node exists."
  ;; Find the first mix's socket & send a create.
  (let [socket (c/find-by-id (-> n :auth :srv-id))
        id     (circ/create config socket (:auth n))
        ctrl   (chan)
        dest   (chan)
        notify (chan)]
    (circ/update-data id [:roles]      [:origin])
    (circ/update-data id [:ctrl]       ctrl)
    (circ/update-data id [:dest-ctrl]  dest)
    (circ/update-data id [:notify]     notify)
    (circ/update-data id [:mk-path-fn] #(go (>! ctrl :next)))
    (circ/update-data id [:path-dest]  (-> all-nodes last :dest))
    (circ/update-data id [:chosen-mix] n)
    ;; for each remaining mix (nodes here), send a relay-extend, wait until
    ;; the handshaking is over by waiting on (<! ctrl)
    (go (loop [cmd (<! ctrl), [n & nodes] nodes]
          (when n
            (circ/relay-extend config id n)
            (log/debug "Single Circuit:" id "extending to;" (-> n :auth :srv-id b/hx) "-- remaining =" (count nodes))
            (recur (<! ctrl) nodes)))
        ;; the circuit is built, waiting on dest-ctrl for a destination before sending relay begin,
        ;; or a :rdv command to make the last node a rdv.
        (let [cmd  (<! dest)
              circ (circ/get-data id)]
          (condp = cmd
            ;; normal circuit, what app-proxy uses:
            :begin (do (circ/relay-begin config id (:ap-dest circ))
                       (circ/update-data id [:state] :relay-ack-pending)
                       (circ/update-data id [:path-dest :port] (:port (<! ctrl)))
                       (circ/update-data id [:state] :relay)
                       (>! (-> circ :backward-hop c/get-data :ctrl) :relay)
                       (log/info "Single Circuit:" id "is ready for relay"))
            ;; RDV logic: send relay rdv to ask last node to become our rdv point.
            :rdv   (do (circ/relay-rdv config id)
                       (log/info "Using Single Circuit" id "as RDV")
                       (circ/update-data id [:rdv] (last all-nodes))
                       ;; each time we receive a new dest, we ask rdv to extend to it.
                       ;; if the rdv already had a next hop, it will destroy it.
                       (loop [next-hop (<! dest)]
                         (let [enc-path (-> id circ/get-data :path)]
                           ;; if rdv had a next hop, remove it from the encryption node list.
                           (when (> (count enc-path) (count all-nodes))
                             (circ/update-data id [:path] (drop-last enc-path)))
                           (when (not= next-hop :drop-last)
                             (log/debug "Extending RDV" id "to" (-> next-hop :role) (-> next-hop :auth :srv-id b/hx))
                             ;; send extend, then wait for extended before notifying upstream.
                             (circ/relay-extend config id next-hop)
                             (<! ctrl) ;; FIXME add timeout in case things go wrong.
                             ;; notify:
                             (circ/update-data id [:state] :relay)
                             (log/info "RDV" id "is ready for relay"))
                           (go (>! notify :extended))
                           (recur (<! dest)))))
            (log/error "Single: Did not understand command" cmd "on circ" id))))
    id))

;; create a realtime path for RTP. This version connects to the callee's ap.
(defn create-rt [config socket mix]
  "Creates a real time path. Assumes a connection to the first node exists."
  ;; Find the first mix's (will be our assigned mix/SP) socket & send a create.
  (let [id                 (circ/create config socket (:auth mix))
        [ctrl dest notify] (repeatedly chan)]
    (circ/update-data id [:roles] [:origin])
    (circ/update-data id [:ctrl] ctrl)
    (circ/update-data id [:notify] notify)
    (circ/update-data id [:dest-ctrl] dest)
    (circ/update-data id [:mk-path-fn] #(go (>! ctrl :next)))
    (go (<! ctrl)
        (log/debug "RT Circuit" id "waiting for destination")
        ;; wait until we are given a destination: our rdv, the peer's rdv, the peer's mix, and the peer's name.
        (doseq [hop (<! dest)]
          (circ/relay-extend config id hop)
          (<! ctrl)
          (log/info "RT Circuit" id "extended by one hop"))
        (>! notify :done)
        (log/info "RT Circuit" id "is ready for relay"))
    id))
;(circ/update-data id [:path-dest] rt-dest)

(defn create-one-hop [config socket mix]
  "Creates a one hop path. Assumes a connection to the first & only node exists. used for SIP dir signaling. See sip.cljs."
  ;; Find the first mix's (will be our assigned mix/SP) socket & send a create.
  (println :creating :one-hop)
  (let [id     (circ/create config socket (:auth mix))
        ctrl   (chan)
        notify (chan)]
    (circ/update-data id [:roles] [:origin])
    (circ/update-data id [:ctrl] ctrl)
    (circ/update-data id [:notify] notify)
    (circ/update-data id [:mk-path-fn] #(go (>! ctrl :next)))
    (go (<! ctrl)
        (circ/update-data id [:state] :relay)
        (>! notify :done)
        (log/info "One Hop Circuit" id "is ready for Signaling"))
    id))


;; path ap glue ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; the following functions are helpers for forwarding local data into circuits.

(defn app-proxy-forward-udp [config s b]
  "For packets already encapsulated in socks5 header"
  (let [circ-id   (:circuit (c/get-data s))
        circ-data (circ/get-data circ-id)
        config    (merge config {:data s})]
    (if (= (-> circ-data :state) :relay)
      (circ/relay-data config circ-id b)
      (log/info "UDP: not ready for data, dropping on circuit" circ-id))))

(defn forward-udp [config s b]
  "For packets needing socks5 header."
  (let [circ-id    (:circuit (c/get-data s))
        circ-data  (circ/get-data circ-id)
        dest       (:path-dest circ-data)
        config     (merge config {:data s}) ;; FIXME we are going to have to get rid of this.
        data       (b/new (+ 10 (.-length b)))
        [w1 w2 w4] (b/mk-writers data)]
    (w4 0 0)
    (w1 1 3)
    (.copy (conv/ip4-to-bin (:host dest)) data 4)
    (w2 (:port dest) 8)
    (.copy b data 10)
    (if (= (-> circ-data :state) :relay)
      (circ/relay-data config circ-id data)
      (log/info "UDP: not ready for data, dropping on circuit" circ-id))))

(defn app-proxy-forward [config s]
  "Used for forwarding local data."
  (let [circ-id   (:circuit (c/get-data s))
        circ-data (circ/get-data circ-id)
        config    (merge config {:data s})]
    (if (= (-> circ-data :state) :relay)
      (when true;(circ/done?)
        (if-let [b (.read s 1350)] ;; FIXME, this value should not be hardcoded.
          (do ;(circ/inc-block)
              (circ/relay-data config circ-id b))
          (when-let [b (.read s)]
            ;(circ/inc-block)
            (circ/relay-data config circ-id b))))
      (log/info "App-Proxy-Forward: not ready for data, dropping on circuit" circ-id))))

(defn attach-local-udp [config circ-id forward-to forwarder & [bind-port]] ;; FIXME: forward-to changed meaning, it is now only used for what ip we're binding to.
  "Unused right now, except by hardcoded rtp benchmarks."
  (go (let [ctrl      (chan)
            udp-sock  (.createSocket (node/require "dgram") "udp4")
            port      (do (.bind udp-sock (or bind-port 0) (:host forward-to) #(go (>! ctrl (-> udp-sock .address .-port))))
                          (<! ctrl))
            dest      {:type :ip4 :proto :udp :host "0.0.0.0" :port 0}] ;; FIXME should not be hardcoded to ip4.
        (-> udp-sock
            (c/add {:ctype :udp :ctrl ctrl :type :udp-ap :circuit circ-id :local-dest forward-to}) ;; FIXME circ data is messy... need to separate and harmonise things.
            (c/add-listeners {:message (partial forwarder config udp-sock)}))
        (circ/update-data circ-id [:ap-dest] dest)
        (circ/update-data circ-id [:backward-hop] udp-sock)
        (circ/update-data circ-id [:local-dest] forward-to)
        [udp-sock port])))

(defn attach-circs-to-new-udp [config in-circ-id-chan out-circ-id-chan forward-to-dest]
  "Create a socket that will redirect incoming traffic to out-circ-id (outgoing traffic) and receive
  traffic from in-circ-id (incoming traffic).
  forward-to is the destination of local traffic (outside world [eg callee] -> in-circ -> forward-to [local sip client, caller])."
  (let [ack         (chan)
        cookie      (-> "crypto" node/require (.randomBytes 4) (.readUInt32BE 0)) ;; cookie used to identify transaction
        get-secrets #(map :secret (-> % circ/get-data :path))]

    (log/debug "DTLS: asked for new local udp socket with cookie =" cookie)
    (sub dtls/dispatch-pub cookie ack)
    (dtls/send-new-local-udp cookie)

    (go (let [answer     (<! ack) ;; dtls anwer has to be at least x long.
              index      (.readUInt32BE answer 5)
              port       (.readUInt16BE answer 9)
              id         {:index index :type :local-udp}]
          (log/debug "DTLS: got ack, index =" index "port =" port)
          (c/add id {:ctype :udp :type :rtp-exit
                     :on-destroy [#(dtls/rm-local-udp id)]})

          (go (let [out-circ-id (<! out-circ-id-chan)]
                (log/debug "DTLS: got out circ")
                (c/update-data id [:circuit] out-circ-id)
                (circ/update-data out-circ-id [:state] :relay)
                (circ/update-data out-circ-id [:backward-hop] id)
                (dtls/send-update-local-udp-dest index out-circ-id :out (-> out-circ-id circ/get-data :id) (get-secrets out-circ-id))))

          (go (let [in-circ-id (<! in-circ-id-chan)
                    fwd-to     (<! forward-to-dest)]
                (log/debug "DTLS: got in circ")
                (c/update-data id [:rtp-dest] fwd-to)
                (circ/update-data in-circ-id [:forward-hop] id)
                (circ/update-data in-circ-id [:state] :relay)
                (dtls/send-update-local-udp-dest index in-circ-id :in fwd-to (get-secrets in-circ-id))))

          [id port]))))

(defn attach-local-udp-to-simplex-circs [config in-circ-id-chan out-circ-id-chan forward-to-dest]
  "Create a socket that will redirect incoming traffic to out-circ-id (outgoing traffic) and receive
  traffic from in-circ-id (incoming traffic).
  forward-to is the destination of local traffic (outside world [eg callee] -> in-circ -> forward-to [local sip client, caller]).

  This is being deprecated, in favor of letting dtls-handler take care of local sockets (for fastpath) with attach-circs-to-new-udp."
  (let [port       (chan)
        udp-sock   (.createSocket (node/require "dgram") "udp4")
        dest       {:type :ip4 :proto :udp :host "0.0.0.0" :port 0}] ;; FIXME should not be hardcoded to ip4.
    (.bind udp-sock 0 (:host "0.0.0.0") #(go (>! port (-> udp-sock .address .-port))))
    (-> udp-sock
        (c/add {:ctype :udp :type :rtp-exit})
        (c/add-listeners {:message (partial app-proxy-forward-udp config udp-sock)}))
    ;; out:
    (go (let [out-circ-id (<! out-circ-id-chan)]
          (c/update-data udp-sock [:circuit] out-circ-id)
          (circ/update-data out-circ-id [:state] :relay)
          (circ/update-data out-circ-id [:backward-hop] udp-sock)))
    ;; in:
    (go (let [in-circ-id (<! in-circ-id-chan)]
          (c/update-data udp-sock [:rtp-dest] (<! forward-to-dest))
          (c/update-data udp-sock [:forward-hop] udp-sock)
          (circ/update-data in-circ-id [:forward-hop] udp-sock)
          (circ/update-data in-circ-id [:state] :relay)))
    (go [udp-sock (<! port)])))


;; path pool ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(def pool (atom {}))
(def chosen-mix (atom nil))

(defn reset-chosen-mix! [mix]
  (reset! chosen-mix mix))

(defn init-pool [config soc type path-data]
  "Initialises a channel, filling it with as many circuits as it will take.
  Replaces them as they are consumed."
  (let [new-path (condp = type
                   :one-hop #(create-one-hop config soc path-data)
                   :single  #(create-single config (path-data))
                   :rt      #(create-rt config soc path-data))]
    (go-loop [] ;; as soon as one of our buffered circs is claimed, this loop recurs once to replace it:
      (>! (@pool type) (new-path))
      (recur))))

(defn init-pools [config net-info loc N & [already-chosen-mix]]
  "Initialise a pool of N of each type of circuits (rt and single for now)
  net-info is the list of mixes with their geo info."
  (let [zone         (-> loc :zone)
        select-mixes #(->> net-info seq (map second) (filter %) shuffle)
        ;; entry mix, for :rt --> will be assigned by dir.
        mix          (or already-chosen-mix
                         (first (select-mixes #(and (= (:role %) :mix) (= (:zone %) zone)))))
        ;; make path for :single, three hops, the first being mix chosen for :rt.
        mk-path      (fn [] ;; change (take n) for a path of n+1 nodes.
                       (->> (select-mixes #(and (= (:role %) :mix) (not= mix %))) (take 0) (cons mix))) ;; use same mix as entry point for single & rt. ; not= mix
        ;; rdvs in our zone:
        rdvs         (select-mixes #(and (= (:role %) :rdv) (= (:zone %) zone)))
        soc          (if already-chosen-mix
                       (go (c/find-by-id (-> already-chosen-mix :auth :srv-id)))
                       (conn/new :herd :client mix config  {:connect identity})) ;; FIXME make :connect optional
        N            (dec N)] ;; an additional circ is created waiting for the channel to be ready to receive.
    (log/info "Init Circuit pools: we are in" zone)
    (log/debug "Chosen mix:" (:host mix) (:port mix))
    (reset! chosen-mix mix)
    ;; init channel pools:
    (reset! pool {:one-hop (chan N) :rt (chan N) :single (chan N)})
    ;; wait until connected to the chosen mix before sending requests
    (go (let [soc (<! soc)]
          ;;(circ/send-id config soc) ;; not with sp
          (init-pool config soc :rt mix)
          (init-pool config soc :single #(concat (mk-path) (->> rdvs shuffle (take 1)))) ;; for now all single circuits are for rdvs, if this changes this'll have to change too.
          (init-pool config soc :one-hop mix)))
    mix))

(defn get-path [type]
  "Return a channel to the chosen type rt/single of path.
  As soon as a circuit is used, a new one will be put in the channel, see init-pool."
  (@pool type))
