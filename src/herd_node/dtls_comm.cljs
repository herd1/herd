(ns herd-node.dtls-comm
  (:require [cljs.core :as cljs]
            [cljs.nodejs :as node]
            [cljs.core.async :refer [chan <! >! sub pub unsub close!] :as a]
            [herd-node.parse :as conv]
            [herd-node.log :as log]
            [herd-node.buf :as b]
            [herd-node.conns :as c])
  (:require-macros [cljs.core.async.macros :as m :refer [go-loop go]]))

;; globals:
(declare circ-process dispatch-pub dtls-handler-socket-data send-to-dtls)

;; command definitions:

;;  :init             -> give ntor certs, paths to dtls certs.
;;  :connect-to-node  -> give tor-dest
;;  :add-hop          -> add hop to a circuit, we send created ntor shared secret to enable fastpath.
;;  :open-local-udp   -> for fast path between c layer & sip client
;;  :new-circuit      -> for fast path relay
;;  :forward          -> give a packet to forward on a dtls link
;;  :data             -> c layer sends us data it couldn't process in a fast path

(def to-cmd
  {0  :init
   1  :connect-to-node
   2  :open-local-udp
   3  :update-local-udp-dest
   4  :forward
   5  :data
   6  :new-circuit
   7  :ack
   8  :new-client
   9  :rm-node
   10 :new-mix-fp
   11 :rm-mix-fp
   12 :rm-local-udp
   13 :update-role
   14 :update-node-secret
   15 :ping
   })

(def from-cmd
  (apply merge (for [k (keys to-cmd)]
                 {(to-cmd k) k})))

;; helpers:
(defn- mk-send-fn [socket]
  (let [header    (b/new 5)]
    (.writeUInt8 header (from-cmd :forward) 0)
    (.writeUInt32BE header (:index socket) 1)
    #(do (.copy header %)
         (send-to-dtls %))))

;; sending to dtls-handler:
(defn send-to-dtls [buf]
  "send to dtls"
  (let [[soc soc-ctrl port] dtls-handler-socket-data]
    (.send soc buf 0 (.-length buf) port "127.0.0.1")))

(defn send-init [config]
  (let [key-file          (-> config :auth-files :openssl :key)
        cert-file         (-> config :auth-files :openssl :cert)
        herd-pub          (-> config :auth :herd-id :pub)
        herd-sec          (-> config :auth :herd-id :sec)
        herd-id           (-> config :auth :herd-id :id)
        mk-size-and-buf   #(let [buf (b/new %)]
                             (b/cat (b/new2 (.-length buf)) buf))]
    (send-to-dtls (b/cat (-> :init from-cmd b/new1)
                         (-> config :roles first conv/role-to-int b/new1)
                         (mk-size-and-buf cert-file)
                         (mk-size-and-buf key-file)
                         (mk-size-and-buf herd-pub)
                         (mk-size-and-buf herd-sec)
                         (mk-size-and-buf herd-id)
                         (-> config :herd :port b/new2)))))

(defn send-connect [dest cookie]
  (send-to-dtls (b/cat (-> :connect-to-node from-cmd b/new1)
                       (b/new4 cookie)
                       (-> dest :role conv/role-to-int b/new1)
                       (-> dest conv/dest-to-tor-str b/new)
                       b/zero
                       (-> dest :auth :srv-id))))

(defn send-role [socket role]
  "Ask for a new socket. We'll receive an ack with the local port."
  (send-to-dtls (b/cat (-> :update-role from-cmd b/new1)
                       (-> role conv/role-to-int b/new1)
                       (-> socket :index b/new4))))

(defn send-new-local-udp [cookie]
  "Ask for a new socket. We'll receive an ack with the local port."
  (send-to-dtls (b/cat (-> :open-local-udp from-cmd b/new1)
                       (b/new4 cookie))))

(defn send-update-local-udp-dest [index circ-id direction dest secrets]
  "For now at least: assuming that circuits are done finished when called,
  which means that if you extend it after calling this, things will break."
  (let [message [(-> :update-local-udp-dest from-cmd b/new1)
                 (b/new4 index)
                 (b/new4 circ-id)]
        message (concat message (if (= direction :in)
                                  [(b/new1 0)
                                   (-> dest conv/dest-to-tor-str b/new)
                                   b/zero]
                                  [(b/new1 1)
                                   (b/new4 dest)]))
        message (concat message [(-> secrets count b/new4)])
        message (concat message secrets)]
    (log/debug "sending local udp dest" direction "using circ" circ-id "with" (count (filter identity secrets)) "secrets")
    (send-to-dtls (apply b/cat message))))

(defn send-new-mix-fp [circ-data-fwd circ-data-bwd]
  (let [fwd-secs (map #(:secret %) (:path circ-data-fwd))
        bwd-secs (map #(:secret %) (:path circ-data-bwd))
        message  [(-> :new-mix-fp from-cmd b/new1)
                   (-> circ-data-fwd :forward-hop :index b/new4)
                   (-> circ-data-bwd :backward-hop :index b/new4)
                   (-> circ-data-fwd :id b/new4)
                   (-> circ-data-bwd :id b/new4)
                   (-> fwd-secs count b/new4)]
        message  (concat message fwd-secs)
        message  (concat message [(-> bwd-secs count b/new4)])
        message  (concat message bwd-secs)]
    (send-to-dtls (apply b/cat message))))

(defn send-rm-local-udp [socket]
  (send-to-dtls (b/cat (-> :rm-local-udp from-cmd b/new1)
                       (-> socket :index b/new4))))

(defn send-rm-mix-fp [circ-id]
  (send-to-dtls (b/cat (-> :rm-mix-fp from-cmd b/new1)
                       (b/new4 circ-id))))

(defn send-rm-node [socket]
  (send-to-dtls (b/cat (-> :rm-node from-cmd b/new1)
                       (-> socket :index b/new4))))

;; sp signalization:

(defn send-node-secret [sp-socket shared-sec]
  (log/debug "FIXM send-node-secret" sp-socket)
  (send-to-dtls (b/cat (-> :update-node-secret from-cmd b/new1)
                       (-> sp-socket :index b/new4)
                       shared-sec)))
(defn relay-ping [config circ]
  (send-to-dtls (b/cat (-> :ping from-cmd b/new1)
                       (-> circ b/new4))))

;; connect to a new node:
(defn connect [dest conn-info conn-handler err]
  (let [c         (node/require "crypto")
        cookie    (.readUInt32BE (.randomBytes c 4) 0) ;; cookie used to identify transaction
        ctrl      (chan)]
    (log/info "DTLS: Connecting to" (select-keys dest [:host :port :role]) (-> dest :auth :srv-id b/hx))
    (sub dispatch-pub cookie ctrl)
    (go (send-connect dest cookie)
        (let [answer (<! ctrl) ;; also allow for timeout...
              _ (log/info (.-length answer))
              state  (.readUInt32BE answer 5)
              id     (.readUInt32BE answer 9)
              soc    {:index id :type :herd-dtls}]
          (unsub dispatch-pub cookie ctrl)
          (close! ctrl)
          (if (not= 0 state)
            (do (log/error "got fail on" cookie "/ err" state)
                (when err
                  (err soc))
                :fail)
            (do (when conn-handler
                  (conn-handler))
                (log/debug "got dtls-handler ok on cookie" cookie "given node id =" id)
                (c/add soc
                       (merge conn-info
                              {:id id :cs :client :type :herd :host (:host dest) :port (:port dest)
                               :send-fn (mk-send-fn soc)
                               :on-destroy [#(send-rm-node soc)]}))))))));; FIXME: might make this a chan

;; process messages from dtls-handler:
(defn process [socket config buf rinfo dispatch-rq]
  (let [[r1 r2 r4]  (b/mk-readers buf)
        cmd         (to-cmd (r1 0))]
    (log/debug "recvd" cmd "on socket" socket)
    (condp = cmd
      :ack        (go (log/debug "FIXME: got ack with cookie" (.readUInt32BE buf 1))
                      (>! dispatch-rq buf))
      :data       (let [socket-id (r4 1)
                        socket    {:index socket-id :type :herd-dtls}]
                    (log/debug :total-len (.-length buf))
                    (if (nil? (c/get-data socket))
                      (log/error "Got data for an invalid/unknown DTLS socket id" socket-id)
                      (circ-process config socket (.slice buf 5))))
      :new-client (let [socket-id (r4 1)
                        socket    {:index socket-id :type :herd-dtls}]
                    (log/info "New client on socket-id:" socket-id)
                    (c/add socket
                           {:id socket-id :cs :server :type :herd ;; FIXME can we get rid of :cs? that was old...
                            :send-fn (mk-send-fn socket)
                            :on-destroy [#(send-rm-node socket)]}))    ;; FIXME: might make this a chan
      :rm-node    (let [socket-id (r4 1)]
                    ;; also remove circs.
                    (c/destroy {:index socket-id :type :herd-dtls}))
      (log/error "DTLS comm: unsupported command" cmd (r1 0)))))

;; start dtls-handler & create listening socket:
(defn init [{port :dtls-handler-port fixme :files-for-certs :as config} circ-process circ-accept]
  (let [exec          (.-exec (node/require "child_process"))
        dtls-handler  (exec (str (:dtls-handler-path config) " " port)
                            nil
                            #(do (log/error "dtls-handler exited with" %1)
                                 (log/error %&)
                                 ;(init config)
                                 ))
        soc           (.createSocket (node/require "dgram") "udp4")
        soc-ctrl      (chan)
        dispatch-rq   (chan)]
    ;; yerk, define globals. might replace this with chans.
    (def circ-process circ-process)
    (def circ-accept circ-accept)
    (def dispatch-pub (pub dispatch-rq #(.readUInt32BE %1 1)))
    (.bind soc 0 "127.0.0.1")
    (c/add-listeners soc {:message   #(process soc config %1 %2 dispatch-rq)
                          :listening #(go (>! soc-ctrl :listening))
                          :error     #(log/error "DTLS control socket error")
                          :close     #(log/error "DTLS control socket closed")})

    (log/info "Started dtls handler, PID:" (.-pid dtls-handler) "Port:" port)
    ;; yerk, define global:
    (def dtls-handler-socket-data [soc soc-ctrl port])
    (go (<! soc-ctrl)
        (send-init config))))
