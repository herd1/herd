(ns herd-node.sp
  (:require [cljs.core :as cljs]
            [cljs.nodejs :as node]
            [cljs.core.async :refer [chan <! >! sub pub unsub close!] :as a]
            [herd-node.parse :as conv]
            [herd-node.dtls-comm :as dtls]
            [herd-node.conn-mgr :as conn]
            [herd-node.circ :as circ]
            [herd-node.path :as path]
            [herd-node.ntor :as hs]
            [herd-node.conns :as c]
            [herd-node.log :as log]
            [herd-node.dir :as dir]
            [herd-node.buf :as b])
  (:require-macros [cljs.core.async.macros :as m :refer [go-loop go]]))


(def to-cmd
  {0  :register-to-sp
   1  :mk-secret
   2  :ack-secret
   3  :register-id-to-sp
   })

(def from-cmd
  (apply merge (for [k (keys to-cmd)]
                 {(to-cmd k) k})))


;; sent by mix:

(defn send-client-sp-id [config socket client-index sp-id]
  "send a sp id & its client-index on the channel to a client"
  (circ/send-sp config socket (b/cat (-> :register-to-sp from-cmd b/new1)
                                     (b/new4 client-index)
                                     sp-id)))

(defn mk-secret-from-create [config payload]
  (log/debug ":aoeu" (.-length payload))
  (let [{pub-B :pub node-id :id sec-b :sec} (-> config :auth :herd-id) ;; FIXME: this is the current blocking bug.
        client-id                           (.readUInt32BE payload 0)
        hs-type                             (.readUInt16BE payload 4)
        len                                 (.readUInt16BE payload 6)
        [shared-sec created]                (hs/server-reply config {:pub-B pub-B :node-id node-id :sec-b sec-b} (.slice payload 8) (-> config :enc :key-len))]
    (assert (= hs-type 2) "unsupported handshake type")
    [client-id shared-sec created]))


;; sent by client:

(defn send-mk-secret [config mix-socket client-id mix-auth]
  (let [[auth create]   (hs/client-init config mix-auth)]
    (log/debug :FIXME :mk-secret (.-length create))
    (circ/send-sp config mix-socket (b/cat (-> :mk-secret from-cmd b/new1)
                                           (b/new4 client-id)
                                           (b/new2 2) ;; type of hs
                                           (-> create .-length b/new2)
                                           create))
    auth))


;; init:

(defn init [config]
  (let [[sp-ctrl sp-notify] (:sp-chans config)
        mix-answer (chan)
        config     (merge config [sp-ctrl sp-notify])
        process   (fn [{cmd :cmd data :data socket :socket}]
                    (let [cmd (if (number? cmd) (to-cmd cmd) cmd)]
                      (log/info "Recvd" cmd)
                      (condp = cmd
                        ;;;; recvd by mix:
                        :new-client       (let [conns               (c/get-all)
                                                sps                 (for [k (keys conns)
                                                                          :let [conn-data (conns k)]
                                                                          :when (= :super-peer (:role conn-data))]
                                                                      [k  conn-data])
                                                [sp-socket sp-data] (first sps)
                                                sp-id               (-> sp-data :auth :srv-id)
                                                sp-clients          (-> sp-data :client-secrets)
                                                sp-clients          (or sp-clients {})
                                                client-id           (first (filter #(not (sp-clients %)) (range (:max-clients-per-channel config))))
                                                client-ntor-id      data]
                                            (when (not= 1 (count sps))
                                              (log/error "wrong number of superpeers" sps))
                                            (assert client-id "could not add client, channel full")
                                            (log/debug "Sending SP id" (b/hx sp-id) "to client" client-id)
                                            (c/update-data sp-socket [:client-secrets] (merge sp-clients {client-id {:secret nil :srv-id client-ntor-id}}))
                                            (c/update-data socket [:future-sp] sp-socket)
                                            (send-client-sp-id config socket client-id sp-id))
                        :mk-secret        (let [[client-id shared-sec created]  (mk-secret-from-create config data)
                                                on-destroy                      (-> socket c/get-data :on-destroy)
                                                sp-socket                       (-> socket c/get-data :future-sp)
                                                client-secrets                  (-> sp-socket c/get-data :client-secrets)]
                                            (c/update-data sp-socket [:client-secrets]
                                                           (merge client-secrets {client-id {:secret shared-sec}}))
                                            (c/update-data socket [:on-destroy] (cons #(c/add-id sp-socket (:srv-id (client-secrets client-id)))
                                                                                      on-destroy))
                                            (dtls/send-node-secret {:index client-id} shared-sec)
                                            ;; send ack to client:
                                            (circ/send-sp config socket (b/cat (-> :ack-secret from-cmd b/new1)
                                                                               (-> created .-length b/new2)
                                                                               created)))
                        ;;;; recvd by client:
                        :register-to-sp   (let [client-id (.readUInt32BE data 0)
                                                sp-id     (.slice data 4)]
                                           (go (>! mix-answer [client-id sp-id]))) ;; :connect function is waiting for this.
                        :ack-secret       (go (>! mix-answer data))
                        ;; internal commands (not from the network)
                        :connect          (let [zone          (-> config :geo-info :zone)
                                                net-info      (dir/get-net-info)
                                                select-mixes  #(->> net-info seq (map second) (filter %) shuffle) ;; FIXME make this a function
                                                mix           (first (select-mixes #(and (= (:role %) :mix) (= (:zone %) zone))))
                                                socket        (conn/new :herd :client mix config  {:connect identity})]
                                            ;; 1/ connect to mix, wait for client-id & sp-id
                                            (go (let [mix-socket (<! socket)]
                                                  (circ/send-id config mix-socket)
                                                  (log/debug :FIXME "sent id")
                                                  (let [[client-id sp-id] (<! mix-answer)
                                                        sp                (first (select-mixes #(b/b= sp-id (-> % :auth :srv-id))))]
                                                    (log/debug "Will connect to SP" (b/hx sp-id))
                                                    (assert sp "Could not find SP")
                                                    ;; 2/ connect to SP:
                                                    (let [socket     (conn/new :herd :client sp config {:connect identity})
                                                          auth       (send-mk-secret config mix-socket client-id (:auth mix))
                                                          payload    (<! mix-answer)
                                                          shared-sec (hs/client-finalise auth (.slice payload 2) (-> config :enc :key-len))
                                                          sp-socket  (<! socket)]
                                                      (circ/send-sp config sp-socket (b/cat (-> :register-id-to-sp from-cmd b/new1)
                                                                                            (b/new4 client-id)))
                                                      ;; 3/ create circuits:
                                                      (dtls/send-role sp-socket :super-peer)
                                                      (dtls/send-node-secret sp-socket shared-sec)
                                                      (c/update-data sp-socket [:sp-auth] (:auth sp)) ;; FIXME: not sure if we'll keep this, but for now it'll do
                                                      (c/update-data sp-socket [:auth] (-> mix-socket c/get-data :auth)) ;; FIXME: not sure if we'll keep this, but for now it'll do
                                                      (c/add-id sp-socket (-> mix :auth :srv-id))
                                                      ;(circ/send-id config sp-socket)
                                                      (path/init-pools config net-info (:geo-info config) 2 (c/get-data sp-socket))
                                                      (>! sp-notify [sp-socket mix])))))))))]
    (go-loop [msg (<! sp-ctrl)]
      (process msg)
      (recur (<! sp-ctrl)))
    (log/info "Superpeer signaling initialised")))
