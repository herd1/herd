(ns herd-node.sip-dir
  (:require [cljs.core :as cljs]
            [cljs.nodejs :as node]
            [cljs.core.async :refer [chan <! >!]]
            [clojure.walk :as walk]
            [herd-node.log :as log]
            [herd-node.buf :as b]
            [herd-node.parse :as conv]
            [herd-node.conns :as c]
            [herd-node.conn-mgr :as conn]
            [herd-node.circ :as circ]
            [herd-node.path :as path]
            [herd-node.dir :as dir]
            [herd-node.sip-helpers :as s])
  (:require-macros [cljs.core.async.macros :as m :refer [go-loop go]]))


;; SIP DIR service and associated client functions ;;;;;;;;;;;;;;;

(def dir (atom {}))

(defn rm [name]
  "Remove name from dir"
  (swap! dir dissoc name))

(defn register [config name out-rdv-id rdv-cid rdv-id]
  "Send a register to a sip dir. Format of message:
  - cmd: 0 = register
  - rdv's circuit id
  - rdv ntor ID.
  - sip name.
  Used by application proxies to register the SIP username of a client & its RDV to a SIP DIR."
  (let [cmd         (-> :register s/from-cmd b/new1)
        rdv-b       (b/new4 rdv-cid)
        name-b      (b/new name)]
    (log/debug "SIP: registering" name "on RDV circ:" rdv-cid "RDV ID:" (b/hx rdv-id))
    (circ/relay-sip config out-rdv-id :f-enc (b/cat cmd rdv-b rdv-id name-b))))

(defn query [config name rdv-id call-id]
  "Query for the RDV that is used for the given name.
  Used by application proxies to connect to callee."
  (let [cmd         (-> :query s/from-cmd b/new1)
        name-b      (b/new name)]
    (log/debug "SIP: querying for" name "on RDV" rdv-id)
    (circ/relay-sip config rdv-id :f-enc (b/cat cmd (b/new call-id) b/zero name-b))))

(defn mk-query-reply [name dir call-id]
  (when-let [entry   (@dir name)]
    (let [cmd      (-> :query-reply s/from-cmd b/new1)]
      (b/cat cmd (b/new call-id) b/zero (b/new4 (:rdv-cid entry)) (:rdv-id entry)))))

(defn create-dir [config]
  "Wait for sip requests on the sip channel and process them.
  Returns the SIP channel it is listening on.
  SIP directories start this service."
  (let [sip-chan    (chan)
        node-id-len (-> config :ntor-values :node-id-len)
        ;; process register:
        p-register  (fn [{rq :sip-rq}]
                      (let [rdv-cid       (.readUInt32BE rq 1)
                            rdv-id        (.slice rq 5 (+ node-id-len 5))
                            name          (-> rq (.slice (+ node-id-len 5)) .toString)
                            timeout-id    (js/setTimeout #(do (log/debug "SIP DIR: timeout for" name)
                                                              (rm name))
                                                         (:sip-register-interval config))]
                        (log/debug "SIP DIR, registering" name "on RDV circ-id:" rdv-cid "RDV ID:" (b/hx rdv-id))
                        ;; if the user is renewing his registration, remove rm timeout:
                        (when (@dir name)
                          (js/clearTimeout (:timeout (@dir name))))
                        ;; update the global directory:
                        (swap! dir merge {name {:rdv-cid rdv-cid :rdv-id rdv-id :timeout timeout-id}})))
        ;; process query:
        p-query     (fn [{circ :circ-id rq :sip-rq}]
                      (let [[call-id name] (s/get-call-id rq)
                            name           (.toString name)
                            reply          (mk-query-reply name dir call-id)]
                        (if reply
                          (do (log/debug "SIP DIR, query for" name)
                              (circ/relay-sip config circ :b-enc reply))
                          (do (log/debug "SIP DIR, could not find" name)
                              (circ/relay-sip config circ :b-enc
                                              (b/cat (-> :error s/from-cmd b/new1) (b/new call-id) b/zero (b/new "404")))))))]
    ;; dispatch requests to the corresponding functions:
    (go-loop [request (<! sip-chan)]
      (let [cmd (-> request :sip-rq (.readUInt8 0))]
        (condp = (s/to-cmd cmd)
          :register (p-register request)
          :query    (p-query request)
          (log/error "SIP DIR, received unknown command" (s/to-cmd cmd) cmd)))
      (recur (<! sip-chan)))
    sip-chan))


;; MIX DIR service and associated client functions ;;;;;;;;;;;;;;;

;; This will also keep track of what clients are active.
;; this might get exported to another module at some point.
;; Either that, or merge with create-dir, while separating functionality to avoid abuse.
;; maybe a different go-loop based on role?

(def mix-dir (atom {}))

(defn create-mix-dir [config]
  "Wait for sip requests on the sip channel and process them.
  Returns the SIP channel it is listening on.
  Mixes start this service to keep track of the state of its users."
  (let [sip-chan   (chan)
        ;; process register:
        p-register     (fn [{rq :sip-rq}]
                         (let [[client-dest rq] (conv/parse-addr (.slice rq 1))
                               [name rq]        (b/cut-at-null-byte rq)
                               name             (.toString name)
                               [id pub]         (b/cut rq (-> config :ntor-values :node-id-len))
                               timeout-id       (js/setTimeout #(do (log/debug "SIP DIR: timeout for" name)
                                                                    (rm name))
                                                               (:sip-register-interval config))]
                           (log/debug "SIP MIX DIR, registering" name "dest:" client-dest)
                           ;; if the user is renewing his registration, remove rm timeout:
                           (when (@mix-dir name)
                             (js/clearTimeout (:timeout (@mix-dir name))))
                           ;; update the global directory:
                           (swap! mix-dir merge {name {:dest client-dest :state :inactive :auth {:pub-B pub :srv-id id}}})))
        ;; process extend:
        p-extend       (fn [{circ :circ-id rq :sip-rq}]
                         (log/error "This shouldn't be called any more. what are you doing?")
                         (let [[call-id name] (s/get-call-id rq)
                               name           (.toString name)
                               reply          (mk-query-reply name mix-dir call-id)]
                           (if reply
                             (do (log/debug "SIP DIR, query for" name)
                                 (circ/relay-sip config circ :b-enc reply))
                             (do (log/debug "SIP DIR, could not find" name)
                                 (circ/relay-sip config circ :b-enc
                                                 (b/cat (-> :error s/from-cmd b/new1) (b/new call-id) b/zero (b/new "404")))))))
        ;; relay mix queries to client:
        p-relay-invite (fn [{rq :sip-rq}]
                         (let [[_ data] (s/get-call-id rq)
                               rdv-id   (.readUInt32BE data 0)]
                           (when (circ/get-data rdv-id)
                             (circ/relay-sip config rdv-id :b-enc rq))))]
    ;; dispatch requests to the corresponding functions:
    (go-loop [request (<! sip-chan)]
      (let [cmd (-> request :sip-rq (.readUInt8 0))]
        (condp = (s/to-cmd cmd)
          :register-to-mix (p-register request)
          :extend          (p-extend request)
          :invite          (p-relay-invite request)
          (log/error "SIP MIX DIR, received unknown command" (s/to-cmd cmd) cmd)))
      (recur (<! sip-chan)))
    sip-chan))

(defn register-to-mix [config name circ-id]
  "Register client's sip username to the mix so people can extend circuits to us.
  Format:
  - dest (tor dest thing)
  - username"
  (let [cmd    (-> :register-to-mix s/from-cmd b/new1)
        dest   (b/new (conv/dest-to-tor-str {:host (:external-ip config) :port 0 :type :ip4 :proto :udp}))
        name-b (b/new name)]
    (log/debug "SIP: registering" name "on mix" circ-id)
    (circ/relay-sip config circ-id :f-enc (b/cat cmd dest b/zero name-b b/zero (-> config :auth :herd-id :id) (-> config :auth :herd-id :pub)))))
