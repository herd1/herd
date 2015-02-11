(ns herd-node.dir
  (:require [cljs.core :as cljs]
            [cljs.nodejs :as node]
            [cljs.core.async :refer [chan <! >!]]
            [clojure.string :as str]
            [herd-node.buf :as b]
            [herd-node.log :as log]
            [herd-node.conns :as c]
            [herd-node.conn-mgr :as conn]
            [herd-node.parse :as conv]
            [herd-node.geo :as geo])
  (:require-macros [cljs.core.async.macros :as m :refer [go]]))


;; dir.cljs: directory logic. Has server service & client requests.


;; defs & helpers ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(declare to-cmd from-cmd)

(def mix-dir (atom {}))       ;; directory of mixes
(def app-dir (atom {}))       ;; directory of application proxies
;; (def sp-dir  (atom {}))       ;; directory of super-peers ;; FIXME: for now everything goes in mix-dir.
(def net-info-buf (atom nil)) ;; keep the mix topology in a buffer ready to be sent. This is updated when clients register.

;; The data is a map with [ip port] as key for each mix entry:
;; [ip port] {:proto   protocol
;;            :type    ip type
;;            :host    host address
;;            :port    port
;;            :zone    geo location
;;            :role    its role
;;            :auth    its pub key & id}

(defn find-by-id [id]
  (first (keep (fn [[_ m]]
                 (when (and (-> m :auth :srv-id) (b/b= id (-> m :auth :srv-id)))
                   m))
               (seq @mix-dir))))

(defn get-net-info []
  "Return our local mix topology, obtained from a dir."
  @mix-dir)

(defn rm [id]
  (log/info "removing client" id)
  (swap! app-dir dissoc id))


;; encode/decode ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn parse-info [config msg]
  "Parse an entry consisting of:
  - role, int8 0 = app-proxy, 1 = mix, will add 2 = super peer
  - geographical zone, int8, see geo/int-to-zone
  - nTor id & public key (sizes are in config/static-conf)
  - ip/host, port, connection type
  - if it's an app-proxy, parse the next entry as its rendez vous mix
  return the appropriate entry and the rest of the payload."
  (let [role         (conv/int-to-role (.readUInt8 msg 0))
        zone         (.readUInt8 msg 1)
        id-len       (-> config :ntor-values :node-id-len)
        [id pub msg] (doall (b/cut (.slice msg 2) id-len (+ id-len (-> config :ntor-values :h-len))))
        [client msg] (doall (conv/parse-addr msg))
        ip           (:host client)
        [mix msg]    (doall (if (= role :app-proxy)
                              (conv/parse-addr msg)
                              [nil msg]))]
    [(merge client {:mix mix :zone (geo/int-to-zone zone) :role role :auth {:srv-id id :pub-B pub}}) msg]))

(defn mk-info-buf [info]
  "Create an entry from info, that parse-info can read."
  (let [role  (conv/role-to-int (:role info))
        msg   [(-> [role (-> info :zone geo/zone-to-int)] cljs/clj->js b/new)
               (-> info :auth :srv-id)
               (-> info :auth :pub-B)
               (b/new (conv/dest-to-tor-str {:type :ip4 :proto :udp :host (:host info) :port (:port info)}))
               b/zero]
        msg   (if (zero? role)
                (concat msg [(b/new (conv/dest-to-tor-str (merge (:mix info) {:proto :udp :type :ip4}))) b/zero])
                msg)]
    (apply b/cat msg)))

(defn mk-net-buf! []
  "Recreate net-info-buf, which is sent to clients on a net-request."
  ;; header:
  (reset! net-info-buf (b/new 5))
  (.writeUInt8    @net-info-buf (from-cmd :net-info) 0)
  (.writeUInt32BE @net-info-buf (count @mix-dir) 1)
  (doseq [k (keys @mix-dir)] ;; create an entry for each mix:
    (swap! net-info-buf b/copycat2 (mk-info-buf (@mix-dir k)))))


;; send things ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn send-client-info [config soc geo mix done-chan]
  "Send our info to the given directory (soc). This is how we register."
  (let [header (-> [(from-cmd :client-info)] cljs/clj->js b/new)
        is?    (fn [role]
                 (first (filter #(= role %) (:roles config))))
        info   {:auth {:srv-id   (-> config :auth :herd-id :id)
                       :pub-B    (-> config :auth :herd-id :pub)}
                :host (-> config :external-ip)
                :port (-> config :herd :port)
                :role (or (is? :super-peer) (is? :sip-dir) (is? :rdv) (is? :mix) (is? :app-proxy))
                :mix  mix
                :zone (-> geo :zone)}]
    (.write soc (b/copycat2 header (mk-info-buf info)) #(go (>! done-chan :done)))))

(defn send-net-request [config soc done]
  "Send a message asking for the herd mix topology"
  (.write soc (-> [(from-cmd :net-request) 101] cljs/clj->js b/new)
          #(when done
             (go (>! done :done)))))

(defn send-query [config soc ip]
  "Send a query to get the rendez vous point of a client. Right now we query using
  the client's IP, will change to SIP username."
  (.write soc (b/cat (-> [(from-cmd :query)] cljs/clj->js b/new)
                     (b/new (conv/dest-to-tor-str {:proto :udp :type :ip4 :host ip :port 0}))
                     (-> [0] cljs/clj->js b/new))))

;; process recv ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn recv-client-info [config srv msg recv-chan]
  "Process a registration."
  (let [[info]      (parse-info config msg)
        ip          (:host info)
        role        (:role info)]
    (if (or (= role :super-peer) (= role :sip-dir) (= role :rdv) (= role :mix))
      ;; FIXME: mixes should also timeout.
      (do (swap! mix-dir merge {[ip (:port info)] info})
          (mk-net-buf!))
      ;; add app-proxy to app-dir. Update entry if it already exists.
      (let [entry   (@app-dir ip)
            to-id   (js/setTimeout #(rm ip) 20000)]
        (when entry ;; if a timer was already set, remove it.
          (js/clearTimeout (:timeout entry)))
        (swap! app-dir merge {ip (merge {:timeout to-id} info)}))))
  (when recv-chan
    (go (>! recv-chan :got-geo))))

(defn recv-net-info [config srv msg recv-chan]
  "Parse the received herd mix topology."
  ;; FIXME: we should reset mix-dir first.
  (let [nb      (.readUInt32BE msg 0)] ;; nb is the number of entries
    ;; init i at 0, and cut the header off of msg
    (reset! mix-dir nil)
    (loop [i 0, msg (.slice msg 4)]
      ;; do this until we've parsed all entries:
      (when (< i nb)
        ;; Parse entry and add it to mix-dir.
        (let [[{port :port host :host :as info} msg] (parse-info config msg)]
          (swap! mix-dir merge {[host port] (merge {:dest {:host host :port port}} info)})
          (recur (inc i) msg))))
    (when recv-chan
      (go (>! recv-chan :got-geo)))))

(defn recv-net-request [config soc msg recv-chan]
  "When we receive a net-request, just send the net-info-buf that
  contains the mix topology in the required format."
  (if @net-info-buf
    (.write soc @net-info-buf)
    (.write soc (-> [(from-cmd :net-info) 0 0 0 0] cljs/clj->js b/new))))

(defn recv-query [config soc msg recv-query]
  "Receive a query for a client's rendez vous"
  ;; parse the client info, find the entry in app-dir.
  (let [info (-> msg conv/parse-addr first :host (@app-dir))
        ;; find the associated rendez vous from that entry:
        mix  (@mix-dir [(-> info :mix :host) (-> info :mix :port)])]
    (if info
      ;; reply with the client's info & associated rendez vous.
      (.write soc (b/cat (-> [(from-cmd :query-ans)] cljs/clj->js b/new)
                         (mk-info-buf info)
                         (mk-info-buf mix)))
      ;; unknown client.
      (.write soc (b/copycat2 (-> [(from-cmd :query-ans)] cljs/clj->js b/new) (b/new "no"))))))

(defn recv-query-ans [config soc msg recv-query]
  "Receive answer from a sent query (for a client's rendez vous)."
  (go (if (= 2 (.-length msg))
        ;; unknown client:
        (>! recv-query [nil nil])
        ;; we got the rendez vous, put it in the given channel.
        (let [[app msg] (parse-info config msg)
              [mix]     (parse-info config msg)]
          (>! recv-query [app mix])))))

(def to-cmd
  {0   {:name :client-info  :fun recv-client-info}
   1   {:name :net-info     :fun recv-net-info}
   2   {:name :net-request  :fun recv-net-request}
   3   {:name :query        :fun recv-query}
   4   {:name :query-ans    :fun recv-query-ans}})

;; (def roles {:mix 0 :app-proxy 1}) ;; FIXME add :super-peer

(def from-cmd
  (apply merge (for [k (keys to-cmd)]
                 {((to-cmd k) :name) k})))

(defn process [config srv buf & [recv-chan]]
  "Parse the header & give the message to the appropriate function."
  (when (> (.-length buf) 0) ;; FIXME put real size when message header is finalised.
    (let [cmd        (.readUInt8 buf 0)
          msg        (.slice buf 1)
          process    (-> cmd to-cmd :fun)]
      (log/info "Dir: Recieved:" (-> cmd to-cmd :name))
      (if process
        (try (process config srv msg recv-chan)
             (catch js/Object e (log/c-error e (str "Herd-Dir: Malformed message" (to-cmd cmd)))))
        (log/info "Net-Info: invalid message command")))))


;; interface ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn query [{dir :remote-dir :as config} ip]
  "Query for an client's rendez vous from his IP."
  (log/info "querying dir for:" ip)
  ;; create socket, setup listen, send query, tear down the connection.
  (let [done (chan)
        c    (conn/new :dir :client dir config {:connect #(go (>! done :connected))})]
    (c/add-listeners c {:data #(process config c % done)})
    (go (<! done)
        (send-query config c ip)
        (let [m-and-a (<! done)] ;; we got mix & app-proxy data.
          (c/rm c)
          (.end c)
          m-and-a))))
