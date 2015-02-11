(ns herd-node.parse
  (:require [cljs.core :as cljs]
            [cljs.nodejs :as node]
            [clojure.walk :as walk]
            [herd-node.buf :as b]
            [herd-node.log :as log]))

(defn ip4-to-bin [ip]
  "Return a 32b buffer containing binary representation of given string ip."
  (let [re   #"^(\d+)\.(\d+)\.(\d+)\.(\d+)$" ]
    (-> (.match ip re) next cljs/clj->js b/new)))

(defn ip6-to-bin [ip]
  (assert nil "FIXME"))

(defn port-to-bin [port]
  "Return a 16b buffer containing binary representation of given int port."
  (let [p (b/new 2)]
    (.writeUInt16BE p port 0)
    p))

(defn ip4-to-str [buf4]
  "Return a string representation of given binary ip4."
  (->> (range 0 4) (map #(.readUInt8 buf4 %)) (interpose ".") (apply str)))

(defn ip6-to-str [buf16]
  "Return a string representation of given binary ip6."
  (->> (.toString buf16 "hex") (partition 4) (interpose [\:]) (apply concat) (apply str)))

(defn dest-to-tor-str [{proto :proto host :host port :port type :type}]
  "Used in TOR circuits to specify destination. Modified to accept udp & tcp.
  Returns the string: '[u|t]:host:port'
  Warning: this started of as the TOR function but is not compatible anymore because of the added proto field."
  (let [host   (if (= type :ip6) (str "[" host "]") host)]
    (str (if (= :udp proto) "u" "t") ":" host ":" port)))

;; compared to tor, we add a type: which can be:
;; tcp-exit, udp-exit, rtp-exit: t, u or r. will change if needed, tmp.
(defn parse-addr [buf]
  "Parse the string created by dest-to-tor-str. Must be null terminated.
  Return the destination information and the rest of the buffer."
  (let [z    (->> (range (.-length buf))
                  (map #(when (= 0 (.readUInt8 buf %)) %))
                  doall
                  (some identity))]
    (assert z "bad buffer: no zero delimiter")
    (let [str           (.toString buf "ascii" 0 z)
          ip4-re        #"^([utr]):((\d+\.){3}\d+):(\d+)$"
          ip6-re        #"^([utr]):\[((\d|[a-fA-F]|:)+)\]:(\d+)$"
          dns-re        #"^([utr]):(.*):(\d+)$"
          re            #(let [res (cljs/js->clj (.match %2 %1))]
                           (doall (map (partial nth res) %&)))
          [ip prot h p] (->> [(re ip4-re str 1 2 4) (re ip6-re str 1 2 4) (re dns-re str 1 2 3)]
                             (map cons [:ip4 :ip6 :dns])
                             (filter second)
                             doall
                             first)]
      [{:proto (condp = prot, "u" :udp, "t" :tcp, "r" :rtp) :type ip :host h :port (js/parseInt p)} (.slice buf (inc z))])))

(defn role-to-int [role]
  (condp = role
    :app-proxy       0
    :mix             1
    :sip-dir         2
    :rdv             3
    :super-peer      4
    :app-proxy-dummy 5
    :dir             6))

(defn int-to-role [role]
  (condp = role
    0 :app-proxy ;; FIXME: app-proxy will stop registering to dir, only to sip-dir.
    1 :mix
    2 :sip-dir
    3 :rdv
    4 :super-peer
    5 :app-proxy-dummy
    6 :dir))


;; Converting ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn to-clj [js-map]
  "Convert a js map to a clojure hashmap with keywords as keys"
  (-> js-map cljs/js->clj walk/keywordize-keys))

(defn to-js [clj-map]
  "Convert a clj map to a js hashmap with strings as keys"
  (-> clj-map walk/stringify-keys cljs/clj->js))
