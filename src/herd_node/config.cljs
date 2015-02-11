(ns herd-node.config
  (:require [cljs.core :as cljs]
            [cljs.nodejs :as node]
            [cljs.reader :as reader]
            [herd-node.buf :as b]
            [herd-node.crypto :as c]))


(def config (atom {}))

(def static-conf 
  ;; set defaults and non user stuff here.
  (let [;; ntor handshake configuration:
        protoid   "ntor-curve25519-sha256-1"
        bp        #(b/new (str protoid %1))
        ntor      {:m-expand    (bp ":key_expand")
                   :t-key       (bp ":key_extract")
                   :mac         (bp ":mac")
                   :verify      (bp ":verify")
                   :protoid     (b/new protoid)
                   :server      (b/new "Server")
                   :node-id-len 20
                   :key-len     32
                   :g-len       32
                   :h-len       32}]
    ;; key lengths, ntor, and rate period in milliseconds.
    {:enc                       {:iv-len 16 :key-len 32}
     :debug                     false
     :ntor-values               ntor
     :rate                      {:period 10}
     ;; dir & sip dir register will timeout if not renewed within these:
     :register-interval         10000
     :keep-alive-interval       20000
     :sip-register-interval     600000
     ;; dtls c layer:
     :dtls-handler-port         6677
     :dtls-handler-path         "./dtls-handler"
     :herd-packet-size          400
     ;; SP:
     :max-clients-per-channel   5
     }))

(defn read-config [argv]
  "Parse config file herdrc in current directory, or from argv's --config <path>."
  (let [;; read config
        fs          (node/require "fs")
        read        #(reader/read-string %)
        cfg         (read (.readFileSync fs (or (:config argv) "herdrc") "utf8"))
        ;; file manipulation
        cat         (fn [k auth]
                      "Read file, path in the k key of the auth map: used for reading openssl certs."
                      (try {k (.readFileSync fs (auth k) "ascii")}
                           (catch js/Object e (do (println "/!\\  could not load auth info:" e) {k nil}))))
        xcat        (fn [k auth]
                      "Read file, path in the k key of the auth map: used for reading herd certs. File expected in base64."
                      (try {k (js/Buffer. (.toString (.readFileSync fs (auth k)) "binary") "base64")} ;; FIXME -> this buf->str->buf conversions make base64 work. get this working with a single call, this is ridiculous.
                           (catch js/Object e (do (println "/!\\  could not load auth info:" e) {k nil}))))
        mcat        (fn [cat auth & keys]
                      "map one of the cat functions over keys."
                      (apply merge auth (map #(cat % auth) keys)))
        echo-to     (fn [file buf]
                      "Write a buffer to a file as base64, for writing herd certs. Return the original buffer."
                      (.writeFile fs file (.toString buf "base64"))
                      buf)
        ;; cat key paths as keys
        ;; read certs, from the paths given in config:
        ossl        (mcat cat  (-> cfg :auth :openssl) :cert :key)
        herd        (mcat xcat (-> cfg :auth :herd-id) :sec :pub :id)
        ;; if herd certs are null, create some (first run).
        herd        (if (:sec herd)
                      herd
                      (let [[s p] (c/gen-keys static-conf)] ;; generate herd certs.
                        (merge {:sec (echo-to (-> cfg :auth :herd-id :sec) s)}
                               {:pub (echo-to (-> cfg :auth :herd-id :pub) p)}
                               {:id  (echo-to (-> cfg :auth :herd-id :id)  (-> (node/require "crypto") (.createHash "sha256") (.update p) .digest (.slice 0 (-> static-conf :ntor-values :node-id-len))))})))] ;; FIXME test node len
    ;; Sanity checks
    (assert (= (-> herd :sec .-length) (-> static-conf :ntor-values :key-len))    "Bad secret key length, check herd certificates.")
    (assert (= (-> herd :pub .-length) (-> static-conf :ntor-values :key-len))    "Bad public key length, check herd certificates.")
    (assert (= (-> herd :id .-length) (-> static-conf :ntor-values :node-id-len)) "Bad ID length, check herd certificates.")
    ;; merge static-conf, config file & argv
    (swap! config merge static-conf cfg {:auth-files (:auth cfg)} {:auth {:openssl ossl :herd-id herd}} argv))) ;; FIXME will probably need to remove that, filter argv values we accept & do sanity checking. For now anything in argv overwrites config file.
                                                                                      ;; FIXME Argv supported options:
                                                                                      ;;           --debug (also --debug false)
                                                                                      ;;           --config <file path>. 

(defn get-cfg []
  @config)
