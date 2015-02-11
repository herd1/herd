(ns herd-node.ntor
  (:require [cljs.core :as cljs]
            [cljs.nodejs :as node]
            [herd-node.config :as cfg]
            [herd-node.crypto :as c]
            [herd-node.buf :as b]))


;; see: torspec/proposals/216-ntor-handshake.txt
;;      torspec/tor-spec.txt 5.1.4
;;      tor/src/test/ntor_ref.py, tor/src/or/onion_ntor.c

;; FIXME: also, [slow]buffers or not?
(def conf (:ntor-values cfg/static-conf)) ;; why did I do this again?

(defn hmac [key message]
  (let [crypto (node/require "crypto")]
        (-> (.createHmac crypto "sha256" key)
            (.update message)
            .digest)))

(def h-mac (partial hmac (:mac conf)))
(def h-verify (partial hmac (:verify conf)))

;; FIXME: perfect function to start unit testing...
(defn expand [k n]
  (let [prk    (hmac (:t-key conf) k)
        info   (b/new (:m-expand conf))]
    (loop [out (b/new 0), prev (b/new 0), i 1]
      (if (>= (.-length out) n)
        (.slice out 0 n)
        (let [h   (hmac prk (b/cat prev info (b/new (cljs/clj->js. [i])))) ;; FIXME, test what happens when i > 255...
              out (b/cat out h)]
          (recur out h (inc i)))))))


;; FIXME: assert all lens.
(defn client-init [config {srv-id :srv-id pub-B :pub-B :as auth}]
  (let [[secret-x public-X]        (c/gen-keys config)] ;; FIXME we might change this.
    [(merge auth {:sec-x secret-x :pub-X public-X}) (b/cat srv-id pub-B public-X)]))

(defn server-reply [config {pub-B :pub-B sec-b :sec-b id :node-id :as auth} req key-len]
  (assert (= (.-length req) (+ (:node-id-len conf) (:h-len conf) (:h-len conf))) "bad client req ntor length")
  (let [curve                      (node/require "curve25519")
        [req-nid req-pub pub-X]    (b/cut req (:node-id-len conf) (+ (:node-id-len conf) (:h-len conf)))]
    (assert (b/b= req-nid id)    "received create request with bad node-id")
    (assert (b/b= req-pub pub-B) "received create request with bad pub key")
    (let [[sec-y pub-Y]            (c/gen-keys config)
          x-y                      (.deriveSharedSecret curve sec-y pub-X)
          x-b                      (.deriveSharedSecret curve sec-b pub-X)
          secret-input             (b/cat x-y x-b id pub-B pub-X pub-Y (:protoid conf))
          auth-input               (b/cat (h-verify secret-input) id pub-B pub-Y pub-X (:protoid conf) (:server conf))]
      [(expand secret-input key-len) (b/cat pub-Y (h-mac auth-input))])))

(defn client-finalise [{srv-id :srv-id pub-B :pub-B pub-X :pub-X sec-x :sec-x :as auth} req key-len]
  (assert (= (.-length req) (+ (:g-len conf) (:h-len conf))) "bad server req ntor length")
  (let [curve                      (node/require "curve25519")
        [pub-Y srv-auth]           (b/cut req (:g-len conf))
        x-y                        (.deriveSharedSecret curve sec-x pub-Y)
        x-b                        (.deriveSharedSecret curve sec-x pub-B)
        secret-input               (b/cat x-y x-b srv-id pub-B pub-X pub-Y (:protoid conf))
        auth                       (h-mac (b/cat (h-verify secret-input) srv-id pub-B pub-Y pub-X (:protoid conf) (:server conf)))]
    (assert (b/b= auth srv-auth) "mismatching auth") ;; FIXME here and srv, check x-y & b none 0000.
    (expand secret-input key-len)))
