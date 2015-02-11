(ns herd-node.join
  (:require [cljs.core :as cljs]
            [cljs.nodejs :as node]
            [cljs.core.async :refer [chan <! >!]]
            [herd-node.log :as log]
            [herd-node.misc :as m]
            [herd-node.buf :as b]
            [herd-node.parse :as conv])
  (:require-macros [cljs.core.async.macros :as m :refer [go]]))


(def channels (atom {}))

(def to-cmd
  {0   :super-peer-register
   1   :client-register
   2   :reply})


(defn server-process [config buffer]
  (let [node-id-len (-> config :ntor-values :node-id-len)
        [id pub b]  (b/cut buffer node-id-len (-> config :ntor-values :key-len (+ node-id-len)))
        cmd         (.readUInt8 b 0)
        role        (conv/int-to-role (.readUInt8 b 1))]
     ))

(defn init [config]
  (condp #(m/is? % (:roles config))
    :super-peer (let [nb-channels (-> config :super-peer :nb-channels)]
                  (doseq [i (range nb-channels)]
                    (swap! channels merge {i {:state nil :nb-clients 0}})))))
