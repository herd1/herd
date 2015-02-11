(ns herd-node.geo
  (:require [cljs.core :as cljs]
            [cljs.nodejs :as node]
            [cljs.core.async :refer [chan <! >!]]
            [clojure.string :as str]
            [herd-node.log :as log]
            [herd-node.parse :as conv])
  (:require-macros [cljs.core.async.macros :as m :refer [go]]))

(defn int-to-zone [zone]
  "Return keyword from int coding of zone"
  (condp = zone
    0  :australia
    1  :california
    2  :ireland
    3  :japan
    4  :singapore
    5  :virginia))

(defn zone-to-int [zone]
  "Return int coding of region keyword. For sending over network."
  (condp = zone
    :australia   0
    :california  1
    :ireland     2
    :japan       3
    :singapore   4
    :virginia    5))

(defn parse [config]
  (try
    (let [fs  (node/require "fs")
          geo (chan)
          ip  (-> config :external-ip conv/ip4-to-bin (.readUInt32BE 0))]
      (if (:geo-info config)
        ;; zone is specified in config
        (go (log/info "Geo: We are in" (-> config :geo-info :zone))
            (:geo-info config))
        ;; parse geo db, downloaded from http://software77.net/geo-ip/
        (do (.readFile fs (-> config :geo-db) #(go (>! geo %2)))
            (go (first (for [l (str/split (<! geo) #"\n")
                             :let  [[from to zone _ _ _ country] (str/split (str/replace l \" "") #",") ]
                             :when (and (not= \# (first l))
                                        (>= ip from)
                                        (<= ip to))] ;; parse line by line, only keep the entry that encapsulates our ip.
                         {:zone      (keyword zone)
                          :country   country
                          :ip        ip}))))))
    (catch js/Object e (log/c-error "Error reading Geo loc DB" e))))
