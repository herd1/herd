(ns herd-node.conns
  (:require [cljs.core :as cljs]
            [cljs.nodejs :as node]
            [herd-node.log :as log]
            [herd-node.buf :as b]))

(declare destroy find-by-dest)

;; conns.cljs: used to keep track of open connections/sockets (be it herd,
;; socks, local udp, etc).
;; Add new, update info, remove, etc.


(def connections (atom {}))

(def id-to-connections (atom {}))

(defn rm [conn]
  (when (-> conn (@connections) :auth :srv-id)
    (swap! id-to-connections dissoc (-> conn (@connections) :auth :srv-id b/hx)))
  (swap! connections dissoc conn)
  conn)

(defn destroy [conn]
  (when-let [c (@connections conn)]
    (when (-> c :auth :srv-id)
      (log/info "Removing connection to:" (-> c :auth :srv-id b/hx)))
      (rm conn)
      (doall (map #(%) (:on-destroy c))) ;; used to kill circs.
      (cond (or (= :herd-dtls (:type conn))
                (= :local-udp (:type conn))) (log/debug "destroyed:" (:type conn) "index:" (:index conn))
            (= :tcp (:ctype c))              (do (log/debug :fixme2)
                                                 (.destroy conn))
            (= :udp (:ctype c))              (do (log/debug :fixme3 "trying to close" c conn)
                                                 (.close conn))
            (= :herd-dir (:type c))          (.destroy conn)
            :else                            (log/error :fixme5 "tried to close unknown type of socket" c conn))))

(defn add [conn & [data]]
  (swap! connections merge {conn data})
  (when-let [id (-> data :auth :srv-id)]
    (destroy (-> id b/hx (@id-to-connections) :socket))
    (swap! id-to-connections merge {(-> id b/hx) {:socket conn}})
    (log/info "Added connection to:" (-> id b/hx)))
  conn)

(defn add-id [conn id]
  (let [existing-socket (-> id b/hx (@id-to-connections) :socket)]
    (when (not= existing-socket conn)
      (destroy existing-socket)))
  (swap! id-to-connections merge {(b/hx id) {:socket conn}})
  (log/info "Received ID connection to:" (b/hx id) (:index conn)))

(defn set-data [conn data]
  (swap! connections merge {conn data})
  conn)

(defn update-data [conn keys subdata]
  (swap! connections assoc-in (cons conn keys) subdata)
  conn)

(defn add-listeners [conn listeners]
  "Add callbacks to socket events.
  Listeners is a hash map of events & functions: {:connect do-connect, :close do-cleanup}"
  (doseq [k (keys listeners) :let [fns (k listeners) fns (if (seq? fns) fns [fns])]]
    (dorun (map #(.on conn (name k) %) fns)))
  conn)

(defn get-all []
  @connections)

(defn get-data [conn]
  (when conn
    (@connections conn)))

(defn find-by-id [id]
  "Find an open socket for the given host.
  Might also add a filter to match a type of connections (herd, dir, etc)."
  (-> id b/hx (@id-to-connections) :socket))

(defn find-by-dest [{host :host}] ;; FIXME should deprecate this. breaks on nat for example.
  "Find an open socket for the given host.
  Might also add a filter to match a type of connections (herd, dir, etc)."
  (first (keep (fn [[s d]]
                 (when (= host (:host d)) s))
               (seq @connections))))
