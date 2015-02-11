(ns herd-node.conn-mgr
  (:require [cljs.core :as cljs]
            [cljs.nodejs :as node]
            [cljs.core.async :refer [chan <! >! sub pub unsub close!] :as a]
            [herd-node.log :as log]
            [herd-node.dtls-comm :as dtls]
            [herd-node.tls :as tls]
            [herd-node.conns :as c])
  (:require-macros [cljs.core.async.macros :as m :refer [go-loop go]]))

;; conn_mgr.cljs: high level network inits (dtls/tls/tcp/udp/dir).


(defn new [type cs conn {auth :auth :as config} {connect :connect data :data udp-data :udp-data init :init err :error}]
  "Used to create new connections. Type can be socks, herd, dir, tcp, udp or rtp.
  Warning: :herd :client will return a chan to the socket id, whereas all others return the socket id. <- FIXME."
  (let [conn-info   (merge conn {:type type :cs cs})
        is?         #(and (= %2 cs) (= %1 type))
        data        (partial data config)
        udp-data    (partial udp-data config)
        err         (or err #(do (log/error "Caught error on socket:" %) (c/destroy %)))
        ;; create a new tcp connection:
        new-tcp-c   (fn [] (let [socket (.connect (node/require "net") (cljs/clj->js (select-keys conn [:host :port])))]
                             (c/add socket {:ctype :tcp :type :tcp-exit :cs :client})
                             (c/add-listeners socket {:data      (partial data socket)
                                                      :connect   #(connect socket)
                                                      :error     err
                                                      :end       err})
                             socket))
        ;; create a new udp connection:
        new-udp-c   (fn [type] (let [socket (.createSocket (node/require "dgram") (if (= :ip6 (:ip conn)) "udp6" "udp4"))]
                                 (.bind socket 0)
                                 (c/add socket {:ctype :udp :type type :cs :client :send #(.send socket % 0 (.-length %) (:port conn) (:host conn))})
                                 (c/add-listeners socket {:message   (partial data socket)
                                                          :listening #(connect socket)
                                                          :error     err
                                                          :close     err})
                                 socket))
        connect     (partial connect config)]
    ;; create the appropriate connection:
    (cond ;(is? :socks :server) (socks/create-server conn data udp-data (partial init config) (partial err config))
          (is? :herd :server)  (log/error "Herd server should be created by dtls-comm/init now")
          (is? :herd :client)  (go-loop [soc (<! (dtls/connect conn conn-info connect err))]
                                 (if (not= soc :fail)
                                   soc
                                   (recur (<! (dtls/connect conn conn-info connect err)))))
          (is? :dir :server)   (tls/create-server conn config connect err) ;; FIXME: setting type to herd/herd-dir is in dtls/tls. this is Bad.
          (is? :dir :client)   (tls/connect conn config connect err)
          (is? :tcp :client)   (new-tcp-c)
          (is? :udp :client)   (new-udp-c :udp-exit)
          (is? :rtp :client)   (new-udp-c :rtp-exit)
          :else                (log/error "Unsupported connection type:" type "as" cs))))
