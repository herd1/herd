(ns herd-node.sip
  (:require [cljs.core :as cljs]
            [cljs.nodejs :as node]
            [cljs.core.async :refer [chan <! >!]]
            [clojure.string :as str]
            [clojure.walk :as walk]
            [herd-node.log :as log]
            [herd-node.buf :as b]
            [herd-node.parse :as conv]
            [herd-node.conns :as c]
            [herd-node.conn-mgr :as conn]
            [herd-node.circ :as circ]
            [herd-node.path :as path]
            [herd-node.dir :as dir]
            [herd-node.dtls-comm :as dtls]
            [herd-node.sip-dir :as sd]
            [herd-node.sip-helpers :as s])
  (:require-macros [cljs.core.async.macros :as m :refer [go-loop go]]))


;; Call management ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; call data:
;; {:sip-ctrl      sip channel dedicated to that call
;;  :sip-call-id   sip id we're feeding to our SIP client
;;  :state         state of the call}

(def calls (atom {}))
(def sip-to-call-id (atom {}))

(defn add-sip-call [sip-id call-id]
  (swap! sip-to-call-id merge {sip-id call-id}))

(defn add-call [call-id data]
  (when (:sip-call-id data)
    (add-sip-call (:sip-call-id data) call-id))
  (swap! calls merge {call-id data}))

(defn update-data [call-id keys data]
  (swap! calls assoc-in (cons call-id keys) data))

(defn rm-call [call-id]
  (when-let [sip-id (-> call-id (@calls) :sip-call-id)]
    (swap! sip-to-call-id dissoc sip-id))
  (swap! calls dissoc call-id))

(defn kill-call [config call-id]
  (let [call      (@calls call-id)
        flat-sel  #(map second (select-keys %1 %2))
        vlc       (:vlc-child call)]
    (log/info "SIP killing call:" call-id)
    (doseq [r [:rt :rtcp] i [:in :out]]
      (->> call r i (circ/destroy config)))
    (when vlc
      (try
        (.kill js/process (.-pid vlc) "SIGKILL")
        (catch js/Object e (log/c-info e "VLC already exited."))))
    (rm-call call-id)))

(defn mk-call-id []
  (-> (node/require "crypto") (.randomBytes 16) (.toString "hex")))


;; SIP sdp creation ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn mk-ack [ok-200 call-id]
  "Creates an ACK based on the 200 ok headers."
  (let [h    (:headers ok-200)]
    {:method  "ACK"
     :uri     (-> ok-200 :headers :contact first :uri)
     :headers {:to       (-> h :to)
               :from     (-> h :from)
               :call-id  call-id
               :cseq     {:method "ACK"
                          :seq (-> h :cseq :seq)}
               :via      []}}))


(defn mk-headers [method call-id caller headers uri-to {ip :host}]
  "create headers for generating an invite. Uses the headers that we saved during register."
  {:uri     uri-to
   :method  method
   :headers (merge {:to               {:uri uri-to}
                    :from             {:uri (str/replace (-> headers :from :uri) #"sip:\w+@" (str "sip:" caller "@")) :name caller}
                    :call-id          call-id
                    ;:via             ; thankfully, sip.js takes care of this one.
                    :contact [{:name nil
                               :uri (str "sip:" caller "@" ip ":5060;transport=UDP;ob")
                               :params {}}]
                    :cseq             {:seq 1 ;(rand-int 888888)
                                       :method method}} ;; FIXME (rand-int 0xFFFFFFFF) is what we'd want.
                   (when (= "INVITE" method)
                     {:content-type    "application/sdp"}))})

(defn mk-sdp [codec {ip :host port :port} {rtcp-port :port} method & [sdp]] ;; FIXME: Codec is temporary
  "generates SDP for invite or 200/ok. codec choice is hardcoded for now."
  (let [to-string   #(apply str (interleave % (repeat "\r\n")))]
    (if sdp
      (let [[owner-sess-id owner-sess-version] (next (re-find #"o=.*\b(\d+) (\d+) IN IP" sdp))
            sdp         (str/replace sdp #"o=.*" (str "o=- " owner-sess-id " " (inc (js/parseInt owner-sess-version)) " IN IP4 " ip)) ;; should completely generate these, inc of that thing is only needed on re-offer/re-negotiation.
            sdp         (str/replace sdp #"c=.*" (str "c=IN IP4 " ip))
            sdp         (str/replace sdp #"(m=video).*" (str "$1 " rtcp-port " RTP/AVP 105 99"))
            sdp         (str/replace sdp #"m=audio \d+ .*" (str "m=audio " port " RTP/AVP 96 97 98 9 100 102 0 8 103 3 104 101"))
            ;sdp         (->> sdp str/split-lines (filter #(or (not= "a" (first %))
            ;                                                  (re-find #"X-nat|sendrecv|rtpmap:9 |rtcp" %))))
            ]
        {:content sdp})
      {:content (to-string ["v=0"
                            (str "o=- 3607434973 3607434973 IN IP4 " ip)
                            "s=-"
                            (str "c=IN IP4 " ip)
                            "t=0 0"
                            "a=X-nat:0"
                            (condp = codec
                              :pcma (str "m=audio " port " RTP/AVP 8 96 97 98 9 100 102 0 103 3 104 101")
                              :pcmu (str "m=audio " port " RTP/AVP 0 96 97 98 9 100 102 8 103 3 104 101")
                              :opus (str "m=audio " port " RTP/AVP 96 97 98 9 100 102 0 8 103 3 104 101")
                              :g722 (str "m=audio " port " RTP/AVP 9 96 97 98 100 102 0 8 103 3 104 101"))
                            ;(str "a=rtcp:" rtcp-port " IN IP4 " ip) ;; FIXME nothing open for that yet.
                            "a=rtpmap:96 opus/48000/2"
                            "a=fmtp:96 usedtx=1"
                            "a=rtpmap:97 SILK/24000"
                            "a=rtpmap:98 SILK/16000"
                            "a=rtpmap:9 G722/8000"
                            "a=rtpmap:100 speex/32000"
                            "a=rtpmap:102 speex/16000"
                            "a=rtpmap:0 PCMU/8000"
                            "a=rtpmap:8 PCMA/8000"
                            "a=rtpmap:103 iLBC/8000"
                            "a=rtpmap:3 GSM/8000"
                            "a=rtpmap:104 speex/8000"
                            "a=rtpmap:101 telephone-event/8000"
                            "a=extmap:1 urn:ietf:params:rtp-hdrext:csrc-audio-level"
                            (str "m=video " rtcp-port " RTP/AVP 105 99")
                            "a=recvonly"
                            "a=rtpmap:105 H264/90000"
                            "a=fmtp:105 profile-level-id=4DE01f;packetization-mode=1"
                            "a=imageattr:105 send * recv [x=[0-1366],y=[0-768]]"
                            "a=rtpmap:99 H264/90000"
                            "a=fmtp:99 profile-level-id=4DE01f"
                            "a=imageattr:99 send * recv [x=[0-1366],y=[0-768]]"
                            ])})))

;; [
;;  "v=0
;;  o=william 0 0 IN IP4 139.19.186.120
;;  s=-
;;  c=IN IP4 139.19.186.120
;;  t=0 0
;;  m=audio 5024 RTP/AVP 96 97 98 9 100 102 0 8 103 3 104 101
;;  a=rtpmap:96 opus/48000/2
;;  a=fmtp:96 usedtx=1
;;  a=rtpmap:97 SILK/24000
;;  a=rtpmap:98 SILK/16000
;;  a=rtpmap:9 G722/8000
;;  a=rtpmap:100 speex/32000
;;  a=rtpmap:102 speex/16000
;;  a=rtpmap:0 PCMU/8000
;;  a=rtpmap:8 PCMA/8000
;;  a=rtpmap:103 iLBC/8000
;;  a=rtpmap:3 GSM/8000
;;  a=rtpmap:104 speex/8000
;;  a=rtpmap:101 telephone-event/8000
;;  a=extmap:1 urn:ietf:params:rtp-hdrext:csrc-audio-level
;;  m=video 5026 RTP/AVP 105 99
;;  a=recvonly
;;  a=rtpmap:105 H264/90000
;;  a=fmtp:105 profile-level-id=4DE01f;packetization-mode=1
;;  a=imageattr:105 send * recv [x=[0-1366],y=[0-768]]
;;  a=rtpmap:99 H264/90000
;;  a=fmtp:99 profile-level-id=4DE01f
;;  a=imageattr:99 send * recv [x=[0-1366],y=[0-768]]
;;  "
;;  ]

;; Manage local SIP client requests ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn create-server [config]
  "Creates the listening service that will process the connected SIP client's requests.
  Application Proxies start this service."
  (let [incoming-sip          (chan)
        node-id-len           (-> config :ntor-values :node-id-len)] ;; Constant we'll be using often.
    (go (let [sip             (node/require "sip")
              headers         (atom {})
              uri-to          (atom "")
              my-name         (atom "")
              answering-machine (some #(= % :answering-machine) (:roles config))
              ;; Prepare RDV:
              rdv-id          (<! (path/get-path :single)) ;; FIXME we should specify what zone we want our rdv in.
              rdv-data        (circ/get-data rdv-id)
              rdv-ctrl        (:dest-ctrl rdv-data)
              rdv-notify      (:notify rdv-data)
              ;; Outgoinp RDV:
              out-rdv-id      (<! (path/get-path :single)) ;; FIXME we should specify what zone we want our rdv in.
              out-rdv-data    (circ/get-data out-rdv-id)
              out-rdv-ctrl    (:dest-ctrl out-rdv-data)
              out-rdv-notify  (:notify out-rdv-data)
              ;; Prepare MIX SIG:
              mix-id          (<! (path/get-path :one-hop))
              ;; SDP parsing:
              get-sdp-dest    (fn [rq]
                                {:port (->> (:content rq) (re-seq #"(?m)m\=(audio)\s+(\d+)") first last)
                                 :host (second (re-find #"(?m)c\=IN IP4 ((\d+\.){3}\d+)" (:content rq)))})
              get-sdp-rtcp    (fn [rq]
                                {:port (->> (:content rq) (re-seq #"(?m)m\=(video)\s*(\d+)") first last)
                                 :host (second (re-find #"(?m)c\=IN IP4 ((\d+\.){3}\d+)" (:content rq)))})
              ;; temp helper
              select          #(->> (dir/get-net-info) seq (map second) (filter %) shuffle)                ;; FIXME -> this should be shared by path.
              distinct-hops   (fn [[m1 r1 r2 m2 c]]
                                "We are already connected to m1. Remove duplicate hops (only happens on same zone calls)."
                                (let [id=  #(= (-> %1 :auth :srv-id b/hx) (-> %2 :auth :srv-id b/hx))]
                                  (cond (id= m1 m2)                  [c]
                                        (or (id= r1 r2) (id= m1 r2)) [r1 m2 c]
                                        (id= r2 m2)                  [r2 m2 c]
                                        :else                        [r1 r2 m2 c])))
              ;;print-hops      (fn [path] ;; used for testing distinct-hops
              ;;                  (doseq [h path]
              ;;                    (println :path (-> h :auth :srv-id b/hx))))
              ;; sip channel processing:
              skip-until      (fn [found-it? from]
                                (go-loop [r (<! from)]
                                  (if (found-it? r)
                                    r
                                    (recur (<! from)))))
              wait-for-bye    (fn [call-id sip-ctrl {name :name local-dest :dest}]
                                (let [{bye :bye sip-call-id :sip-call-id headers :headers uri-to :uri-to} (@calls call-id)]
                                  (skip-until #(when (or (= "BYE" (-> % :nrq :method))
                                                         (< 200   (-> % :nrq :status))
                                                         (= :bye %))
                                                 ;(.send sip bye)
                                                 ;(->> (mk-headers "BYE" sip-call-id name headers uri-to local-dest)
                                                 ;     (merge {:content ""})
                                                 ;     conv/to-js
                                                 ;     (.send sip))
                                                 (kill-call config call-id))
                                            sip-ctrl)))
              add-sip-ctrl-to-rt-circs
                              (fn [call-id sip-ctrl]
                                (doseq [r [:rt :rtcp] i [:in :out]
                                        :let [circ-id (->> call-id (@calls) r i)]]
                                  (circ/update-data circ-id [:sip-ctrl] sip-ctrl)))
              ;; Process SIP logic:
              process     (fn process [rq]
                            (let [nrq          (-> rq cljs/js->clj walk/keywordize-keys)
                                  contact      (-> nrq :headers :contact first)
                                  name         (str/replace (or (-> contact :name)                                    ;; get name and remove surrounding "".
                                                                (->> contact :uri (re-find #"sip:(.*)@") second))
                                                            #"\"" "")]
                              ;; debug <--
                              ;; (println)
                              ;; (println :nrq nrq)
                              ;; (println :cid (-> nrq :headers :call-id (@sip-to-call-id) (@calls)))
                              ;; (println :cid @sip-to-call-id (-> nrq :headers :call-id ))
                              ;; debug -->

                              (cond

                                ;; if call is recognised:
                                (-> nrq :headers :call-id (@sip-to-call-id))
                                (go (>! (-> nrq :headers :call-id (@sip-to-call-id) (@calls) :sip-ctrl)
                                        {:nrq nrq :rq rq}))

                                (= (:method nrq) "REGISTER")
                                (let [rdv-data     (circ/get-data out-rdv-id)
                                      sip-dir-dest (first (select #(= (:role %) :sip-dir)))
                                      ack          (.makeResponse sip rq 200 "OK")]                                   ;; prepare sip successful answer
                                  (println :l (doall (map :role (select identity))))
                                  (if (:auth sip-dir-dest)
                                    (go (>! out-rdv-ctrl sip-dir-dest)                                                ;; --- RDV: connect to sip dir to send register
                                        (<! out-rdv-notify)                                                           ;; wait until connected to send
                                        (sd/register config name out-rdv-id rdv-id (-> rdv-data :rdv :auth :srv-id))  ;; send register to dir, ack to sip client:
                                        (sd/register-to-mix config name mix-id)                                       ;; register our sip user name (needed for last step of incoming rt circs, without giving our ip to caller)
                                        (.send sip ack)                                                               ;; --- SIP: answer sip client, successfully registered.
                                        (reset! my-name name)
                                        (reset! uri-to  (-> contact :uri))                                            ;; save uri & headers for building invite later:
                                        (reset! headers (-> ack cljs/js->clj walk/keywordize-keys :headers)))
                                    (do (log/error "Could not find SIP DIR in herd network")
                                        ;; debug <--
                                        (doall (->> (dir/get-net-info) seq (map second) (map #(dissoc % :auth)) (map println)))
                                        ;; debug -->
                                        (.send sip (.makeResponse sip rq "404" "NOT FOUND")))))

                                (= (:method nrq) "BYE")
                                (.send sip (.makeResponse sip rq "200" "OK"))

                                (= (:method nrq) "SUBSCRIBE")
                                (condp = (-> nrq :headers :event)
                                  "presence.winfo"  (do (println (:event nrq))
                                                        ;; and register the gringo.
                                                        (.send sip (.makeResponse sip rq 200 "OK")))
                                  "message-summary" (do (println :200 :OK) (.send sip (.makeResponse sip rq 200 "OK")))
                                  (.send sip (.makeResponse sip rq 501 "Not Implemented")))

                                (= (:method nrq) "PUBLISH")
                                (when false (go (if (= "presence" (-> nrq :headers :event))
                                                  (let [parse-xml (-> (node/require "xml2js") .-parseString)
                                                        xml       (chan)]
                                                    ;; debug <--
                                                    (parse-xml (:content nrq) #(go (println %2) (>! xml %2)))
                                                    (println (-> (<! xml) cljs/js->clj walk/keywordize-keys))
                                                    ;; debug -->
                                                    (.send sip (.makeResponse sip rq 200 "OK")))
                                                  (do (log/error "SIP: Unsupported PUBLISH event:" (-> nrq :headers :event))
                                                      (.send sip (.makeResponse sip rq 501 "Not Implemented"))))))

                                (= (:method nrq) "OPTIONS")
                                (.send sip (.makeResponse sip rq 200 "OK"))

                                ;; Take care of invite: SIP client sent an invite.
                                ;; this means we are the caller. The following will find the callee & initiate call:
                                (= (:method nrq) "INVITE")
                                (go (let [sip-call-id      (-> nrq :headers :call-id)
                                          call-id          (mk-call-id)
                                          sip-ctrl         (chan)
                                          callee-name      (second (re-find #"sip:(.*)@" (:uri nrq)))                                   ;; get callee name
                                          sdp              (:content nrq)
                                          sip-dir-dest     (first (select #(= (:role %) :sip-dir)))]
                                      (add-call call-id {:sip-ctrl sip-ctrl :sip-call-id sip-call-id :state :ringing
                                                         :headers (-> (.makeResponse sip rq 200 "OK") cljs/js->clj walk/keywordize-keys :headers)
                                                         :uri-to  (-> contact :uri)})
                                      (assert (:auth sip-dir-dest) "Could not find SIP DIR in herd network")
                                      (>! out-rdv-ctrl sip-dir-dest)                                                ;; --- RDV: connect to sip dir to send register
                                      (<! out-rdv-notify)                                                           ;; wait until connected to send
                                      (sd/query config callee-name out-rdv-id call-id)                                                  ;; query for callee's rdv
                                      (log/info "SIP:" "initiating call" call-id "to" callee-name)
                                      (let [query-reply-rdv      (<! sip-ctrl)                                                          ;; get query reply
                                            rdv-data             (circ/get-data rdv-id)]
                                        (if (= :error (-> query-reply-rdv :sip-rq (.readUInt8 0) s/to-cmd))                             ;; FIXME: assert this instead.
                                          (do (log/error "Query for" callee-name "failed.")
                                              (.send sip (.makeResponse sip rq 404 "NOT FOUND")))
                                          (let [callee-rdv       (:data query-reply-rdv)
                                                callee-rdv-cid   (.readUInt32BE callee-rdv 0)
                                                callee-rdv-id    (.slice callee-rdv 4 (+ 4 node-id-len))
                                                sdp-dest         (get-sdp-dest nrq)
                                                rtcp-dest        (get-sdp-rtcp nrq)]                                                    ;; parse sdp to find where the SIP client expects to receive incoming RTP.
                                            (println sdp-dest)
                                            (println rtcp-dest)
                                            (assert callee-rdv-id (str "SIP: Could not find callee's mix:" name))
                                            (update-data call-id [:peer-rdv] callee-rdv-cid)
                                            (.send sip (.makeResponse sip rq 100 "TRYING"))                                             ;; inform the SIP client we have initiated the call.
                                            (if (not (b/b= callee-rdv-id (-> out-rdv-id circ/get-data :rdv :auth :srv-id)))
                                              (do (>! out-rdv-ctrl (dir/find-by-id callee-rdv-id))
                                                  (<! out-rdv-notify)
                                                  (log/debug "Extended to callee's RDV"))
                                              (do (>! out-rdv-ctrl :drop-last)
                                                  (<! out-rdv-notify)
                                                  (log/debug "We already are on callee's RDV")))
                                            ;; FIXME: once this works we'll add relay-sip extend to callee so rdv can't read demand,
                                            ;; and client can match our HS against the keys he has for his contacts.
                                            (circ/relay-sip config out-rdv-id :f-enc (b/cat (-> :invite s/from-cmd b/new1)              ;; Send invite to callee. include our rdv-id so callee can send sig to us.
                                                                                            (b/new call-id)
                                                                                            b/zero
                                                                                            (b/new4 callee-rdv-cid)
                                                                                            (-> rdv-data :rdv :auth :srv-id)
                                                                                            (-> @path/chosen-mix :auth :srv-id)
                                                                                            (b/new name)
                                                                                            b/zero
                                                                                            (-> config :auth :herd-id :id)
                                                                                            (-> config :auth :herd-id :pub)))
                                            (let [reply1                 (<! sip-ctrl)
                                                  reply2                 (<! sip-ctrl)
                                                  [rtp-rep rtcp-rep]     (if (= (:cmd reply1) :ack-rtcp) [reply2 reply1] [reply1 reply2])]                                                 ;; and now we wait for ack
                                              (assert (= (:cmd rtp-rep) :ack) (str "Something went wrong with call" call-id))
                                              (.send sip (.makeResponse sip rq 180 "RINGING"))                                                            ;; we received an answer (non error) from callee, inform our SIP client that callee's phone is ringing
                                              (let [[rdv-callee-id mix-id id pub] (b/cut (:data rtp-rep) node-id-len (* 2 node-id-len) (* 3 node-id-len))
                                                    rtp-circ                      (<! (path/get-path :rt))
                                                    rtp-data                      (circ/get-data rtp-circ)
                                                    rtp-ctrl                      (:dest-ctrl rtp-data)
                                                    rtp-notify                    (:notify rtp-data)
                                                    rtp-done                      (chan)
                                                    [_ local-port]                (<! (path/attach-circs-to-new-udp config                               ;; create local udp socket. in-circ will be sent to sdp-dest, the SIP client's RTP media. out-circ is where data from the sip client will be sent through to callee.
                                                                                                                    (go (:circ-id rtp-rep))
                                                                                                                    rtp-done
                                                                                                                    (go sdp-dest)))
                                                    rtcp-circ                     (<! (path/get-path :rt))
                                                    rtcp-data                     (circ/get-data rtcp-circ)
                                                    rtcp-ctrl                     (:dest-ctrl rtcp-data)
                                                    rtcp-notify                   (:notify rtcp-data)
                                                    rtcp-done                     (chan)
                                                    [_ loc-rtcp-port]             (<! (path/attach-circs-to-new-udp config                               ;; create local udp socket. in-circ will be sent to sdp-dest, the SIP client's RTP media. out-circ is where data from the sip client will be sent through to callee.
                                                                                                                    (go (:circ-id rtcp-rep))
                                                                                                                    rtcp-done
                                                                                                                    (go rtcp-dest)))
                                                    circuit-path                  (distinct-hops [(:chosen-mix rdv-data)              ;; our mix
                                                                                                  (:rdv rdv-data)                     ;; our rdv
                                                                                                  (dir/find-by-id rdv-callee-id)      ;; callee's rdv
                                                                                                  (dir/find-by-id mix-id)             ;; callee's mix
                                                                                                  {:auth {:pub-B pub :srv-id id}}])]  ;; callee.

                                                (>! rtp-ctrl circuit-path)                                            ;; connect to callee using given path.
                                                (>! rtcp-ctrl circuit-path)                                           ;; connect to callee using given path.
                                                (<! rtp-notify)                                                                                           ;; wait until ready.
                                                (<! rtcp-notify)                                                                                          ;; wait until ready.
                                                (>! rtcp-done rtcp-circ)
                                                (>! rtp-done rtp-circ)
                                                (log/info "SIP: RT circuits ready for outgoing data on:" call-id)
                                                (update-data call-id [:rt] {:in (:circ-id rtp-rep) :out rtp-circ}) ;; FIXME if needed add chans.
                                                (update-data call-id [:rtcp] {:in (:circ-id rtcp-rep) :out rtcp-circ}) ;; FIXME if needed add chans.
                                                (circ/relay-sip config rtp-circ :f-enc (b/cat (-> :ackack s/from-cmd b/new1)                              ;; send final ack to callee, with call-id so it knows that this circuit will be used for our outgoing (its incoming) RTP.
                                                                                              (b/new call-id)
                                                                                              b/zero))
                                                (circ/relay-sip config rtcp-circ :f-enc (b/cat (-> :ackack-rtcp s/from-cmd b/new1)                        ;; send final ack to callee, with call-id so it knows that this circuit will be used for our outgoing (its incoming) RTP.
                                                                                               (b/new call-id)
                                                                                               b/zero))
                                                (log/info "SIP: sent ackack, ready for relay on" call-id)
                                                (let [ok (merge (assoc-in (assoc-in (conv/to-clj (.makeResponse sip rq 200 "OK"))                 ;; Send our client a 200 OK, with out-circ's listening udp as "callee's" dest (what caller thinks is the callee actually is herd).
                                                                                    [:headers :content-type]
                                                                                    "application/sdp") ;; inelegant, testing.
                                                                          [:headers :contact]
                                                                          [{:name nil
                                                                            :uri (str "sip:" callee-name "@" (:local-ip config) ":5060;transport=UDP;ob")
                                                                            :params {}}])
                                                                (mk-sdp (:codec config) {:host (:local-ip config) :port local-port} {:port loc-rtcp-port} :ack sdp))]
                                                  (update-data call-id [:uri-to] (-> ok :headers :contact first :uri))
                                                  (update-data call-id [:headers] (-> ok :headers))
                                                  ;(update-data call-id [:bye] (.makeResponse sip rq))
                                                  (.send sip (conv/to-js ok)))
                                                (add-sip-ctrl-to-rt-circs call-id sip-ctrl)
                                                (js/setInterval #(dtls/relay-ping config rtcp-circ) 500)
                                                (wait-for-bye call-id
                                                              sip-ctrl
                                                              {:name callee-name
                                                               :dest {:host (:local-ip config)}}))))))))

                                :else (log/error "Unsupported sip method" (:method nrq)))))]

          ;; Initialisation of create-server: prepare RDV, sip signalisation incoming channel.
(log/debug :lol1)
          (>! rdv-ctrl :rdv)
(log/debug :lol0.5)
          (>! out-rdv-ctrl :rdv)
          (circ/update-data rdv-id [:sip-chan] incoming-sip)
          (circ/update-data out-rdv-id [:sip-chan] incoming-sip)
          (.start sip (cljs/clj->js {:protocol "UDP"}) process)
(log/debug :lol2)

          ;; FIXME: sip-ch is general and dispatches according to call-id to sub channels.
          (go-loop [query (<! incoming-sip)]
            (if (= query :destroy)
              (do (log/info "SIP lost connectivity, stopping.")
                  (.stop sip)
                  (doseq [call-id @calls]
                    (kill-call config call-id)))
              (let [cmd           (-> query :sip-rq (.readUInt8 0) s/to-cmd)
                    [call-id msg] (-> query :sip-rq s/get-call-id)
                    call-chan     (-> call-id (@calls) :sip-ctrl)]
                (log/info "SIP: call-id:" call-id "-" cmd)
                (cond
                  ;; try to dispatch to an existing call. Right now, sig messages from SIP client to us, and from herd nw to us are put in the same chan. We might want one for each, and avoid doing things like skip-until.
                  call-chan
                  (go (>! call-chan (merge query {:data msg :call-id call-id :cmd cmd})))

                  ;; if it's an invite, initiate call. We are the callee.
                  (= cmd :invite)
                  (go (let [caller-rdv-id                 (.readUInt32BE msg 0)
                            [_ rdv-caller-id mix-id msg]  (b/cut msg 4 (+ 4 node-id-len) (+ 4 (* 2 node-id-len)))
                            [caller msg]                  (b/cut-at-null-byte msg)
                            [id pub]                      (b/cut msg node-id-len)
                            rdv-data                      (circ/get-data rdv-id)
                            caller                        (.toString caller)
                            sip-ctrl                      (chan)
                            mix-dest                      (dir/find-by-id mix-id)
                            circuit-path                  (distinct-hops [(:chosen-mix rdv-data)              ;; our mix
                                                                          (:rdv rdv-data)                     ;; our rdv
                                                                          (dir/find-by-id rdv-caller-id)      ;; caller's rdv
                                                                          (dir/find-by-id mix-id)             ;; caller's mix
                                                                          {:auth {:pub-B pub :srv-id id}}])   ;; caller
                            ;; rtp
                            rtp-circ                      (<! (path/get-path :rt))
                            rtp-data                      (circ/get-data rtp-circ)
                            rtp-ctrl                      (:dest-ctrl rtp-data)
                            rtp-notify                    (:notify rtp-data)
                            rtp-done                      (chan)
                            rtp-incoming                  (chan)
                            sdp-dest                      (chan)
                            [_ local-port]                (<! (path/attach-circs-to-new-udp config                 ;; our local udp socket for exchanging RTP with local sip client. rtp-incoming is caller's RTP which we'll route to the @/port which will be given in 200/OK after sending invite to it.
                                                                                            rtp-incoming
                                                                                            rtp-done               ;; The invite we'll send will have our local sockets @/port as media, so sip client sends us RTP, we'll route it through rtp-circ.
                                                                                            sdp-dest))
                            local-dest                    {:host (:local-ip config) :port local-port}
                            ;; rtcp
                            rtcp-circ                     (<! (path/get-path :rt))
                            rtcp-data                     (circ/get-data rtcp-circ)
                            rtcp-ctrl                     (:dest-ctrl rtcp-data)
                            rtcp-notify                   (:notify rtcp-data)
                            rtcp-done                     (chan)
                            rtcp-incoming                 (chan)
                            rtcp-dest                     (chan)
                            [_ loc-rtcp-port]             (<! (path/attach-circs-to-new-udp config                 ;; our local udp socket for exchanging RTP with local sip client. rtp-incoming is caller's RTP which we'll route to the @/port which will be given in 200/OK after sending invite to it.
                                                                                            rtcp-incoming
                                                                                            rtcp-done              ;; The invite we'll send will have our local sockets @/port as media, so sip client sends us RTP, we'll route it through rtp-circ.
                                                                                            rtcp-dest))
                            ok-200                        (atom {})]
                        (log/info "SIP: invited by" caller "- Call-ID:" call-id "Rdv" caller-rdv-id)
                        (add-call call-id {:sip-ctrl sip-ctrl, :sip-call-id call-id, :state :ringing, :peer-rdv caller-rdv-id
                                           :rtcp {:out rtcp-circ} :rt {:out rtp-circ}
                                           :headers @headers
                                           :uri-to  @uri-to})
                        (if answering-machine
                          (let [exec (.-exec (node/require "child_process"))]
                            ; (.writeFile fs file sdp)
                            (>! rtp-ctrl circuit-path)                                                               ;; connect to caller's mix & then to caller.
                            (>! rtcp-ctrl circuit-path)                                                              ;; connect to caller's mix & then to caller.
                            (<! rtcp-notify)                                                                         ;; wait for answer.
                            (<! rtp-notify)                                                                          ;; wait for answer.
                            (>! rtcp-done rtcp-circ)
                            (>! rtp-done rtp-circ)
                            (go (>! rtcp-dest {:host "127.0.0.1" :port 1234}))
                            (go (>! sdp-dest {:host "127.0.0.1" :port 1234}))
                            (log/info "SIP: RT circuit ready for call" call-id)
                            (circ/relay-sip config rtp-circ :f-enc (b/cat (-> :ack s/from-cmd b/new1)                ;; Send ack to caller, with our mix's coordinates so he can create an rt-path to us to send rtp.
                                                                          (b/new call-id)
                                                                          b/zero
                                                                          (-> rdv-data :rdv :auth :srv-id)
                                                                          (-> @path/chosen-mix :auth :srv-id)
                                                                          (-> config :auth :herd-id :id)
                                                                          (-> config :auth :herd-id :pub)))
                            (circ/relay-sip config rtcp-circ :f-enc (b/cat (-> :ack-rtcp s/from-cmd b/new1)          ;; Send ack to caller, with our mix's coordinates so he can create an rt-path to us to send rtp.
                                                                           (b/new call-id)
                                                                           b/zero))
                            (let [reply1             (<! (skip-until #(:circ-id %) sip-ctrl))
                                  reply2             (<! (skip-until #(:circ-id %) sip-ctrl))
                                  [rtp-id rtcp-id]   (map :circ-id (if (= (:cmd reply1) :ackack-rtcp) [reply2 reply1] [reply1 reply2]))]                                     ;; Wait for caller's rt path's first message.
                              (>! rtp-incoming  rtp-id)                                                              ;; inform attach-local-udp-to-simplex-circs that we have incoming-rtp to attach to socket.
                              (>! rtcp-incoming rtcp-id)                                                             ;; inform attach-local-udp-to-simplex-circs that we have incoming-rtp to attach to socket.
                              (update-data call-id [:rt :in] rtp-id)
                              (update-data call-id [:rtcp :in] rtcp-id))
                            (log/info "SIP: got ackack, ready for relay on" call-id)
                            (add-sip-ctrl-to-rt-circs call-id sip-ctrl)
                            (js/setInterval #(dtls/relay-ping config rtcp-circ) 100)
                            (log/info "SIP: launching vlc for answering-machine playback")
                            (update-data call-id [:vlc-child]
                                         (exec (str "cvlc '" (:answering-machine-file config) "' --play-and-exit --sout '#transcode{acodec=ulaw,channels=1,samplerate=8000}:rtp{dst=127.0.0.1,port-audio=" (:port local-dest) "}'") nil #(do (log/debug "VLC exited with:" %1)
                                                                                                                                                                                                                                             (log/debug "VLC stdout:" %2)
                                                                                                                                                                                                                                             (log/debug "VLC stdout:" %3)
                                                                                                                                                                                                                                             (kill-call config call-id))))
                            (wait-for-bye call-id
                                          sip-ctrl
                                          nil))
                          (do (.send sip (conv/to-js (merge (mk-headers "INVITE" call-id caller @headers @uri-to local-dest)       ;; Send our crafted invite with local udp port as "caller's" media session
                                                         (mk-sdp (:codec config) local-dest {:port loc-rtcp-port} :invite))))
                              (let [user-answer (<! (skip-until #(let [status (-> % :nrq :status)
                                                                       {user-answer :nrq} %]
                                                                   (cond (> 200 status) false
                                                                         (< 200 status) true
                                                                         :else          (do (go (>! sdp-dest  (get-sdp-dest user-answer))) ;; FIXME one go should do, test
                                                                                            (go (>! rtcp-dest (get-sdp-rtcp user-answer)))
                                                                                            (reset! ok-200 user-answer))))
                                                                sip-ctrl))]
                                (if (not= 200 (-> user-answer :nrq :status))
                                  (kill-call config call-id)
                                  (do (>! rtp-ctrl circuit-path)                                                               ;; connect to caller's mix & then to caller.
                                      (>! rtcp-ctrl circuit-path)                                                              ;; connect to caller's mix & then to caller.
                                      (<! rtcp-notify)                                                                         ;; wait for answer.
                                      (<! rtp-notify)                                                                          ;; wait for answer.
                                      (log/info "SIP: RT circuit ready for call" call-id)
                                      (circ/relay-sip config rtp-circ :f-enc (b/cat (-> :ack s/from-cmd b/new1)                ;; Send ack to caller, with our mix's coordinates so he can create an rt-path to us to send rtp.
                                                                                    (b/new call-id)
                                                                                    b/zero
                                                                                    (-> rdv-data :rdv :auth :srv-id)
                                                                                    (-> @path/chosen-mix :auth :srv-id)
                                                                                    (-> config :auth :herd-id :id)
                                                                                    (-> config :auth :herd-id :pub)))
                                      (circ/relay-sip config rtcp-circ :f-enc (b/cat (-> :ack-rtcp s/from-cmd b/new1)          ;; Send ack to caller, with our mix's coordinates so he can create an rt-path to us to send rtp.
                                                                                     (b/new call-id)
                                                                                     b/zero))
                                      (let [reply1             (<! (skip-until #(:circ-id %) sip-ctrl))
                                            reply2             (<! (skip-until #(:circ-id %) sip-ctrl))
                                            [rtp-id rtcp-id]   (map :circ-id (if (= (:cmd reply1) :ackack-rtcp) [reply2 reply1] [reply1 reply2]))]                                     ;; Wait for caller's rt path's first message.
                                        (>! rtp-incoming  rtp-id)                                                              ;; inform attach-local-udp-to-simplex-circs that we have incoming-rtp to attach to socket.
                                        (>! rtcp-incoming rtcp-id)                                                             ;; inform attach-local-udp-to-simplex-circs that we have incoming-rtp to attach to socket.
                                        (update-data call-id [:rt :in] rtp-id)
                                        (update-data call-id [:rtcp :in] rtcp-id))
                                      (let [ok (mk-ack @ok-200 call-id)]
                                        (update-data call-id [:uri-to] (-> ok :uri))
                                        (update-data call-id [:headers] (-> ok :headers))
                                        (.send sip (conv/to-js ok)))
                                      (log/info "SIP: got ackack, ready for relay on" call-id)
                                      (add-sip-ctrl-to-rt-circs call-id sip-ctrl)
                                      (js/setInterval #(dtls/relay-ping config rtcp-circ) 100)
                                      (wait-for-bye call-id
                                                    sip-ctrl
                                                    {:name caller
                                                     :dest {:host (:local-ip config)}})))))))) ;; loop waiting for bye.

                  :else
                  (log/info "SIP: incoming message with unknown call id:" call-id "-- dropping."))
                (recur (<! incoming-sip)))))

            (log/info "SIP proxy listening on default UDP SIP port")

            (when answering-machine
              (let [name            (:answering-machine-name config)
                    sip-dir-dest    (first (select #(= (:role %) :sip-dir)))
                    rdv-data        (circ/get-data rdv-id)
                    register        #(go (>! out-rdv-ctrl sip-dir-dest)                                                ;; --- RDV: connect to sip dir to send register
                                         (<! out-rdv-notify)                                                           ;; wait until connected to send
                                         (sd/register config name out-rdv-id rdv-id (-> rdv-data :rdv :auth :srv-id))  ;; send register to dir, ack to sip client:
                                         (sd/register-to-mix config name mix-id)                                       ;; register our sip user name (needed for last step of incoming rt circs, without giving our ip to caller)
                                         (reset! my-name name))]
                (register)
                (js/setInterval register (/ (:sip-register-interval config) 2)))))

          (when (:debug config)
            (js/setInterval (fn []
                              (let [rtp-conns (filter #(-> % second :rtp-stats) (c/get-all))]
                                (doseq [[socket {[total rtp-seq] :rtp-stats circ-id :circuit}] rtp-conns]
                                  (c/update-data socket [:rtp-stats] [0 rtp-seq])
                                  (log/debug "RTP Status:" total "drops on circuit" circ-id "in the last 5 seconds"))))
                            5000)))
    incoming-sip))


;; replace all uris, tags, ports by hc defaults.
;; {method REGISTER
;;  uri sip:localhost                                                                                  ; URI
;;  version 2.0
;;  headers {contact [{name "herd"
;;                     uri sip:herd@127.0.0.1:18750;transport=udp;registering_acc=localhost            ; URI
;;                     params {expires 600}}]
;;           user-agent Jitsi2.5.5104Linux                                                             ; becomes herd-version.
;;           call-id 659987c14fca0876dc89d5fa4ec715e5@0:0:0:0:0:0:0:0                                  ; this changes.
;;           from {name "herd"
;;                 uri sip:herd@localhost                                                              ; URI
;;                 params {tag 81429e45}}                                                              ; tag.
;;           via [{version 2.0
;;                 protocol UDP
;;                 host 127.0.0.1                                                                      ; remove this. remove via entirely?
;;                 port 18750
;;                 params {branch z9hG4bK-313432-de5cc56153489d6de96fa6deeabaab8f
;;                         received 127.0.0.1}}]                                                       ; and this
;;           expires 600
;;           max-forwards 70
;;           content-length 0
;;           to {name "herd"
;;               uri sip:herd@localhost
;;               params {}}
;;           cseq {seq 1
;;                 method REGISTER}}
;;  content }

;; media session.
;;                         B2BUA
;;    Ann                  Server                 Bob
;;     |                    | |                    |
;;     |      INVITE     F1 | |                    |
;;     |------------------->| |                    |
;;     |    100 Trying   F2 | |                    |
;;     |<-------------------| |       INVITE    F3 |
;;     |                    | |------------------->|
;;     |                    | |    100 Trying   F4 |
;;     |                    | |<-------------------|
;;     |                    | |    180 Ringing  F5 |
;;     |   180 Ringing   F6 | |<-------------------|
;;     |<-------------------| |                    |
;;     |                    | |       200 OK    F7 |
;;     |      200 OK     F8 | |<-------------------|
;;     |<-------------------| |         ACK     F9 |
;;     |         ACK    F10 | |------------------->|
;;     |------------------->| |                    |
;;     |      RTP Media     | |      RTP Media     |
;;     |<==================>| |<==================>|
;;     |        BYE     F11 | |                    |
;;     |------------------->| |        BYE     F12 |
;;     |      200 OK    F13 | |------------------->|
;;     |<-------------------| |       200 OK   F14 |
;;     |                    | |<-------------------|
;;     |                    | |                    |


;; presence stuff

;; (comment
;; {:method PUBLISH
;;  :uri sip:me@localhost
;;  :version 2.0
;;  :headers {:via [{:version 2.0 :protocol UDP :host 127.0.0.1 :port 9669
;;                   :params {:branch z9hG4bK-373037-96f223ef93a23586ffc02df09af2cc53
;;                            :received 127.0.0.1}}]
;;            :content-type application/pidf+xml
;;            :expires 3600
;;            :max-forwards 70
;;            :event presence
;;            :content-length 401
;;            :to {:name "me"
;;                 :uri sip:me@localhost
;;                 :params {}}
;;            :cseq {:seq 2
;;                   :method PUBLISH}
;;            :contact [{:name "me"
;;                       :uri sip:me@127.0.0.1:9669;transport=udp;registering_acc=localhost
;;                       :params {}}]
;;            :user-agent Jitsi2.5.5104Linux
;;            :call-id a091313efa9d8c5f2c7471c2952d21de@0:0:0:0:0:0:0:0
;;            :from {:name "me"
;;                   :uri sip:me@localhost
;;                   :params {:tag c4c41a24}}}
;;  :content <?xml version="1.0" encoding="UTF-8" standalone="no"?><presence xmlns="urn:ietf:params:xml:ns:pidf" xmlns:dm="urn:ietf:params:xml:ns:pidf:data-model" xmlns:rpid="urn:ietf:params:xml:ns:pidf:rpid" entity="sip:me@localhost"><dm:personid="p2856"><rpid:activities/></dm:person><tuple id="t5430"><status><basic>open</basic></status><contact>sip:me@localhost</contact><note>Online</note></tuple></presence>})
;;
;;
;; (comment
;;   {:method SUBSCRIBE
;;    :uri sip:me@localhost
;;    :version 2.0
;;    :headers {:via [{:version 2.0
;;                     :protocol UDP
;;                     :host 127.0.0.1
;;                     :port 55590
;;                     :params {:branch z9hG4bK-373037-cae0467c2ff1881dad572e4d6c2c8c93
;;                              :received 127.0.0.1}}]
;;              :expires 3600
;;              :max-forwards 70
;;              :event message-summary
;;              :content-length 0
;;              :to {:name "me"
;;                   :uri sip:me@localhost
;;                   :params {}}
;;              :cseq {:seq 1
;;                     :method SUBSCRIBE}
;;              :contact [{:name "me"
;;                         :uri sip:me@127.0.0.1:55590;transport=udp;registering_acc=localhost
;;                         :params {}}]
;;              :user-agent Jitsi2.5.5104Linux
;;              :accept application/simple-message-summary
;;              :call-id 9fe891081a73da36fd0d1984409fedb5@0:0:0:0:0:0:0:0
;;              :from {:name "me"
;;                     :uri sip:me@localhost
;;                     :params {:tag ba13e9ef}}}
;;

;; {:method INVITE
;;  :uri sip:lol@172.17.0.7
;;  :version 2.0
;;  :headers {:supported " replaces, 100rel, timer, norefersub,"
;;            :via [{:version 2.0
;;                   :protocol UDP
;;                   :host 172.17.42.1
;;                   :port 5555
;;                   :params {:rport 5555
;;                            :branch z9hG4bKPjb3bfc8f5-ced1-42ce-ade2-495d7bad0c60
;;                            :received 172.17.42.1}}]
;;            :content-type "application/sdp"
;;            :max-forwards 70
;;            :content-length 230
;;            :to {:name nil
;;                 :uri "sip:lol@172.17.0.7"
;;                 :params {}}
;;            :cseq {:seq 9058
;;                   :method INVITE}
;;            :session-expires 1800
;;            :contact [{:name nil
;;                       :uri "sip:aoeu1@172.17.42.1:5555;transport=UDP;ob"
;;                       :params {}}]
;;            :user-agent "PJSUA v1.14.0 Linux-3.13.5/x86_64/glibc-2.17 "
;;            :allow " PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS,"
;;            :call-id "4e6eb96d-c8e5-482b-ac12-f0cb9076655b"
;;            :from {:name nil
;;                   :uri "sip:aoeu1@172.17.0.7"
;;                   :params {:tag 676d64bf-a738-48fe-9b6b-6c108f484edd}}
;;            :min-se 90}
;;  :content "v=0
;;           o=- 3606712585 3606712585 IN IP4 139.19.186.120
;;           s=pjmedia
;;           c=IN IP4 139.19.186.120
;;           t=0 0
;;           a=X-nat:0
;;           m=audio 4000 RTP/AVP 96
;;           a=rtcp:4001 IN IP4 139.19.186.120
;;           a=sendrecv
;;           a=rtpmap:96 telephone-event/8000
;;           a=fmtp:96 0-15" }

