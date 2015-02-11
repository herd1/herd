(ns herd-node.buf
  (:require [cljs.core :as cljs]
            [cljs.nodejs :as node]))


;; node js/buffer helpers ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn new [data]
  "Create new buffer from data.
  Will take the content of data if it's a string/buffer/array.
  If data is an int, will create a buffer of that size."
  (js/Buffer. data))

(defn new4 [integer]
  (let [b (js/Buffer. 4)]
    (.writeUInt32BE b integer 0)
    b))

(defn new2 [integer]
  (let [b (js/Buffer. 2)]
    (.writeUInt16BE b integer 0)
    b))

(defn new1 [integer]
  (let [b (js/Buffer. 1)]
    (.writeUInt8 b integer 0)
    b))

(defn cat [& bs]
  "concatenate buffers"
  (js/Buffer.concat (cljs/clj->js bs)))

(defn copycat [& bs]
  "For performance: for a small number of buffers, this can be quicker than cat.
  Same functionality."
  (let [len  (reduce #(+ %1 (.-length %2)) 0 bs)
        data (js/Buffer. len)]
    (loop [[b & bs] bs i 0]
      (if b
        (do (.copy b data i)
            (recur bs (+ i (.-length b))))
        data))))

(defn copycat2 [a b]
  "For performance: fastest way to cat 2 buffers."
  (let [len  (+ (.-length a) (.-length b))
        data (js/Buffer. len)]
    (.copy a data)
    (.copy b data (.-length a))
    data))

(defn b= [a b]
  "Test buffer content equality."
  (= (.toString b) (.toString a)))

(defn cut [b & xs]
  "Divide the buffer: (cut b 55 88 99) will return a seq of slices from 0 to 55, 55 to 88, 88 to end of buf"
  (map #(.slice b %1 %2) (cons 0 xs) (concat xs [(.-length b)])))

(defn cut-at-null-byte [msg]
  "return data until null byte and remainder of the buffer"
  (let [z (->> (range (.-length msg))
               (map #(when (= 0 (.readUInt8 msg %)) %))
               (some identity))]
    [(.slice msg 0 z) (.slice msg (inc z))]))


;; low level io ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn mk-readers [b]
  "make big endian readers"
  [#(.readUInt8 b %) #(.readUInt16BE b %) #(.readUInt32BE b %)])

(defn mk-writers [b]
  "make big endian writers"
  [#(.writeUInt8 b %1 %2) #(.writeUInt16BE b %1 %2) #(.writeUInt32BE b %1 %2)])



;; constants ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(def zero (-> [0] cljs/clj->js js/Buffer.))


;; debug ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn hx [b]
  "debug helper"
  (.toString b "hex"))

(defn print-x [b & [s]]
  (println "---  " s (hx b)))
